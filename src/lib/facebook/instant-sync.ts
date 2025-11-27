import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { startBackgroundAnalysis } from './background-analysis';
import { startPipelineAnalysis } from './pipeline-analyzer';

interface InstantSyncResult {
  success: boolean;
  jobId: string;
  message: string;
  contactsStored: number;
  aiAnalysisQueued: boolean;
}

/**
 * Concurrency limiter utility for parallel operations
 */
class ConcurrencyLimiter {
  private queue: Array<{ 
    fn: () => Promise<unknown>; 
    resolve: (value: unknown) => void; 
    reject: (error: unknown) => void 
  }> = [];
  private running = 0;

  constructor(private limit: number) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ 
        fn: fn as () => Promise<unknown>, 
        resolve: resolve as (value: unknown) => void, 
        reject: reject as (error: unknown) => void 
      });
      this.process();
    });
  }

  private async process() {
    while (this.running < this.limit && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;

      this.running++;
      
      task.fn()
        .then((result) => {
          task.resolve(result);
        })
        .catch((error) => {
          task.reject(error);
        })
        .finally(() => {
          this.running--;
          this.process();
        });
    }
  }
}

/**
 * Starts an instant sync that stores contacts immediately (< 1 minute)
 * and queues AI analysis as a background job
 */
/**
 * Check if a sync job has been cancelled
 */
async function isJobCancelled(jobId: string): Promise<boolean> {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
    select: { status: true },
  });
  return job?.status === 'CANCELLED';
}

/**
 * Executes the actual instant sync operation
 */
async function executeInstantSync(jobId: string, facebookPageId: string, userId: string): Promise<void> {
  const startTime = Date.now();
  
  try {
    // OPTIMIZATION: Non-blocking initial status update - start syncing immediately
    // Update job status to in progress (fire and forget - don't wait)
    prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'IN_PROGRESS',
        startedAt: new Date(),
        syncedContacts: 0,
        totalContacts: 0, // Will be updated as we discover contacts
      },
    }).catch(() => {}); // Silently fail - don't block on initial update

    console.log(`[Instant Sync ${jobId}] 🚀 Starting instant sync execution...`);

    // Get page info (including auto-pipeline configuration)
    const page = await prisma.facebookPage.findUnique({
      where: { id: facebookPageId },
      select: {
        id: true,
        pageId: true,
        pageAccessToken: true,
        instagramAccountId: true,
        organizationId: true,
        autoPipelineId: true,
      },
    });

    if (!page) {
      throw new Error('Facebook page not found');
    }

    const client = new FacebookClient(page.pageAccessToken);
    let contactsStored = 0;
    const contactIds: string[] = [];
    const errors: Array<{ platform: string; id: string; error: string }> = [];

    // OPTIMIZATION: Process contacts in batches during streaming for immediate storage
    // Returns the number of contacts stored (created + updated)
    const processContactBatch = async (
      participants: Array<[string, { updatedTime: string; name?: string }]>,
      platform: 'Messenger' | 'Instagram'
    ): Promise<number> => {
      if (participants.length === 0) return 0;

      const participantIds = participants.map(([id]) => id);
      
      // OPTIMIZATION: Batch fetch existing contacts with optimized query
      // Only select needed fields and use indexed fields for faster lookup
      const existingContacts = await prisma.contact.findMany({
        where: {
          facebookPageId: page.id, // Filter by page first (indexed) for better performance
          OR: platform === 'Messenger' 
            ? [{ messengerPSID: { in: participantIds } }]
            : [
                { instagramSID: { in: participantIds } },
                { messengerPSID: { in: participantIds } },
              ],
        },
        select: { id: true, messengerPSID: true, instagramSID: true }, // Only select needed fields
      });

      const existingMap = new Map<string, string>();
      for (const contact of existingContacts) {
        const id = platform === 'Messenger' ? contact.messengerPSID : (contact.instagramSID || contact.messengerPSID);
        if (id) existingMap.set(id, contact.id);
      }

      // Separate new contacts from updates
      const toCreate: Array<{
        messengerPSID?: string;
        instagramSID?: string;
        firstName: string;
        lastName: string | null;
        hasMessenger: boolean;
        hasInstagram: boolean;
        organizationId: string;
        facebookPageId: string;
        lastInteraction: Date;
      }> = [];
      
      const toUpdate: Array<{
        id: string;
        firstName: string;
        lastName: string | null;
        lastInteraction: Date;
        hasMessenger?: boolean;
        hasInstagram?: boolean;
        instagramSID?: string;
      }> = [];

      for (const [participantId, info] of participants) {
        // Extract name
        let firstName = platform === 'Messenger' 
          ? `User ${participantId.slice(-6)}`
          : `IG User ${participantId.slice(-6)}`;
        let lastName: string | null = null;

        if (info.name) {
          const nameParts = info.name.trim().split(' ');
          firstName = nameParts[0] || firstName;
          if (nameParts.length > 1) {
            lastName = nameParts.slice(1).join(' ');
          }
        }

        const existingId = existingMap.get(participantId);
        const lastInteraction = new Date(info.updatedTime);

        if (existingId) {
          toUpdate.push({
            id: existingId,
            firstName,
            lastName,
            lastInteraction,
            ...(platform === 'Messenger' ? { hasMessenger: true } : { hasInstagram: true, instagramSID: participantId }),
          });
        } else {
          toCreate.push({
            ...(platform === 'Messenger' 
              ? { messengerPSID: participantId, hasMessenger: true, hasInstagram: false }
              : { instagramSID: participantId, hasInstagram: true, hasMessenger: false }),
            firstName,
            lastName,
            organizationId: page.organizationId,
            facebookPageId: page.id,
            lastInteraction,
          });
        }
      }

      // OPTIMIZATION: Use bulk operations with timeout and parallel processing
      try {
        const BATCH_OPERATION_TIMEOUT = 60000; // 60 seconds max for batch operations
        
        // OPTIMIZATION: Process creates and updates in parallel for maximum speed
        // Both operations are independent and can run simultaneously
        const [createdResults, updateResults] = await Promise.all([
          // OPTIMIZATION: Use parallel creates with higher concurrency for better performance
          // Split into chunks and process with controlled concurrency
          toCreate.length > 0 ? (async () => {
            const CREATE_CHUNK_SIZE = 500; // Increased chunk size for maximum throughput
            const createChunks: typeof toCreate[] = [];
            for (let i = 0; i < toCreate.length; i += CREATE_CHUNK_SIZE) {
              createChunks.push(toCreate.slice(i, i + CREATE_CHUNK_SIZE));
            }
            
            const createPromise = prisma.$transaction(
              async (tx) => {
                // OPTIMIZATION: Maximized concurrency to 18 (connection pool has 20, leaving 2 for safety)
                // Process chunks in parallel with maximum concurrency
                const limiter = new ConcurrencyLimiter(18); // 18 concurrent create chunks
                const allCreated = await Promise.all(
                  createChunks.map(chunk =>
                    limiter.execute(async () => {
                      return Promise.all(
                        chunk.map(data => tx.contact.create({ data }))
                      );
                    })
                  )
                );
                return allCreated.flat();
              },
              { timeout: BATCH_OPERATION_TIMEOUT }
            );
            
            const timeoutPromise = new Promise<never>((_, reject) => {
              setTimeout(() => reject(new Error('Batch create operation timed out')), BATCH_OPERATION_TIMEOUT);
            });
            
            const created = await Promise.race([createPromise, timeoutPromise]);
            return created.map(c => c.id);
          })() : Promise.resolve([]),

          // OPTIMIZATION: Use transaction with parallel updates and higher concurrency
          // Batch updates in chunks to avoid overwhelming the database
          toUpdate.length > 0 ? (async () => {
            const UPDATE_CHUNK_SIZE = 500; // Increased chunk size for maximum throughput
            const updateChunks: typeof toUpdate[] = [];
            for (let i = 0; i < toUpdate.length; i += UPDATE_CHUNK_SIZE) {
              updateChunks.push(toUpdate.slice(i, i + UPDATE_CHUNK_SIZE));
            }
            
            const updatePromise = prisma.$transaction(
              async (tx) => {
                // OPTIMIZATION: Maximized concurrency to 18 (connection pool has 20, leaving 2 for safety)
                // Process chunks in parallel with maximum concurrency
                const limiter = new ConcurrencyLimiter(18); // 18 concurrent update chunks
                await Promise.all(
                  updateChunks.map(chunk =>
                    limiter.execute(async () => {
                      return Promise.all(
                        chunk.map(update =>
                          tx.contact.update({
                            where: { id: update.id },
                            data: {
                              firstName: update.firstName,
                              lastName: update.lastName,
                              lastInteraction: update.lastInteraction,
                              ...(update.hasMessenger !== undefined && { hasMessenger: update.hasMessenger }),
                              ...(update.hasInstagram !== undefined && { hasInstagram: update.hasInstagram }),
                              ...(update.instagramSID && { instagramSID: update.instagramSID }),
                            },
                          })
                        )
                      );
                    })
                  )
                );
              },
              { timeout: BATCH_OPERATION_TIMEOUT }
            );
            
            const timeoutPromise = new Promise<never>((_, reject) => {
              setTimeout(() => reject(new Error('Batch update operation timed out')), BATCH_OPERATION_TIMEOUT);
            });
            
            await Promise.race([updatePromise, timeoutPromise]);
            return toUpdate.map(u => u.id);
          })() : Promise.resolve([]),
        ]);

        // Combine results
        contactIds.push(...createdResults, ...updateResults);
        const batchCount = createdResults.length + updateResults.length;
        contactsStored += batchCount; // Update shared counter for progress tracking
        return batchCount; // Return count for this batch
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Bulk operation failed, falling back to individual operations:`, error);
        // Fallback to individual operations
        const contactLimiter = new ConcurrencyLimiter(50);
        await Promise.all(
          participants.map(([participantId, info]) =>
            contactLimiter.execute(async () => {
              try {
                let firstName = platform === 'Messenger' 
                  ? `User ${participantId.slice(-6)}`
                  : `IG User ${participantId.slice(-6)}`;
                let lastName: string | null = null;

                if (info.name) {
                  const nameParts = info.name.trim().split(' ');
                  firstName = nameParts[0] || firstName;
                  if (nameParts.length > 1) {
                    lastName = nameParts.slice(1).join(' ');
                  }
                }

                const existingId = existingMap.get(participantId);
                let savedContact;

                if (existingId) {
                  savedContact = await prisma.contact.update({
                    where: { id: existingId },
                    data: {
                      firstName,
                      lastName,
                      lastInteraction: new Date(info.updatedTime),
                      ...(platform === 'Messenger' ? { hasMessenger: true } : { hasInstagram: true, instagramSID: participantId }),
                    },
                  });
                } else {
                  savedContact = await prisma.contact.create({
                    data: {
                      ...(platform === 'Messenger' 
                        ? { messengerPSID: participantId, hasMessenger: true }
                        : { instagramSID: participantId, hasInstagram: true }),
                      firstName,
                      lastName,
                      organizationId: page.organizationId,
                      facebookPageId: page.id,
                      lastInteraction: new Date(info.updatedTime),
                    },
                  });
                }

                contactIds.push(savedContact.id);
                contactsStored++; // Update shared counter for progress tracking
              } catch (error) {
                console.error(`[Instant Sync ${jobId}] Failed to store ${platform} contact ${participantId}:`, error);
                errors.push({
                  platform,
                  id: participantId,
                  error: error instanceof Error ? error.message : 'Unknown error',
                });
              }
            })
          )
        );
        
        // Return the count of successfully stored contacts from fallback
        return contactsStored; // This is approximate since it's a shared counter
      }
      
      // If no contacts to create or update, return 0
      return 0;
    };

    // Phase 1: Fast contact storage (NO AI ANALYSIS)
    // OPTIMIZATION: Stream conversations and process contacts in batches as they arrive
    let heartbeatInterval: NodeJS.Timeout | null = null;
    let streamTimeout: NodeJS.Timeout | null = null;
    
    // OPTIMIZATION: Parallel batch processing - queue batches and process multiple simultaneously
    // Connection pool analysis:
    // - Total connections: 25
    // - Each batch uses: ~2 connections (1 for transaction, 1 for findMany query)
    // - Leave 5 connections for other operations (progress updates, queries, etc.)
    // - Available for batches: 20 connections
    // - Safe limit: 10 batches in parallel (uses ~20 connections, leaves 5 for safety)
    const batchProcessor = new ConcurrencyLimiter(10); // Process 10 batches in parallel (max safe limit)
    const batchPromises: Promise<number>[] = []; // Track all batch promises to wait for completion (returns count)
    
    try {
      console.log(`[Instant Sync ${jobId}] Streaming Messenger conversations...`);
      
      // Collect unique participants as we stream conversations
      const participantMap = new Map<string, { updatedTime: string; name?: string }>();
      let conversationCount = 0;
      // OPTIMIZATION: Reduced batch size to 100 for faster contact appearance
      // Smaller batches = contacts appear more frequently, better user experience
      const PROCESS_BATCH_SIZE = 100; // Process every 100 conversations
      const MAX_STREAM_TIME = 30 * 60 * 1000; // 30 minutes max for streaming (increased from 10 to handle large pages)
      // OPTIMIZATION: Reduced progress update frequency to reduce overhead
      const PROGRESS_UPDATE_INTERVAL = 20; // Update progress every 20 conversations (reduced frequency)
      const streamStartTime = Date.now();
      let lastProgressUpdate = Date.now();
      let lastConversationTime = Date.now(); // Track when we last received a conversation
      
      // OPTIMIZATION: Skip initial progress update - start streaming immediately
      // No need to wait for database update before starting sync
      console.log(`[Instant Sync ${jobId}] Starting to stream conversations immediately...`);
      
      // OPTIMIZATION: Reduced heartbeat frequency to reduce database overhead
      // Heartbeat mechanism: Update progress every 60 seconds even if no conversations processed
      heartbeatInterval = setInterval(async () => {
        const elapsed = Date.now() - streamStartTime;
        const elapsedSeconds = Math.floor(elapsed / 1000);
        console.log(`[Instant Sync ${jobId}] 💓 Heartbeat: ${elapsedSeconds}s elapsed, ${conversationCount} conversations, ${participantMap.size} participants discovered`);
        
        // OPTIMIZATION: Truly non-blocking heartbeat (fire and forget)
        // Update progress to show we're still alive (non-blocking)
        prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: contactsStored,
            totalContacts: contactsStored + participantMap.size,
          },
        }).catch(() => {}); // Silently fail - heartbeat updates are not critical
      }, 60000); // Every 60 seconds (reduced frequency)
      
      // Wrap the stream in a timeout to detect if it never starts
      streamTimeout = setTimeout(() => {
        console.error(`[Instant Sync ${jobId}] ❌ Stream timeout: No conversations received after 60 seconds. The Facebook API may be hanging.`);
        if (heartbeatInterval) clearInterval(heartbeatInterval);
      }, 60000); // 60 second timeout for first conversation
      
      let firstConversationReceived = false;
      
      // OPTIMIZATION: Process conversations as they're fetched (streaming)
      // Process contacts in batches during streaming for immediate storage
      for await (const convo of client.fetchMessengerConversationsStream(page.pageId)) {
        // Clear the initial timeout once we receive the first conversation
        if (!firstConversationReceived) {
          firstConversationReceived = true;
          clearTimeout(streamTimeout);
          console.log(`[Instant Sync ${jobId}] ✅ Stream started, received first conversation`);
        }
        // Check for cancellation
        if (await isJobCancelled(jobId)) {
          console.log(`[Instant Sync ${jobId}] Sync cancelled by user`);
          return;
        }
        
        // Update last conversation time
        lastConversationTime = Date.now();
        conversationCount++;
        
        // Check for overall timeout (only if we've been running for a very long time)
        if (Date.now() - streamStartTime > MAX_STREAM_TIME) {
          console.warn(`[Instant Sync ${jobId}] ⚠️ Stream timeout reached (${MAX_STREAM_TIME / 60000} minutes), processing collected participants...`);
          break;
        }
        
        // OPTIMIZATION: Skip blocking progress update on first conversation
        // Just log - don't wait for database update
        if (conversationCount === 1) {
          console.log(`[Instant Sync ${jobId}] ✅ Started streaming conversations...`);
        }
        
        if (!convo.participants?.data) {
          console.log(`[Instant Sync ${jobId}] Conversation ${convo.id} has no participants data`);
          continue;
        }
        
        // Extract participants from this conversation immediately
        let participantsInConvo = 0;
        for (const participant of convo.participants.data) {
          if (participant.id === page.pageId) {
            // Skip page itself (this is normal)
            continue;
          }
          participantsInConvo++;
          const existing = participantMap.get(participant.id);
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            participantMap.set(participant.id, {
              updatedTime: convo.updated_time,
              name: participant.name,
            });
          }
        }
        
        // Log if conversation has no external participants (for debugging)
        if (participantsInConvo === 0 && convo.participants.data.length > 0) {
          console.log(`[Instant Sync ${jobId}] Conversation ${convo.id} only has page itself as participant (${convo.participants.data.length} total)`);
        }
        
        // OPTIMIZATION: Process contacts in batches during streaming (every 100 conversations)
        // OPTIMIZATION: Queue batches for parallel processing instead of waiting
        if (conversationCount % PROCESS_BATCH_SIZE === 0 && participantMap.size > 0) {
          // Check for cancellation before processing batch
          if (await isJobCancelled(jobId)) {
            console.log(`[Instant Sync ${jobId}] Sync cancelled by user, processing collected participants before exit...`);
            const batchToProcess = Array.from(participantMap.entries());
            await processContactBatch(batchToProcess, 'Messenger');
            return;
          }
          
          const batchToProcess = Array.from(participantMap.entries());
          const remainingCount = participantMap.size; // Store before clearing
          participantMap.clear(); // Clear processed participants
          
          // OPTIMIZATION: Queue batch for parallel processing (track promise and count)
          const batchPromise = batchProcessor.execute(async () => {
            const batchCount = await processContactBatch(batchToProcess, 'Messenger');
            console.log(`[Instant Sync ${jobId}] Batch processed: ${batchCount} contacts stored (${batchToProcess.length} participants)`);
            
            // OPTIMIZATION: Truly non-blocking progress update (fire and forget)
            // Update progress (non-blocking) - use remainingCount before clearing
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: contactsStored,
                totalContacts: contactsStored + remainingCount, // Use count before clearing
              },
            }).catch(() => {}); // Silently fail - progress updates are not critical
            
            return batchCount; // Return count for verification
          }).catch(err => {
            console.error(`[Instant Sync ${jobId}] Batch processing error:`, err);
            return 0; // Return 0 on error
          });
          batchPromises.push(batchPromise);
          
          lastProgressUpdate = Date.now();
        } else if (conversationCount % PROGRESS_UPDATE_INTERVAL === 0 || Date.now() - lastProgressUpdate > 5000) {
          // OPTIMIZATION: Truly non-blocking progress update (fire and forget)
          // Periodic progress update to show activity even when not processing batches
          // This ensures progress is visible even during the initial streaming phase
          const estimatedTotal = contactsStored + participantMap.size;
          prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: estimatedTotal > 0 ? estimatedTotal : participantMap.size, // Show discovered contacts even if not stored yet
            },
          }).catch(() => {}); // Silently fail - progress updates are not critical
          
          console.log(`[Instant Sync ${jobId}] Progress: ${contactsStored} stored, ${participantMap.size} discovered, ${conversationCount} conversations processed`);
          lastProgressUpdate = Date.now();
        }
      }
      
      // Clean up heartbeat and timeout
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (streamTimeout) clearTimeout(streamTimeout);
      
      console.log(`[Instant Sync ${jobId}] Fetched ${conversationCount} Messenger conversations`);

      // CRITICAL FIX: Wait for all queued batches to complete before processing remaining
      // This ensures all parallel batches finish and contactsStored is accurate
      if (batchPromises.length > 0) {
        console.log(`[Instant Sync ${jobId}] Waiting for ${batchPromises.length} parallel batches to complete...`);
        const batchResults = await Promise.all(batchPromises);
        const totalFromBatches = batchResults.reduce((sum, count) => sum + count, 0);
        console.log(`[Instant Sync ${jobId}] All parallel batches completed. Batch results: ${totalFromBatches} contacts, Shared counter: ${contactsStored}`);
        
        // Verify counter matches batch results (for debugging)
        if (totalFromBatches !== contactsStored) {
          console.warn(`[Instant Sync ${jobId}] ⚠️ Counter mismatch! Batch results: ${totalFromBatches}, Shared counter: ${contactsStored}`);
          // Use the batch results as source of truth
          contactsStored = totalFromBatches;
        }
      }

      // Process any remaining participants
      if (participantMap.size > 0) {
        const remaining = Array.from(participantMap.entries());
        await processContactBatch(remaining, 'Messenger');
        
        // OPTIMIZATION: Non-blocking final progress update
        // Update progress after final batch (fire and forget)
        prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: contactsStored,
            totalContacts: contactsStored,
          },
        }).catch(() => {}); // Silently fail - don't block
      } else {
        // OPTIMIZATION: Non-blocking progress update
        // Update progress even if no remaining participants (fire and forget)
        prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: contactsStored,
            totalContacts: contactsStored,
          },
        }).catch(() => {}); // Silently fail - don't block
      }

      console.log(`[Instant Sync ${jobId}] ✅ Stored ${contactsStored} Messenger contacts`);
    } catch (error) {
      // Clean up on error
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (streamTimeout) clearTimeout(streamTimeout);
      
      console.error(`[Instant Sync ${jobId}] Failed to fetch Messenger conversations:`, error);
      errors.push({
        platform: 'Messenger',
        id: 'conversations',
        error: error instanceof Error ? error.message : 'Failed to fetch conversations',
      });
    }

    // Handle Instagram if connected
    // OPTIMIZATION: Stream Instagram conversations and process in batches
    if (page.instagramAccountId) {
      try {
        console.log(`[Instant Sync ${jobId}] Streaming Instagram conversations...`);
        
        // Collect unique participants as we stream conversations
        const igParticipantMap = new Map<string, { updatedTime: string; name?: string }>();
        let igConversationCount = 0;
        // OPTIMIZATION: Reduced batch size for Instagram too for faster appearance
        const IG_PROCESS_BATCH_SIZE = 100; // Process every 100 conversations
        const MAX_IG_STREAM_TIME = 10 * 60 * 1000; // 10 minutes max for streaming
        // OPTIMIZATION: Reduced progress update frequency
        const IG_PROGRESS_UPDATE_INTERVAL = 20; // Update progress every 20 conversations
        const igStreamStartTime = Date.now();
        let lastIgProgressUpdate = Date.now();
        
        // OPTIMIZATION: Process conversations as they're fetched (streaming)
        for await (const convo of client.fetchInstagramConversationsStream(page.instagramAccountId)) {
          // Check for cancellation
          if (await isJobCancelled(jobId)) {
            console.log(`[Instant Sync ${jobId}] Sync cancelled by user during Instagram sync`);
            return;
          }
          
          // Check for timeout
          if (Date.now() - igStreamStartTime > MAX_IG_STREAM_TIME) {
            console.warn(`[Instant Sync ${jobId}] ⚠️ Instagram stream timeout reached, processing collected participants...`);
            break;
          }
          
          igConversationCount++;
          
          if (!convo.participants?.data) continue;
          
          // Extract participants from this conversation immediately
          for (const participant of convo.participants.data) {
            if (participant.id === page.instagramAccountId) continue;
            
            const existing = igParticipantMap.get(participant.id);
            if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
              igParticipantMap.set(participant.id, {
                updatedTime: convo.updated_time,
                name: participant.name,
              });
            }
          }
          
          // OPTIMIZATION: Process contacts in batches during streaming (every 100 conversations)
          // OPTIMIZATION: Queue batches for parallel processing instead of waiting
          if (igConversationCount % IG_PROCESS_BATCH_SIZE === 0 && igParticipantMap.size > 0) {
            const batchToProcess = Array.from(igParticipantMap.entries());
            const remainingCount = igParticipantMap.size; // Store before clearing
            igParticipantMap.clear(); // Clear processed participants
            
            // OPTIMIZATION: Queue batch for parallel processing (track promise and count)
            const batchPromise = batchProcessor.execute(async () => {
              const batchCount = await processContactBatch(batchToProcess, 'Instagram');
              console.log(`[Instant Sync ${jobId}] Instagram batch processed: ${batchCount} contacts stored (${batchToProcess.length} participants)`);
              
              // OPTIMIZATION: Truly non-blocking progress update (fire and forget)
              // Update progress (non-blocking) - use remainingCount before clearing
              prisma.syncJob.update({
                where: { id: jobId },
                data: {
                  syncedContacts: contactsStored,
                  totalContacts: contactsStored + remainingCount, // Use count before clearing
                },
              }).catch(() => {}); // Silently fail - progress updates are not critical
              
              return batchCount; // Return count for verification
            }).catch(err => {
              console.error(`[Instant Sync ${jobId}] Instagram batch processing error:`, err);
              return 0; // Return 0 on error
            });
            batchPromises.push(batchPromise);
            
            lastIgProgressUpdate = Date.now();
          } else if (igConversationCount % IG_PROGRESS_UPDATE_INTERVAL === 0 || Date.now() - lastIgProgressUpdate > 5000) {
            // OPTIMIZATION: Truly non-blocking progress update (fire and forget)
            // Periodic progress update to show activity even when not processing batches
            const estimatedTotal = contactsStored + igParticipantMap.size;
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: contactsStored,
                totalContacts: estimatedTotal > 0 ? estimatedTotal : igParticipantMap.size, // Show discovered contacts even if not stored yet
              },
            }).catch(() => {}); // Silently fail - progress updates are not critical
            
            console.log(`[Instant Sync ${jobId}] Instagram Progress: ${contactsStored} stored, ${igParticipantMap.size} discovered, ${igConversationCount} conversations processed`);
            lastIgProgressUpdate = Date.now();
          }
        }
        
        console.log(`[Instant Sync ${jobId}] Fetched ${igConversationCount} Instagram conversations`);

        // CRITICAL FIX: Wait for all queued batches to complete before processing remaining
        // This ensures all parallel batches finish and contactsStored is accurate
        if (batchPromises.length > 0) {
          console.log(`[Instant Sync ${jobId}] Waiting for ${batchPromises.length} parallel Instagram batches to complete...`);
          const batchResults = await Promise.all(batchPromises);
          const totalFromBatches = batchResults.reduce((sum, count) => sum + count, 0);
          console.log(`[Instant Sync ${jobId}] All parallel Instagram batches completed. Batch results: ${totalFromBatches} contacts, Shared counter: ${contactsStored}`);
          
          // Verify counter matches batch results (for debugging)
          if (totalFromBatches !== contactsStored) {
            console.warn(`[Instant Sync ${jobId}] ⚠️ Counter mismatch! Batch results: ${totalFromBatches}, Shared counter: ${contactsStored}`);
            // Use the batch results as source of truth
            contactsStored = totalFromBatches;
          }
        }

        // Process any remaining Instagram participants
        if (igParticipantMap.size > 0) {
          const remaining = Array.from(igParticipantMap.entries());
          await processContactBatch(remaining, 'Instagram');
          
          // OPTIMIZATION: Non-blocking final progress update
          // Update progress after final batch (fire and forget)
          prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: contactsStored,
            },
          }).catch(() => {}); // Silently fail - don't block
        } else {
          // OPTIMIZATION: Non-blocking progress update
          // Update progress even if no remaining participants (fire and forget)
          prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: contactsStored,
            },
          }).catch(() => {}); // Silently fail - don't block
        }

        console.log(`[Instant Sync ${jobId}] ✅ Stored ${contactsStored} total contacts (including Instagram)`);
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Failed to fetch Instagram conversations:`, error);
        errors.push({
          platform: 'Instagram',
          id: 'conversations',
          error: error instanceof Error ? error.message : 'Failed to fetch conversations',
        });
      }
    }

    // Update last synced time
    await prisma.facebookPage.update({
      where: { id: page.id },
      data: { lastSyncedAt: new Date() },
    });

    // Phase 2: Queue AI analysis as background job
    let aiAnalysisQueued = false;
    if (contactIds.length > 0) {
      try {
        console.log(`[Instant Sync ${jobId}] 🧠 Queuing AI analysis for ${contactIds.length} contacts...`);
        await startBackgroundAnalysis(
          contactIds,
          page.organizationId,
          userId
        );
        aiAnalysisQueued = true;
        console.log(`[Instant Sync ${jobId}] ✅ AI analysis queued successfully`);
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Failed to queue AI analysis:`, error);
        // Don't fail the sync if AI queueing fails
      }
    }

    // Mark sync as completed
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'COMPLETED',
        syncedContacts: contactsStored,
        totalContacts: contactsStored,
        failedContacts: errors.length,
        errors: errors.length > 0 ? errors : Prisma.JsonNull,
        completedAt: new Date(),
      },
    });

    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[Instant Sync ${jobId}] ✅ Completed in ${elapsedTime}s: ${contactsStored} contacts stored, AI analysis queued: ${aiAnalysisQueued}`);

    // Automatically start pipeline analysis if auto-pipeline is configured
    if (page.autoPipelineId && contactsStored > 0) {
      try {
        console.log(`[Instant Sync ${jobId}] 🔄 Auto-starting pipeline analysis for ${contactsStored} contacts...`);
        const pipelineResult = await startPipelineAnalysis(facebookPageId);
        console.log(`[Instant Sync ${jobId}] ✅ Pipeline analysis started: ${pipelineResult.jobId}`);
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] ⚠️ Failed to start pipeline analysis (non-critical):`, error);
        // Don't fail the sync if pipeline analysis fails to start
      }
    }
  } catch (error) {
    console.error(`[Instant Sync ${jobId}] ❌ Failed:`, error);
    // Mark job as failed in database
    try {
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          status: 'FAILED',
          errors: [
            {
              error: error instanceof Error ? error.message : String(error),
              timestamp: new Date().toISOString(),
            },
          ],
          completedAt: new Date(),
        },
      });
    } catch (dbError) {
      console.error(`[Instant Sync ${jobId}] ❌ Failed to update job status:`, dbError);
    }
    throw error;
  }
}

export async function startInstantSync(
  facebookPageId: string,
  userId: string
): Promise<InstantSyncResult> {
  try {
    // Check if there's already an active sync job for this page
    const existingJob = await prisma.syncJob.findFirst({
      where: {
        facebookPageId,
        status: {
          in: ['PENDING', 'IN_PROGRESS'],
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    if (existingJob) {
      return {
        success: true,
        jobId: existingJob.id,
        message: 'Sync already in progress',
        contactsStored: 0,
        aiAnalysisQueued: false,
      };
    }

    // Create a new sync job
    const syncJob = await prisma.syncJob.create({
      data: {
        facebookPageId,
        status: 'PENDING',
      },
    });

    console.log(`[Instant Sync ${syncJob.id}] 🚀 Starting instant sync...`);

    // CRITICAL: Start the sync process asynchronously and ensure it begins executing
    // For Vercel serverless, we must ensure the promise is actively executing before returning
    // The IIFE pattern ensures the promise starts immediately
    const backgroundPromise = (async () => {
      try {
        // CRITICAL: Log immediately to confirm promise is executing
        console.log(`[Instant Sync ${syncJob.id}] 📍 Inside background promise - starting execution NOW`);
        
        // CRITICAL: Start the first async operation immediately
        // This ensures the promise is actively executing, not just created
        await new Promise(resolve => setTimeout(resolve, 0)); // Yield to event loop
        console.log(`[Instant Sync ${syncJob.id}] ✅ Promise is executing, starting sync...`);
        
        // Now call the actual sync function
        await executeInstantSync(syncJob.id, facebookPageId, userId);
        console.log(`[Instant Sync ${syncJob.id}] ✅ Background execution completed`);
      } catch (error) {
        console.error(`[Instant Sync ${syncJob.id}] ❌ CRITICAL ERROR:`, error);
        console.error(`[Instant Sync ${syncJob.id}] Error stack:`, error instanceof Error ? error.stack : 'No stack trace');
        // Error handling is done in executeInstantSync
      }
    })(); // Immediately invoked async function - starts executing NOW
    
    // CRITICAL: In Vercel, we need to keep the promise alive
    // Store it globally to prevent garbage collection
    if (typeof globalThis !== 'undefined') {
      // Store promise to keep it alive
      (globalThis as any).__activeSyncPromises = (globalThis as any).__activeSyncPromises || new Set();
      (globalThis as any).__activeSyncPromises.add(backgroundPromise);
      
      // Clean up when done
      backgroundPromise.finally(() => {
        (globalThis as any).__activeSyncPromises?.delete(backgroundPromise);
      });
    }

    return {
      success: true,
      jobId: syncJob.id,
      message: 'Instant sync started',
      contactsStored: 0,
      aiAnalysisQueued: false,
    };
  } catch (error) {
    console.error('Failed to start instant sync:', error);
    throw error;
  }
}

