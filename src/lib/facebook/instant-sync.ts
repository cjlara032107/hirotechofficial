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
    // Update job status to in progress with initial progress
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'IN_PROGRESS',
        startedAt: new Date(),
        syncedContacts: 0,
        totalContacts: 0, // Will be updated as we discover contacts
      },
    });

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
    const processContactBatch = async (
      participants: Array<[string, { updatedTime: string; name?: string }]>,
      platform: 'Messenger' | 'Instagram'
    ) => {
      if (participants.length === 0) return;

      const participantIds = participants.map(([id]) => id);
      
      // Batch fetch existing contacts
      const existingContacts = await prisma.contact.findMany({
        where: {
          OR: platform === 'Messenger' 
            ? [{ messengerPSID: { in: participantIds }, facebookPageId: page.id }]
            : [
                { instagramSID: { in: participantIds }, facebookPageId: page.id },
                { messengerPSID: { in: participantIds }, facebookPageId: page.id },
              ],
        },
        select: { id: true, messengerPSID: true, instagramSID: true },
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

      // OPTIMIZATION: Use bulk operations with timeout
      try {
        const BATCH_OPERATION_TIMEOUT = 60000; // 60 seconds max for batch operations
        
        // Bulk create new contacts with timeout
        if (toCreate.length > 0) {
          const createPromise = prisma.$transaction(
            async (tx) => {
              return Promise.all(toCreate.map(data => tx.contact.create({ data })));
            },
            { timeout: BATCH_OPERATION_TIMEOUT }
          );
          
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Batch create operation timed out')), BATCH_OPERATION_TIMEOUT);
          });
          
          const created = await Promise.race([createPromise, timeoutPromise]);
          contactIds.push(...created.map(c => c.id));
          contactsStored += created.length;
        }

        // Bulk update existing contacts with timeout
        if (toUpdate.length > 0) {
          const updatePromise = Promise.all(
            toUpdate.map(update => 
              prisma.contact.update({
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
          
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('Batch update operation timed out')), BATCH_OPERATION_TIMEOUT);
          });
          
          await Promise.race([updatePromise, timeoutPromise]);
          contactIds.push(...toUpdate.map(u => u.id));
          contactsStored += toUpdate.length;
        }
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
                contactsStored++;
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
      }
    };

    // Phase 1: Fast contact storage (NO AI ANALYSIS)
    // OPTIMIZATION: Stream conversations and process contacts in batches as they arrive
    let heartbeatInterval: NodeJS.Timeout | null = null;
    let streamTimeout: NodeJS.Timeout | null = null;
    
    try {
      console.log(`[Instant Sync ${jobId}] Streaming Messenger conversations...`);
      
      // Collect unique participants as we stream conversations
      const participantMap = new Map<string, { updatedTime: string; name?: string }>();
      let conversationCount = 0;
      const PROCESS_BATCH_SIZE = 50; // Process every 50 conversations
      const MAX_STREAM_TIME = 30 * 60 * 1000; // 30 minutes max for streaming (increased from 10 to handle large pages)
      const PROGRESS_UPDATE_INTERVAL = 10; // Update progress every 10 conversations (reduced from 30)
      const streamStartTime = Date.now();
      let lastProgressUpdate = Date.now();
      let lastConversationTime = Date.now(); // Track when we last received a conversation
      
      // Initial progress update to show we're actively fetching
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          syncedContacts: 0,
          totalContacts: 0,
        },
      }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update initial progress:`, err));
      
      console.log(`[Instant Sync ${jobId}] Starting to stream conversations...`);
      
      // Heartbeat mechanism: Update progress every 30 seconds even if no conversations processed
      heartbeatInterval = setInterval(async () => {
        const elapsed = Date.now() - streamStartTime;
        const elapsedSeconds = Math.floor(elapsed / 1000);
        console.log(`[Instant Sync ${jobId}] 💓 Heartbeat: ${elapsedSeconds}s elapsed, ${conversationCount} conversations, ${participantMap.size} participants discovered`);
        
        // Update progress to show we're still alive
        prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: contactsStored,
            totalContacts: contactsStored + participantMap.size,
          },
        }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update heartbeat:`, err));
      }, 30000); // Every 30 seconds
      
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
        
        // Update progress immediately on first conversation to show activity
        if (conversationCount === 1) {
          prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: 0,
              totalContacts: 0,
            },
          }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update first conversation progress:`, err));
          console.log(`[Instant Sync ${jobId}] ✅ Started streaming conversations...`);
        }
        
        if (!convo.participants?.data) continue;
        
        // Extract participants from this conversation immediately
        for (const participant of convo.participants.data) {
          if (participant.id === page.pageId) continue;
          
          const existing = participantMap.get(participant.id);
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            participantMap.set(participant.id, {
              updatedTime: convo.updated_time,
              name: participant.name,
            });
          }
        }
        
        // OPTIMIZATION: Process contacts in batches during streaming (every 50 conversations)
        // This allows contacts to appear immediately instead of waiting for all conversations
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
          
          await processContactBatch(batchToProcess, 'Messenger');
          
          // Update progress (non-blocking) - use remainingCount before clearing
          prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: contactsStored + remainingCount, // Use count before clearing
            },
          }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update progress:`, err));
          
          lastProgressUpdate = Date.now();
        } else if (conversationCount % PROGRESS_UPDATE_INTERVAL === 0 || Date.now() - lastProgressUpdate > 3000) {
          // Periodic progress update to show activity even when not processing batches
          // Update every 10 conversations or every 3 seconds, whichever comes first
          // This ensures progress is visible even during the initial streaming phase
          const estimatedTotal = contactsStored + participantMap.size;
          prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: estimatedTotal > 0 ? estimatedTotal : participantMap.size, // Show discovered contacts even if not stored yet
            },
          }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update periodic progress:`, err));
          
          console.log(`[Instant Sync ${jobId}] Progress: ${contactsStored} stored, ${participantMap.size} discovered, ${conversationCount} conversations processed`);
          lastProgressUpdate = Date.now();
        }
      }
      
      // Clean up heartbeat and timeout
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (streamTimeout) clearTimeout(streamTimeout);
      
      console.log(`[Instant Sync ${jobId}] Fetched ${conversationCount} Messenger conversations`);

      // Process any remaining participants
      if (participantMap.size > 0) {
        const remaining = Array.from(participantMap.entries());
        await processContactBatch(remaining, 'Messenger');
        
        // Update progress after final batch
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: contactsStored,
            totalContacts: contactsStored,
          },
        }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update final progress:`, err));
      } else {
        // Update progress even if no remaining participants
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: contactsStored,
            totalContacts: contactsStored,
          },
        }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update final progress:`, err));
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
        const IG_PROCESS_BATCH_SIZE = 50; // Process every 50 conversations
        const MAX_IG_STREAM_TIME = 10 * 60 * 1000; // 10 minutes max for streaming
        const IG_PROGRESS_UPDATE_INTERVAL = 30; // Update progress every 30 conversations even if not processing batch
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
          
          // OPTIMIZATION: Process contacts in batches during streaming (every 50 conversations)
          if (igConversationCount % IG_PROCESS_BATCH_SIZE === 0 && igParticipantMap.size > 0) {
            const batchToProcess = Array.from(igParticipantMap.entries());
            const remainingCount = igParticipantMap.size; // Store before clearing
            igParticipantMap.clear(); // Clear processed participants
            
            await processContactBatch(batchToProcess, 'Instagram');
            
            // Update progress (non-blocking) - use remainingCount before clearing
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: contactsStored,
                totalContacts: contactsStored + remainingCount, // Use count before clearing
              },
            }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update progress:`, err));
            
            lastIgProgressUpdate = Date.now();
          } else if (igConversationCount % IG_PROGRESS_UPDATE_INTERVAL === 0 || Date.now() - lastIgProgressUpdate > 3000) {
            // Periodic progress update to show activity even when not processing batches
            // Update every 10 conversations or every 3 seconds, whichever comes first
            const estimatedTotal = contactsStored + igParticipantMap.size;
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: contactsStored,
                totalContacts: estimatedTotal > 0 ? estimatedTotal : igParticipantMap.size, // Show discovered contacts even if not stored yet
              },
            }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update periodic Instagram progress:`, err));
            
            console.log(`[Instant Sync ${jobId}] Instagram Progress: ${contactsStored} stored, ${igParticipantMap.size} discovered, ${igConversationCount} conversations processed`);
            lastIgProgressUpdate = Date.now();
          }
        }
        
        console.log(`[Instant Sync ${jobId}] Fetched ${igConversationCount} Instagram conversations`);

        // Process any remaining Instagram participants
        if (igParticipantMap.size > 0) {
          const remaining = Array.from(igParticipantMap.entries());
          await processContactBatch(remaining, 'Instagram');
          
          // Update progress after final batch
          await prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: contactsStored,
            },
          }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update final Instagram progress:`, err));
        } else {
          // Update progress even if no remaining participants
          await prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: contactsStored,
              totalContacts: contactsStored,
            },
          }).catch(err => console.error(`[Instant Sync ${jobId}] Failed to update final Instagram progress:`, err));
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

