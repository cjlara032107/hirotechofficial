import { prisma, connectPrisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { startBackgroundAnalysis } from './background-analysis';
import { startPipelineAnalysis } from './pipeline-analyzer';
import { isValidPSID, isValidSID, hasValidContactId, normalizeContactId } from './contact-validation';
import {
  isJobActive,
  verifyPageExists,
  markJobFailedDueToPageDeletion,
} from './job-safety-checks';
import { autoAssignBestContactTimes } from '@/lib/contacts/compute-contact-times';

interface InstantSyncResult {
  success: boolean;
  jobId: string;
  message: string;
  contactsStored: number;
  aiAnalysisQueued: boolean;
}

interface FacebookMessage {
  id?: string;
  message?: string;
  attachments?: unknown;
  created_time?: string;
  from?: {
    id?: string;
    name?: string;
  };
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
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();
    
    // CRITICAL: Update job status to IN_PROGRESS BEFORE checking if job is active
    // We must wait for this update to complete, otherwise the job status check will fail
    // because it will still see PENDING status
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

    // Check job status before starting (now that status is updated)
    const statusCheck = await isJobActive(jobId, 'sync');
    if (!statusCheck.active) {
      console.log(`[Instant Sync ${jobId}] Job is not active: ${statusCheck.reason}`);
      return;
    }

    // Verify page exists before proceeding
    const pageCheck = await verifyPageExists(facebookPageId);
    if (!pageCheck.exists || !pageCheck.page) {
      await markJobFailedDueToPageDeletion(jobId, pageCheck.reason || 'Facebook page not found');
      throw new Error(pageCheck.reason || 'Facebook page not found');
    }
    const page = pageCheck.page;

    const client = new FacebookClient(page.pageAccessToken);
    let contactsStored = 0;
    // OPTIMIZATION: Don't collect contactIds during sync - we'll query all at the end (single query)
    const errors: Array<{ platform: string; id: string; error: string }> = [];

    // OPTIMIZATION: Cache existing contacts across batches to avoid repeated queries
    // This significantly reduces database queries for large syncs
    const existingContactsCache = new Map<string, string>(); // participantId -> contactId
    const cacheInitialized = false;

    // OPTIMIZATION: Process contacts in batches during streaming for immediate storage
    // Returns the number of contacts stored (created + updated)
    const processContactBatch = async (
      participants: Array<[string, { updatedTime: string; name?: string; conversationId?: string }]>,
      platform: 'Messenger' | 'Instagram'
    ): Promise<number> => {
      if (participants.length === 0) return 0;

      const participantIds = participants.map(([id]) => id);
      
      // OPTIMIZATION: Batch fetch existing contacts with caching
      // Only query contacts not in cache to minimize database queries
      const uncachedIds = participantIds.filter(id => !existingContactsCache.has(id));
      let existingContacts: Array<{ id: string; messengerPSID: string | null; instagramSID: string | null }> = [];
      
      if (uncachedIds.length > 0) {
        // OPTIMIZATION: Only query uncached contacts
        const QUERY_BATCH_SIZE = 10000; // Maximum IDs per query to avoid query size limits
        
        if (uncachedIds.length <= QUERY_BATCH_SIZE) {
          // Single query for smaller batches
          existingContacts = await prisma.contact.findMany({
            where: {
              facebookPageId: page.id, // Filter by page first (indexed) for better performance
              OR: platform === 'Messenger' 
                ? [{ messengerPSID: { in: uncachedIds } }]
                : [
                    { instagramSID: { in: uncachedIds } },
                    { messengerPSID: { in: uncachedIds } },
                  ],
            },
            select: { id: true, messengerPSID: true, instagramSID: true }, // Only select needed fields
          });
        } else {
          // Split into multiple queries for very large batches
          const queryChunks: string[][] = [];
          for (let i = 0; i < uncachedIds.length; i += QUERY_BATCH_SIZE) {
            queryChunks.push(uncachedIds.slice(i, i + QUERY_BATCH_SIZE));
          }
          
          const queryResults = await Promise.all(
            queryChunks.map(chunk =>
              prisma.contact.findMany({
                where: {
                  facebookPageId: page.id,
                  OR: platform === 'Messenger' 
                    ? [{ messengerPSID: { in: chunk } }]
                    : [
                        { instagramSID: { in: chunk } },
                        { messengerPSID: { in: chunk } },
                      ],
                },
                select: { id: true, messengerPSID: true, instagramSID: true },
              })
            )
          );
          
          existingContacts = queryResults.flat();
        }
        
        // OPTIMIZATION: Update cache with newly fetched contacts
        for (const contact of existingContacts) {
          const id = platform === 'Messenger' ? contact.messengerPSID : (contact.instagramSID || contact.messengerPSID);
          if (id) existingContactsCache.set(id, contact.id);
        }
      }
      
      // Build existing map from cache and newly fetched contacts
      // Normalize IDs when building map to match lookup keys
      const existingMap = new Map<string, string>();
      
      // First, add cached contacts (normalize IDs for consistency)
      for (const participantId of participantIds) {
        const normalized = normalizeContactId(participantId);
        if (normalized) {
          const cachedId = existingContactsCache.get(normalized) || existingContactsCache.get(participantId);
          if (cachedId) {
            existingMap.set(normalized, cachedId);
            // Also cache with normalized ID
            existingContactsCache.set(normalized, cachedId);
          }
        }
      }
      
      // Then, add newly fetched contacts to map and cache (normalize IDs)
      for (const contact of existingContacts) {
        const id = platform === 'Messenger' ? contact.messengerPSID : (contact.instagramSID || contact.messengerPSID);
        if (id) {
          const normalized = normalizeContactId(id);
          if (normalized) {
            existingMap.set(normalized, contact.id);
            // Cache with normalized ID
            existingContactsCache.set(normalized, contact.id);
          }
        }
      }

      // OPTIMIZATION: Pre-allocate arrays with estimated size for better performance
      // Estimate: ~70% new contacts, ~30% updates (typical ratio)
      const estimatedNew = Math.ceil(participants.length * 0.7);
      const estimatedUpdates = Math.ceil(participants.length * 0.3);
      
      // Separate new contacts from updates
      // Track conversation IDs for message fetching (participantId -> conversationId)
      const conversationIdMap = new Map<string, string>();
      
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
      }> = new Array(estimatedNew); // Pre-allocate with estimated size
      let toCreateIndex = 0;
      
      const toUpdate: Array<{
        id: string;
        firstName: string;
        lastName: string | null;
        lastInteraction: Date;
        hasMessenger?: boolean;
        hasInstagram?: boolean;
        instagramSID?: string;
        messengerPSID?: string;
      }> = new Array(estimatedUpdates); // Pre-allocate with estimated size
      let toUpdateIndex = 0;

      // OPTIMIZATION: Pre-compute platform-specific values to avoid repeated conditionals
      const isMessenger = platform === 'Messenger';
      const defaultNamePrefix = isMessenger ? 'User ' : 'IG User ';
      const messengerFields = isMessenger 
        ? { hasMessenger: true, hasInstagram: false }
        : { hasInstagram: true, hasMessenger: false };

      for (const [participantId, info] of participants) {
        // Validate and normalize the participant ID
        const normalizedId = normalizeContactId(participantId);
        if (!normalizedId) {
          console.warn(`[Instant Sync ${jobId}] Skipping invalid participant ID: ${participantId}`);
          continue; // Skip invalid IDs
        }

        // Validate ID format based on platform
        const isValidId = isMessenger ? isValidPSID(normalizedId) : isValidSID(normalizedId);
        if (!isValidId) {
          console.warn(`[Instant Sync ${jobId}] Skipping invalid ${platform} ID format: ${normalizedId}`);
          continue; // Skip invalid ID formats
        }

        // OPTIMIZATION: Optimize name parsing - reduce string operations
        let firstName: string;
        let lastName: string | null = null;

        if (info.name?.trim()) {
          // OPTIMIZATION: Use indexOf instead of split for better performance
          const trimmedName = info.name.trim();
          const firstSpaceIndex = trimmedName.indexOf(' ');
          
          if (firstSpaceIndex > 0) {
            firstName = trimmedName.substring(0, firstSpaceIndex);
            lastName = trimmedName.substring(firstSpaceIndex + 1) || null;
          } else {
            firstName = trimmedName;
          }
        } else {
          // OPTIMIZATION: Pre-computed prefix + slice (faster than template literal)
          firstName = defaultNamePrefix + normalizedId.slice(-6);
        }

        // Track conversation ID for message fetching
        if (info.conversationId) {
          conversationIdMap.set(normalizedId, info.conversationId);
        }
        
        const existingId = existingMap.get(normalizedId);
        // OPTIMIZATION: Cache Date parsing - only parse once per updatedTime
        const lastInteraction = new Date(info.updatedTime);

        if (existingId) {
          // Get existing contact to check if it has both IDs
          const existingContact = existingContacts.find(c => c.id === existingId);
          
          // Handle contacts with both Messenger and Instagram IDs
          const updateData: {
            id: string;
            firstName: string;
            lastName: string | null;
            lastInteraction: Date;
            hasMessenger?: boolean;
            hasInstagram?: boolean;
            instagramSID?: string;
            messengerPSID?: string;
          } = {
            id: existingId,
            firstName,
            lastName,
            lastInteraction,
          };

          if (isMessenger) {
            updateData.hasMessenger = true;
            updateData.messengerPSID = normalizedId;
            // If contact already has Instagram ID, preserve it
            if (existingContact?.instagramSID) {
              updateData.hasInstagram = true;
            }
          } else {
            updateData.hasInstagram = true;
            updateData.instagramSID = normalizedId;
            // If contact already has Messenger PSID, preserve it
            if (existingContact?.messengerPSID) {
              updateData.hasMessenger = true;
              updateData.messengerPSID = existingContact.messengerPSID;
            }
          }

          // OPTIMIZATION: Direct array assignment instead of push (faster)
          toUpdate[toUpdateIndex++] = updateData;
        } else {
          // Ensure contact has at least one valid ID before creating
          if (!hasValidContactId(
            isMessenger ? normalizedId : null,
            isMessenger ? null : normalizedId
          )) {
            console.warn(`[Instant Sync ${jobId}] Cannot create contact without valid ID: ${normalizedId}`);
            continue; // Skip contacts without valid IDs
          }

          // OPTIMIZATION: Direct array assignment and pre-computed fields
          toCreate[toCreateIndex++] = {
            ...(isMessenger 
              ? { messengerPSID: normalizedId, ...messengerFields }
              : { instagramSID: normalizedId, ...messengerFields }),
            firstName,
            lastName,
            organizationId: page.organizationId,
            facebookPageId: page.id,
            lastInteraction,
          };
        }
      }

      // OPTIMIZATION: Use bulk operations with timeout and parallel processing
      // CRITICAL: Use createMany() for bulk inserts - 10-50x faster than individual creates
      try {
        const BATCH_OPERATION_TIMEOUT = 60000; // 60 seconds max for batch operations
        
      // OPTIMIZATION: Trim arrays to actual size (remove pre-allocated empty slots)
      const actualToCreate = toCreateIndex > 0 ? toCreate.slice(0, toCreateIndex) : [];
      const actualToUpdate = toUpdateIndex > 0 ? toUpdate.slice(0, toUpdateIndex) : [];

      // OPTIMIZATION: Process creates and updates in parallel for maximum speed
      // Both operations are independent and can run simultaneously
      const [createdResults, updateResults] = await Promise.all([
          // OPTIMIZATION: Use createMany() for bulk inserts - MUCH faster than individual creates
          // createMany is optimized for bulk operations and doesn't return records, so we query them back
          actualToCreate.length > 0 ? (async () => {
            const CREATE_CHUNK_SIZE = 5000; // Increased to 5000 - createMany can handle large batches efficiently
            const createChunks: typeof actualToCreate[] = [];
            for (let i = 0; i < actualToCreate.length; i += CREATE_CHUNK_SIZE) {
              createChunks.push(actualToCreate.slice(i, i + CREATE_CHUNK_SIZE));
            }
            
            // OPTIMIZATION: Process chunks in parallel without transaction overhead
            // createMany is atomic and doesn't need a transaction wrapper
            const limiter = new ConcurrencyLimiter(30); // 30 concurrent create chunks
            
            // OPTIMIZATION: Collect all participant IDs first for batch query-back
            const allParticipantIds: string[] = [];
            const createPromises = createChunks.map(chunk =>
              limiter.execute(async () => {
                // Use createMany with skipDuplicates to handle race conditions gracefully
                await prisma.contact.createMany({
                  data: chunk,
                  skipDuplicates: true, // Skip if duplicate key exists (handles race conditions)
                });
                
                // Collect participant IDs for batch query-back (more efficient than per-chunk queries)
                const participantIds = chunk.map(c => 
                  platform === 'Messenger' ? c.messengerPSID : c.instagramSID
                ).filter((id): id is string => !!id);
                
                allParticipantIds.push(...participantIds);
                return participantIds; // Return IDs for batch query
              })
            );
            
            const timeoutPromise = new Promise<never>((_, reject) => {
              setTimeout(() => reject(new Error('Batch create operation timed out')), BATCH_OPERATION_TIMEOUT);
            });
            
            await Promise.race([
              Promise.all(createPromises),
              timeoutPromise,
            ]);
            
            // OPTIMIZATION: Skip query-back during sync - we'll query all contacts at the end
            // This eliminates N queries during sync and defers to a single query at the end
            // Contact IDs are only needed for AI analysis queuing, which happens after sync completes
            // Return count instead of IDs - we'll query IDs at the end
            return allParticipantIds.length; // Return count for progress tracking
          })() : Promise.resolve(0),

          // OPTIMIZATION: Batch updates in parallel with higher concurrency
          // Note: Can't use updateMany easily since each contact has different data
          // But we can optimize by processing larger chunks in parallel
          actualToUpdate.length > 0 ? (async () => {
            const UPDATE_CHUNK_SIZE = 3000; // Increased to 3000 - updates can handle larger batches
            const updateChunks: typeof actualToUpdate[] = [];
            for (let i = 0; i < actualToUpdate.length; i += UPDATE_CHUNK_SIZE) {
              updateChunks.push(actualToUpdate.slice(i, i + UPDATE_CHUNK_SIZE));
            }
            
            // OPTIMIZATION: Process update chunks in parallel without transaction overhead
            // Individual updates are atomic, transaction wrapper adds overhead
            const limiter = new ConcurrencyLimiter(30); // 30 concurrent update chunks
            const updatePromises = updateChunks.map(chunk =>
              limiter.execute(async () => {
                // Process updates in parallel within chunk
                await Promise.all(
                  chunk.map(update =>
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
                return chunk.map(u => u.id);
              })
            );
            
            const timeoutPromise = new Promise<never>((_, reject) => {
              setTimeout(() => reject(new Error('Batch update operation timed out')), BATCH_OPERATION_TIMEOUT);
            });
            
            const allUpdated = await Promise.race([
              Promise.all(updatePromises),
              timeoutPromise,
            ]);
            
            return allUpdated.flat();
          })() : Promise.resolve([]),
        ]);

        // OPTIMIZATION: Don't collect contact IDs during sync - we'll query all at the end
        // This eliminates query-back overhead during sync (N queries → 0 queries during sync)
        // Contact IDs are only needed for AI analysis, which happens after sync completes
        // Both results are now consistently typed: createdResults is a number, updateResults is an array
        const batchCount = (typeof createdResults === 'number' ? createdResults : 0) + (Array.isArray(updateResults) ? updateResults.length : 0);
        contactsStored += batchCount; // Update shared counter for progress tracking
        
        // Fetch and save messages for contacts in this batch (non-blocking, runs in background)
        if (conversationIdMap.size > 0) {
          // Query back contacts to get their IDs
          const participantIds = Array.from(conversationIdMap.keys());
          const savedContacts = await prisma.contact.findMany({
            where: {
              facebookPageId: page.id,
              OR: platform === 'Messenger'
                ? [{ messengerPSID: { in: participantIds } }]
                : [{ instagramSID: { in: participantIds } }],
            },
            select: {
              id: true,
              messengerPSID: true,
              instagramSID: true,
            },
          });
          
          // Fetch messages for each contact in background
          for (const contact of savedContacts) {
            const participantId = platform === 'Messenger' ? contact.messengerPSID : contact.instagramSID;
            const conversationId = participantId ? conversationIdMap.get(participantId) : undefined;
            
            if (conversationId && participantId) {
              // Fetch messages in background without blocking
              client.getRecentMessagesForConversation(conversationId, 200)
                .then(async (messages) => {
                  if (messages && messages.length > 0) {
                    try {
                      const conversationPlatform = platform === 'Messenger' ? 'MESSENGER' : 'INSTAGRAM';
                      let conversation = await prisma.conversation.findFirst({
                        where: {
                          contactId: contact.id,
                          platform: conversationPlatform,
                        },
                      });

                      if (!conversation) {
                        conversation = await prisma.conversation.create({
                          data: {
                            contactId: contact.id,
                            facebookPageId: page.id,
                            platform: conversationPlatform,
                            status: 'OPEN',
                            lastMessageAt: new Date(),
                          },
                        });
                      }

                      // Check which messages already exist
                      const messageIds = messages
                        .map((m: FacebookMessage) => m.id)
                        .filter((id): id is string => !!id);
                      
                      const existingMessages = messageIds.length > 0
                        ? await prisma.message.findMany({
                            where: {
                              facebookMessageId: { in: messageIds },
                              conversationId: conversation.id,
                            },
                            select: { facebookMessageId: true },
                          })
                        : [];
                      
                      const existingIds = new Set(
                        existingMessages
                          .map(m => m.facebookMessageId)
                          .filter((id): id is string => !!id)
                      );

                      // Prepare messages for bulk insert
                      const messagesToSave = messages
                        .filter((msg: FacebookMessage) => {
                          if (!msg.message && !msg.attachments) return false;
                          if (!msg.created_time) return false;
                          if (msg.id && existingIds.has(msg.id)) return false;
                          return true;
                        })
                        .map((msg: FacebookMessage) => {
                          const isFromBusiness = msg.from?.id === (platform === 'Messenger' ? page.pageId : page.instagramAccountId);
                          const createdAt = new Date(msg.created_time || Date.now());
                          
                          return {
                            contactId: contact.id,
                            conversationId: conversation.id,
                            content: msg.message || '[Media]',
                            platform: conversationPlatform,
                            facebookMessageId: msg.id || '',
                            isFromBusiness,
                            status: 'DELIVERED' as const,
                            createdAt,
                            sentAt: createdAt,
                            deliveredAt: createdAt,
                          };
                        })
                        .filter(msg => !!msg.facebookMessageId && msg.facebookMessageId.length > 0); // Filter out messages without IDs

                      // Save messages in batches
                      if (messagesToSave.length > 0) {
                        const BATCH_SIZE = 100;
                        for (let i = 0; i < messagesToSave.length; i += BATCH_SIZE) {
                          const batch = messagesToSave.slice(i, i + BATCH_SIZE);
                          try {
                            await prisma.message.createMany({
                              data: batch,
                            });
                          } catch (batchError) {
                            // Try individual inserts if batch fails
                            for (const msg of batch) {
                              try {
                                await prisma.message.create({ data: msg });
                              } catch (individualError) {
                                // Skip if already exists
                              }
                            }
                          }
                        }
                        
                        // Update conversation's lastMessageAt
                        if (messagesToSave.length > 0) {
                          const mostRecentMessage = messagesToSave.reduce((latest, msg) => {
                            return msg.createdAt > latest.createdAt ? msg : latest;
                          });
                          await prisma.conversation.update({
                            where: { id: conversation.id },
                            data: { lastMessageAt: mostRecentMessage.createdAt },
                          });
                        }
                        
                        console.log(`[Instant Sync ${jobId}] Saved ${messagesToSave.length} messages for contact ${contact.id} (bulk path)`);
                      }
                    } catch (msgError) {
                      console.error(`[Instant Sync ${jobId}] Failed to save messages for contact ${contact.id}:`, msgError);
                    }
                  }
                })
                .catch((error) => {
                  console.warn(`[Instant Sync ${jobId}] Failed to fetch messages for conversation ${conversationId}:`, error);
                });
            }
          }
        }
        
        return batchCount; // Return count for this batch
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Bulk operation failed, falling back to individual operations:`, error);
        // Fallback to individual operations
        const contactLimiter = new ConcurrencyLimiter(50);
        await Promise.all(
          participants.map(([participantId, info]) =>
            contactLimiter.execute(async () => {
              try {
                // OPTIMIZATION: Optimize name parsing - reduce string operations
                let firstName: string;
                let lastName: string | null = null;

                if (info.name?.trim()) {
                  // OPTIMIZATION: Use indexOf instead of split for better performance
                  const trimmedName = info.name.trim();
                  const firstSpaceIndex = trimmedName.indexOf(' ');
                  
                  if (firstSpaceIndex > 0) {
                    firstName = trimmedName.substring(0, firstSpaceIndex);
                    lastName = trimmedName.substring(firstSpaceIndex + 1) || null;
                  } else {
                    firstName = trimmedName;
                  }
                } else {
                  firstName = platform === 'Messenger' 
                    ? `User ${participantId.slice(-6)}`
                    : `IG User ${participantId.slice(-6)}`;
                }

                const existingId = existingMap.get(normalizedId);
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

                // Fetch and save messages for this contact (non-blocking, runs in background)
                if (info.conversationId) {
                  // Fetch messages in background without blocking contact storage
                  client.getRecentMessagesForConversation(info.conversationId, 200)
                    .then(async (messages) => {
                      if (messages && messages.length > 0) {
                        try {
                          // Find or create conversation
                          const conversationPlatform = platform === 'Messenger' ? 'MESSENGER' : 'INSTAGRAM';
                          let conversation = await prisma.conversation.findFirst({
                            where: {
                              contactId: savedContact.id,
                              platform: conversationPlatform,
                            },
                          });

                          if (!conversation) {
                            conversation = await prisma.conversation.create({
                              data: {
                                contactId: savedContact.id,
                                facebookPageId: page.id,
                                platform: conversationPlatform,
                                status: 'OPEN',
                                lastMessageAt: new Date(info.updatedTime),
                              },
                            });
                          }

                          // Check which messages already exist
                          const messageIds = messages
                            .map((m: FacebookMessage) => m.id)
                            .filter((id): id is string => !!id);
                          
                          const existingMessages = messageIds.length > 0
                            ? await prisma.message.findMany({
                                where: {
                                  facebookMessageId: { in: messageIds },
                                  conversationId: conversation.id,
                                },
                                select: { facebookMessageId: true },
                              })
                            : [];
                          
                          const existingIds = new Set(
                            existingMessages
                              .map(m => m.facebookMessageId)
                              .filter((id): id is string => !!id)
                          );

                          // Prepare messages for bulk insert
                          const messagesToSave = messages
                            .filter((msg: FacebookMessage) => {
                              if (!msg.message && !msg.attachments) return false;
                              if (!msg.created_time) return false;
                              if (msg.id && existingIds.has(msg.id)) return false;
                              return true;
                            })
                            .map((msg: FacebookMessage) => {
                              const isFromBusiness = msg.from?.id === page.pageId;
                              const createdAt = new Date(msg.created_time || Date.now());
                              
                              return {
                                contactId: savedContact.id,
                                conversationId: conversation.id,
                                content: msg.message || '[Media]',
                                platform: conversationPlatform,
                                facebookMessageId: msg.id || '',
                                isFromBusiness,
                                status: 'DELIVERED' as const,
                                createdAt,
                                sentAt: createdAt,
                                deliveredAt: createdAt,
                              };
                            })
                            .filter(msg => msg.facebookMessageId); // Filter out messages without IDs

                          // Save messages in batches
                          if (messagesToSave.length > 0) {
                            const BATCH_SIZE = 100;
                            for (let i = 0; i < messagesToSave.length; i += BATCH_SIZE) {
                              const batch = messagesToSave.slice(i, i + BATCH_SIZE);
                              try {
                                await prisma.message.createMany({
                                  data: batch,
                                });
                              } catch (batchError) {
                                // Try individual inserts if batch fails
                                for (const msg of batch) {
                                  try {
                                    await prisma.message.create({ data: msg });
                                  } catch (individualError) {
                                    // Skip if already exists
                                  }
                                }
                              }
                            }
                            
                            // Update conversation's lastMessageAt
                            if (messagesToSave.length > 0) {
                              const mostRecentMessage = messagesToSave.reduce((latest, msg) => {
                                return msg.createdAt > latest.createdAt ? msg : latest;
                              });
                              await prisma.conversation.update({
                                where: { id: conversation.id },
                                data: { lastMessageAt: mostRecentMessage.createdAt },
                              });
                            }
                            
                            console.log(`[Instant Sync ${jobId}] Saved ${messagesToSave.length} messages for contact ${savedContact.id}`);
                          }
                        } catch (msgError) {
                          // Log but don't fail sync if message saving fails
                          console.error(`[Instant Sync ${jobId}] Failed to save messages for contact ${savedContact.id}:`, msgError);
                        }
                      }
                    })
                    .catch((error) => {
                      // Log but don't fail sync if message fetching fails
                      console.warn(`[Instant Sync ${jobId}] Failed to fetch messages for conversation ${info.conversationId}:`, error);
                    });
                }

                // Automatically assign best contact times (non-blocking, runs in background)
                // Uses fallback: compute from messages -> similar contact -> default times
                autoAssignBestContactTimes(savedContact.id, page.organizationId).catch((error) => {
                  console.error(`[Instant Sync ${jobId}] Failed to assign best contact times for contact ${savedContact.id}:`, error);
                });

                // OPTIMIZATION: Don't collect contact IDs during sync - we'll query all at the end
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
    // OPTIMIZATION: Process Messenger and Instagram in parallel for maximum speed
    // OPTIMIZATION: Parallel batch processing - queue batches and process multiple simultaneously
    // Connection pool analysis:
    // - Total connections: 25
    // - Each batch uses: ~2 connections (1 for transaction, 1 for findMany query)
    // - Leave 2 connections for other operations (progress updates, queries, etc.)
    // - Available for batches: 23 connections
    // - Maximum limit: 25 batches in parallel (transactions share connections efficiently)
    const batchProcessor = new ConcurrencyLimiter(25); // Process 25 batches in parallel (maximum optimization)
    const batchPromises: Promise<number>[] = []; // Track all batch promises to wait for completion (returns count)
    
    // Shared state for progress tracking (thread-safe via async/await)
    let messengerContactsStored = 0;
    let instagramContactsStored = 0;
    
    /**
     * Process Messenger conversations in parallel
     */
    const processMessenger = async (): Promise<number> => {
      const participantMap = new Map<string, { updatedTime: string; name?: string }>();
      let conversationCount = 0;
      const PROCESS_BATCH_SIZE = 500;
      const MAX_STREAM_TIME = 30 * 60 * 1000;
      const PROGRESS_UPDATE_INTERVAL = 50;
      const CANCELLATION_CHECK_INTERVAL = 100;
      const streamStartTime = Date.now();
      let lastProgressUpdate = Date.now();
      const platformBatchPromises: Promise<number>[] = [];
      
      try {
        console.log(`[Instant Sync ${jobId}] Streaming Messenger conversations...`);
        
        for await (const convo of client.fetchMessengerConversationsStream(page.pageId)) {
          // Check for cancellation and verify page still exists
          if (conversationCount % CANCELLATION_CHECK_INTERVAL === 0) {
            try {
              const statusCheck = await isJobActive(jobId, 'sync');
              if (!statusCheck.active) {
                console.log(`[Instant Sync ${jobId}] ${statusCheck.reason || 'Job stopped'}`);
                break;
              }
              const pageRecheck = await verifyPageExists(facebookPageId);
              if (!pageRecheck.exists || !pageRecheck.page) {
                await markJobFailedDueToPageDeletion(jobId, 'Page deleted during job execution');
                throw new Error('Page deleted during job execution');
              }
            } catch (error) {
              const errorMsg = error instanceof Error ? error.message : 'Job stopped';
              console.log(`[Instant Sync ${jobId}] ${errorMsg}`);
              break;
            }
          }
          
          conversationCount++;
          
          if (Date.now() - streamStartTime > MAX_STREAM_TIME) {
            console.warn(`[Instant Sync ${jobId}] ⚠️ Messenger stream timeout reached, processing collected participants...`);
            break;
          }
          
          if (!convo.participants?.data) continue;
          
          // Extract participants and track conversation IDs for message fetching
          for (const participant of convo.participants.data) {
            if (participant.id === page.pageId) continue;
            
            const existing = participantMap.get(participant.id);
            // OPTIMIZATION: String comparison for ISO dates (faster than Date parsing)
            if (!existing || convo.updated_time > existing.updatedTime) {
              participantMap.set(participant.id, {
                updatedTime: convo.updated_time,
                name: participant.name,
                conversationId: convo.id, // Track conversation ID for message fetching
              });
            }
          }
          
          // Process in batches
          if (conversationCount % PROCESS_BATCH_SIZE === 0 && participantMap.size > 0) {
            // OPTIMIZATION: Direct iteration instead of Array.from() for better performance
            const batchToProcess: Array<[string, { updatedTime: string; name?: string; conversationId?: string }]> = [];
            batchToProcess.length = participantMap.size; // Pre-allocate
            let batchIndex = 0;
            for (const entry of participantMap.entries()) {
              batchToProcess[batchIndex++] = entry;
            }
            const remainingCount = participantMap.size;
            participantMap.clear();
            
            const batchPromise = batchProcessor.execute(async () => {
              const batchCount = await processContactBatch(batchToProcess, 'Messenger');
              
              // OPTIMIZATION: Batch progress updates - only update every N batches to reduce overhead
              // Progress updates are fire-and-forget and don't block processing
              if (platformBatchPromises.length % 3 === 0) {
                prisma.syncJob.update({
                  where: { id: jobId },
                  data: {
                    syncedContacts: messengerContactsStored + instagramContactsStored + batchCount,
                    totalContacts: messengerContactsStored + instagramContactsStored + batchCount + remainingCount,
                  },
                }).catch(() => {});
              }
              
              return batchCount;
            }).catch(err => {
              // Only log errors in development or if critical
              if (process.env.NODE_ENV === 'development') {
                console.error(`[Instant Sync ${jobId}] Messenger batch error:`, err);
              }
              return 0;
            });
            
            platformBatchPromises.push(batchPromise);
            batchPromises.push(batchPromise);
            lastProgressUpdate = Date.now();
          } else if (conversationCount % PROGRESS_UPDATE_INTERVAL === 0 || Date.now() - lastProgressUpdate > 5000) {
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: messengerContactsStored + instagramContactsStored,
                totalContacts: messengerContactsStored + instagramContactsStored + participantMap.size,
              },
            }).catch(() => {});
            lastProgressUpdate = Date.now();
          }
        }
        
        // Wait for all batches and calculate total
        if (platformBatchPromises.length > 0) {
          const results = await Promise.all(platformBatchPromises);
          messengerContactsStored = results.reduce((sum, count) => sum + count, 0);
        }
        
        // Process remaining
        if (participantMap.size > 0) {
          // OPTIMIZATION: Direct iteration instead of Array.from() for better performance
          const remaining: Array<[string, { updatedTime: string; name?: string }]> = [];
          remaining.length = participantMap.size; // Pre-allocate
          let remainingIndex = 0;
          for (const entry of participantMap.entries()) {
            remaining[remainingIndex++] = entry;
          }
          const finalCount = await processContactBatch(remaining, 'Messenger');
          messengerContactsStored += finalCount;
        }
        
        console.log(`[Instant Sync ${jobId}] ✅ Messenger: ${messengerContactsStored} contacts stored`);
        return messengerContactsStored;
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Messenger sync failed:`, error);
        errors.push({
          platform: 'Messenger',
          id: 'conversations',
          error: error instanceof Error ? error.message : 'Failed to fetch conversations',
        });
        return 0;
      }
    };
    
    /**
     * Process Instagram conversations in parallel
     */
    const processInstagram = async (): Promise<number> => {
      if (!page.instagramAccountId) return 0;
      
      const igParticipantMap = new Map<string, { updatedTime: string; name?: string }>();
      let igConversationCount = 0;
      const IG_PROCESS_BATCH_SIZE = 500;
      const MAX_IG_STREAM_TIME = 10 * 60 * 1000;
      const IG_PROGRESS_UPDATE_INTERVAL = 50;
      const IG_CANCELLATION_CHECK_INTERVAL = 100;
      const igStreamStartTime = Date.now();
      let lastIgProgressUpdate = Date.now();
      const platformBatchPromises: Promise<number>[] = [];
      
      try {
        console.log(`[Instant Sync ${jobId}] Streaming Instagram conversations...`);
        
        for await (const convo of client.fetchInstagramConversationsStream(page.instagramAccountId)) {
          if (igConversationCount % IG_CANCELLATION_CHECK_INTERVAL === 0) {
            try {
              const statusCheck = await isJobActive(jobId, 'sync');
              if (!statusCheck.active) {
                console.log(`[Instant Sync ${jobId}] ${statusCheck.reason || 'Job stopped'}`);
                break;
              }
              const pageRecheck = await verifyPageExists(facebookPageId);
              if (!pageRecheck.exists || !pageRecheck.page) {
                await markJobFailedDueToPageDeletion(jobId, 'Page deleted during job execution');
                throw new Error('Page deleted during job execution');
              }
            } catch (error) {
              const errorMsg = error instanceof Error ? error.message : 'Job stopped';
              console.log(`[Instant Sync ${jobId}] ${errorMsg}`);
              break;
            }
          }
          
          if (Date.now() - igStreamStartTime > MAX_IG_STREAM_TIME) {
            console.warn(`[Instant Sync ${jobId}] ⚠️ Instagram stream timeout reached`);
            break;
          }
          
          igConversationCount++;
          
          if (!convo.participants?.data) continue;
          
          for (const participant of convo.participants.data) {
            if (participant.id === page.instagramAccountId) continue;
            
            const existing = igParticipantMap.get(participant.id);
            // OPTIMIZATION: String comparison for ISO dates (faster than Date parsing)
            if (!existing || convo.updated_time > existing.updatedTime) {
              igParticipantMap.set(participant.id, {
                updatedTime: convo.updated_time,
                name: participant.name,
                conversationId: convo.id, // Track conversation ID for message fetching
              });
            }
          }
          
          if (igConversationCount % IG_PROCESS_BATCH_SIZE === 0 && igParticipantMap.size > 0) {
            // OPTIMIZATION: Direct iteration instead of Array.from() for better performance
            const batchToProcess: Array<[string, { updatedTime: string; name?: string; conversationId?: string }]> = [];
            batchToProcess.length = igParticipantMap.size; // Pre-allocate
            let batchIndex = 0;
            for (const entry of igParticipantMap.entries()) {
              batchToProcess[batchIndex++] = entry;
            }
            const remainingCount = igParticipantMap.size;
            igParticipantMap.clear();
            
            const batchPromise = batchProcessor.execute(async () => {
              const batchCount = await processContactBatch(batchToProcess, 'Instagram');
              
              // OPTIMIZATION: Batch progress updates - only update every N batches to reduce overhead
              // Progress updates are fire-and-forget and don't block processing
              if (platformBatchPromises.length % 3 === 0) {
                prisma.syncJob.update({
                  where: { id: jobId },
                  data: {
                    syncedContacts: messengerContactsStored + instagramContactsStored + batchCount,
                    totalContacts: messengerContactsStored + instagramContactsStored + batchCount + remainingCount,
                  },
                }).catch(() => {});
              }
              
              return batchCount;
            }).catch(err => {
              // Only log errors in development or if critical
              if (process.env.NODE_ENV === 'development') {
                console.error(`[Instant Sync ${jobId}] Instagram batch error:`, err);
              }
              return 0;
            });
            
            platformBatchPromises.push(batchPromise);
            batchPromises.push(batchPromise);
            lastIgProgressUpdate = Date.now();
          } else if (igConversationCount % IG_PROGRESS_UPDATE_INTERVAL === 0 || Date.now() - lastIgProgressUpdate > 10000) {
            // OPTIMIZATION: Reduced progress update frequency (every 10s instead of 5s)
            // Progress updates are non-blocking but still add overhead
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: messengerContactsStored + instagramContactsStored,
                totalContacts: messengerContactsStored + instagramContactsStored + igParticipantMap.size,
              },
            }).catch(() => {});
            lastIgProgressUpdate = Date.now();
          }
        }
        
        // Wait for all batches and calculate total
        if (platformBatchPromises.length > 0) {
          const results = await Promise.all(platformBatchPromises);
          instagramContactsStored = results.reduce((sum, count) => sum + count, 0);
        }
        
        // Process remaining
        if (igParticipantMap.size > 0) {
          // OPTIMIZATION: Direct iteration instead of Array.from() for better performance
          const remaining: Array<[string, { updatedTime: string; name?: string }]> = [];
          remaining.length = igParticipantMap.size; // Pre-allocate
          let remainingIndex = 0;
          for (const entry of igParticipantMap.entries()) {
            remaining[remainingIndex++] = entry;
          }
          const finalCount = await processContactBatch(remaining, 'Instagram');
          instagramContactsStored += finalCount;
        }
        
        console.log(`[Instant Sync ${jobId}] ✅ Instagram: ${instagramContactsStored} contacts stored`);
        return instagramContactsStored;
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Instagram sync failed:`, error);
        errors.push({
          platform: 'Instagram',
          id: 'conversations',
          error: error instanceof Error ? error.message : 'Failed to fetch conversations',
        });
        return 0;
      }
    };
    
    // OPTIMIZATION: Process Messenger and Instagram in parallel for maximum speed
    // This allows both platforms to sync simultaneously instead of waiting for one to finish
    const [messengerResult, instagramResult] = await Promise.allSettled([
      processMessenger(),
      processInstagram(),
    ]);
    
    // Calculate total contacts stored
    contactsStored = (messengerResult.status === 'fulfilled' ? messengerResult.value : 0) +
                     (instagramResult.status === 'fulfilled' ? instagramResult.value : 0);
    
    // Update final progress
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        syncedContacts: contactsStored,
        totalContacts: contactsStored,
      },
    }).catch(() => {});
    
    console.log(`[Instant Sync ${jobId}] ✅ Total contacts stored: ${contactsStored} (Messenger: ${messengerResult.status === 'fulfilled' ? messengerResult.value : 0}, Instagram: ${instagramResult.status === 'fulfilled' ? instagramResult.value : 0})`);

    // Update last synced time
    await prisma.facebookPage.update({
      where: { id: page.id },
      data: { lastSyncedAt: new Date() },
    });

    // Phase 2: Queue AI analysis as background job
    // OPTIMIZATION: Query all contacts for this page at once (single query) instead of querying back during sync
    // This is much faster than N queries during sync - we only need IDs for AI analysis queuing
    let aiAnalysisQueued = false;
    if (contactsStored > 0) {
      try {
        // OPTIMIZATION: Single query to get all contact IDs for this page (much faster than querying back during sync)
        const allContactIds = await prisma.contact.findMany({
          where: {
            facebookPageId: page.id,
            organizationId: page.organizationId,
          },
          select: { id: true },
          // No need to order or limit - we want all contacts for AI analysis
        });
        
        const contactIdsForAnalysis = allContactIds.map(c => c.id);
        
        if (contactIdsForAnalysis.length > 0) {
          console.log(`[Instant Sync ${jobId}] 🧠 Queuing AI analysis for ${contactIdsForAnalysis.length} contacts...`);
          await startBackgroundAnalysis(
            contactIdsForAnalysis,
            page.organizationId,
            userId
          );
          aiAnalysisQueued = true;
          console.log(`[Instant Sync ${jobId}] ✅ AI analysis queued successfully`);
        }
      } catch (error) {
        console.error(`[Instant Sync ${jobId}] Failed to queue AI analysis:`, error);
        // Don't fail the sync if AI queueing fails
      }
    }

    // Mark sync as completed
    // CRITICAL: Ensure contactsStored is accurate before final update
    const finalContactCount = contactsStored;
    console.log(`[Instant Sync ${jobId}] Final sync summary: contactsStored=${contactsStored}, errors=${errors.length}`);
    
    // Get job to retrieve startedAt for metrics calculation
    const job = await prisma.syncJob.findUnique({
      where: { id: jobId },
      select: { startedAt: true },
    });

    const completedAt = new Date();
    
    // Calculate performance metrics
    const { calculateJobMetrics } = await import('@/lib/jobs/job-metrics');
    const metrics = calculateJobMetrics({
      startedAt: job?.startedAt || null,
      completedAt,
      totalContacts: finalContactCount,
      processedContacts: finalContactCount,
      failedContacts: errors.length,
    });
    
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'COMPLETED',
        syncedContacts: finalContactCount,
        totalContacts: finalContactCount,
        failedContacts: errors.length,
        errors: errors.length > 0 ? errors : Prisma.JsonNull,
        completedAt,
        durationMs: metrics.durationMs,
        contactsPerSecond: metrics.contactsPerSecond,
      },
    });

    // Log metrics
    if (metrics.durationMs) {
      console.log(`[Instant Sync ${jobId}] ⏱️ Duration: ${(metrics.durationMs / 1000).toFixed(1)}s`);
    }
    if (metrics.contactsPerSecond) {
      console.log(`[Instant Sync ${jobId}] 📊 Contacts/sec: ${metrics.contactsPerSecond.toFixed(2)}`);
    }

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
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();
    
    // Use PostgreSQL advisory lock to prevent concurrent job creation for the same page
    // This ensures only one job can be created per page at a time, even with concurrent requests
    const lockId = `sync_job_${facebookPageId}`.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0) % 2147483647;
    
    // Use transaction with advisory lock
    const result = await prisma.$transaction(async (tx) => {
      // Acquire advisory lock (blocks until available)
      await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${lockId})`);
      
      // Check for existing active job (within locked transaction)
      const existingJob = await tx.syncJob.findFirst({
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
          existing: true,
          jobId: existingJob.id,
        };
      }

      // Create a new sync job (within locked transaction to prevent duplicates)
      const syncJob = await tx.syncJob.create({
        data: {
          facebookPageId,
          status: 'PENDING',
        },
      });

      return {
        existing: false,
        jobId: syncJob.id,
        syncJob,
      };
      // Lock is automatically released when transaction commits
    });

    // If existing job found, return early
    if (result.existing) {
      return {
        success: true,
        jobId: result.jobId,
        message: 'Sync already in progress',
        contactsStored: 0,
        aiAnalysisQueued: false,
      };
    }

    const syncJob = result.syncJob!;

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

