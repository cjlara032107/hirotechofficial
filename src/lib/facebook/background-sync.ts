import { prisma, connectPrisma } from '@/lib/db';
import { Prisma, Platform, MessageStatus } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';
import { logger } from '@/lib/utils/logger';
import { autoAssignBestContactTimes } from '@/lib/contacts/compute-contact-times';
import { logJobProgress, logJobFailure, logJobComplete } from '@/lib/logging/job-logger';

interface BackgroundSyncResult {
  success: boolean;
  jobId: string;
  message: string;
}

/**
 * Concurrency limiter utility
 * Limits the number of concurrent operations
 * Properly processes queue to avoid pauses
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
    // Don't start new tasks if we're at the limit or queue is empty
    while (this.running < this.limit && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;

      this.running++;
      
      // Execute task asynchronously (don't await here, let it run in background)
      task.fn()
        .then((result) => {
          task.resolve(result);
        })
        .catch((error) => {
          task.reject(error);
        })
        .finally(() => {
          this.running--;
          // Process next task in queue
          this.process();
        });
    }
  }
}

/**
 * Starts a background sync job that tracks progress in the database
 * This allows syncing to continue even if the user navigates away
 */
export async function startBackgroundSync(facebookPageId: string): Promise<BackgroundSyncResult> {
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
      };
    }

    // Create a new sync job
    const syncJob = await prisma.syncJob.create({
      data: {
        facebookPageId,
        status: 'PENDING',
      },
    });

    // Start the sync process asynchronously (don't await)
    // For Vercel serverless, we need to ensure the promise chain starts before response
    // Use immediate execution with proper error handling
    const backgroundPromise = (async () => {
      try {
        logger.info('Starting background execution immediately', { jobId: syncJob.id, operation: 'background-sync' });
        await executeBackgroundSync(syncJob.id, facebookPageId);
      } catch (error) {
        logger.error('Background sync failed', error as Error, { jobId: syncJob.id, operation: 'background-sync' });
        // Mark job as failed in database
        try {
          await prisma.syncJob.update({
            where: { id: syncJob.id },
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
          logger.error('Failed to update job status', dbError as Error, { jobId: syncJob.id, operation: 'background-sync' });
        }
      }
    })(); // Immediately invoked async function

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
      message: 'Sync started',
    };
  } catch (error) {
    logger.error('Failed to start background sync', error as Error, { operation: 'background-sync' });
    throw error;
  }
}

/**
 * Check if sync job has been cancelled
 */
async function isJobCancelled(jobId: string): Promise<boolean> {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
    select: { status: true },
  });
  return job?.status === 'CANCELLED';
}

/**
 * Batch fetch existing contacts for early skip checks
 * Returns a map of participantId -> contact with pipelineId, lastInteraction, and aiContextUpdatedAt
 */
async function getExistingContactsMap(
  facebookPageId: string,
  participantIds: string[],
  platform: 'messenger' | 'instagram'
): Promise<Map<string, { 
  id: string; 
  pipelineId: string | null;
  lastInteraction: Date | null;
  aiContextUpdatedAt: Date | null;
}>> {
  if (participantIds.length === 0) {
    return new Map();
  }

  const whereClause = platform === 'messenger'
    ? {
        messengerPSID: { in: participantIds },
        facebookPageId,
      }
    : {
        OR: [
          { instagramSID: { in: participantIds }, facebookPageId },
          { messengerPSID: { in: participantIds }, facebookPageId },
        ],
      };

  const contacts = await prisma.contact.findMany({
    where: whereClause,
    select: {
      id: true,
      messengerPSID: true,
      instagramSID: true,
      pipelineId: true,
      lastInteraction: true,
      aiContextUpdatedAt: true,
    },
  });

  const map = new Map<string, { 
    id: string; 
    pipelineId: string | null;
    lastInteraction: Date | null;
    aiContextUpdatedAt: Date | null;
  }>();
  
  for (const contact of contacts) {
    const participantId = platform === 'messenger' 
      ? contact.messengerPSID 
      : contact.instagramSID || contact.messengerPSID;
    
    if (participantId) {
      map.set(participantId, {
        id: contact.id,
        pipelineId: contact.pipelineId,
        lastInteraction: contact.lastInteraction,
        aiContextUpdatedAt: contact.aiContextUpdatedAt,
      });
    }
  }

  return map;
}

/**
 * Executes the actual sync operation and updates the job status
 */
async function executeBackgroundSync(jobId: string, facebookPageId: string): Promise<void> {
  const jobType = 'background-sync';
  const startTime = Date.now();
  
  try {
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();
    
    await logJobProgress(jobType, jobId, 'Sync job started, updating status to IN_PROGRESS', 5, { jobId, facebookPageId }).catch(() => {
      // Silently fail - logging should not break the app
    });
    
    // Update job status to in progress
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'IN_PROGRESS',
        startedAt: new Date(),
      },
    });

    const page = await prisma.facebookPage.findUnique({
      where: { id: facebookPageId },
      include: {
        autoPipeline: {
          include: {
            stages: { orderBy: { order: 'asc' } }
          }
        }
      }
    });

    if (!page) {
      throw new Error('Facebook page not found');
    }

    const client = new FacebookClient(page.pageAccessToken);
    let syncedCount = 0;
    let failedCount = 0;
    
    logger.debug('Auto-Pipeline configuration', { jobId, autoPipelineEnabled: !!page.autoPipelineId, operation: 'background-sync' });
    if (page.autoPipelineId && page.autoPipeline) {
      logger.debug('Target pipeline details', { jobId, pipelineName: page.autoPipeline.name, mode: page.autoPipelineMode, operation: 'background-sync' });
      
      // Auto-generate score ranges if stages still have defaults
      const hasDefaultRanges = page.autoPipeline.stages.some(
        s => s.leadScoreMin === 0 && s.leadScoreMax === 100
      );

      if (hasDefaultRanges) {
        logger.info('Detected default score ranges, auto-generating intelligent ranges', { jobId, pipelineId: page.autoPipelineId, operation: 'background-sync' });
        await applyStageScoreRanges(page.autoPipelineId);
        logger.info('Score ranges applied successfully', { jobId, pipelineId: page.autoPipelineId, operation: 'background-sync' });
        
        // Reload page with updated ranges
        const updatedPage = await prisma.facebookPage.findUnique({
          where: { id: page.id },
          include: {
            autoPipeline: {
              include: {
                stages: { orderBy: { order: 'asc' } }
              }
            }
          }
        });
        
        if (updatedPage?.autoPipeline) {
          page.autoPipeline = updatedPage.autoPipeline;
        }
      }
    }
    let tokenExpired = false;
    const errors: Array<{ platform: string; id: string; error: string; code?: number }> = [];

    logger.info('Starting contact sync for Facebook Page', { jobId, pageId: page.pageId, operation: 'background-sync' });

    // Set initial status - this helps UI show progress immediately
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        totalContacts: 0, // Will be updated once we know the count
      },
    });

    // Sync Messenger contacts
    try {
      logger.debug('Fetching Messenger conversations', { jobId, operation: 'background-sync' });
      
      // Add timeout wrapper to prevent hanging (3 minutes max for initial fetch)
      const fetchWithTimeout = async (): Promise<any[]> => {
        let timeoutId: NodeJS.Timeout;
        const timeoutPromise = new Promise<any[]>((_, reject) => {
          timeoutId = setTimeout(() => {
            reject(new Error('Timeout: Fetching conversations took longer than 3 minutes. The page may have too many conversations or there may be a network issue.'));
          }, 3 * 60 * 1000);
        });
        
        try {
          const result = await Promise.race([
            client.getMessengerConversations(page.pageId),
            timeoutPromise,
          ]);
          clearTimeout(timeoutId!);
          return result;
        } catch (error) {
          clearTimeout(timeoutId!);
          throw error;
        }
      };
      
      // Update status to show we're fetching
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          status: 'IN_PROGRESS',
          syncedContacts: 0,
          totalContacts: 0, // Will be updated once we know the count
        },
      });
      
      const messengerConvos = await fetchWithTimeout();
      logger.info('Fetched Messenger conversations', { jobId, count: messengerConvos.length, operation: 'background-sync' });
      
      // Check if no conversations found
      if (messengerConvos.length === 0) {
        logger.warn('No Messenger conversations found', { 
          jobId, 
          pageId: page.pageId, 
          operation: 'background-sync',
          reason: 'No conversations found - could be no conversations, missing permissions, incorrect page ID, or no messages received'
        });
        
        // Still mark as completed (not failed) since this is a valid state
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            status: 'COMPLETED',
            syncedContacts: 0,
            failedContacts: 0,
            totalContacts: 0,
            completedAt: new Date(),
            errors: Prisma.JsonNull,
          },
        });
        return; // Exit early - no conversations to sync
      }
      
      // Update progress: conversations fetched
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          totalContacts: messengerConvos.length, // Temporary: will be updated with actual participant count
        },
      });

      // Collect all participants from all conversations
      interface ParticipantTask {
        participantId: string;
        conversationId: string;
        updatedTime: string;
      }

      const participantTasks: ParticipantTask[] = [];
      let skippedPageSelf = 0;
      for (const convo of messengerConvos) {
        if (!convo.participants || !convo.participants.data) {
          logger.warn('Conversation has no participants data', { jobId, conversationId: convo.id, operation: 'background-sync' });
          continue;
        }
        for (const participant of convo.participants.data) {
          if (participant.id === page.pageId) {
            skippedPageSelf++;
            continue; // Skip page itself
          }
          participantTasks.push({
            participantId: participant.id,
            conversationId: convo.id,
            updatedTime: convo.updated_time,
          });
        }
      }

      logger.info('Processing Messenger participants', { jobId, participantCount: participantTasks.length, skippedPageSelf, operation: 'background-sync' });
      
      // Check if no participants found after filtering
      if (participantTasks.length === 0) {
        logger.warn('No participants found after filtering', { jobId, reason: 'All participants were the page itself', operation: 'background-sync' });
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            status: 'COMPLETED',
            syncedContacts: 0,
            failedContacts: 0,
            totalContacts: 0,
            completedAt: new Date(),
            errors: Prisma.JsonNull,
          },
        });
        return; // Exit early - no participants to sync
      }

      // Update progress: participants collected
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          totalContacts: participantTasks.length, // Update with participant count
        },
      });

      // Batch fetch existing contacts for early skip checks
      const participantIds = participantTasks.map(t => t.participantId);
      logger.debug('Checking existing contacts', { jobId, participantCount: participantIds.length, operation: 'background-sync' });
      const existingContactsMap = await getExistingContactsMap(
        page.id,
        participantIds,
        'messenger'
      );
      logger.debug('Found existing contacts', { jobId, existingCount: existingContactsMap.size, operation: 'background-sync' });

      // Filter out contacts that should be skipped (incremental sync optimization)
      const tasksToProcess = participantTasks.filter(task => {
        const existing = existingContactsMap.get(task.participantId);
        
        if (!existing) {
          return true; // New contact, must process
        }

        // SAFE OPTIMIZATION: Skip if conversation hasn't been updated since last interaction
        // This prevents re-processing unchanged contacts
        const conversationUpdatedTime = new Date(task.updatedTime);
        if (existing.lastInteraction && conversationUpdatedTime <= existing.lastInteraction) {
          logger.debug('Skipping contact - conversation unchanged', { jobId, participantId: task.participantId, lastInteraction: existing.lastInteraction.toISOString(), operation: 'background-sync' });
          return false; // Skip unchanged contact
        }

        // SKIP_EXISTING mode: Skip if already in pipeline
        if (page.autoPipelineMode === 'SKIP_EXISTING' && page.autoPipelineId && existing.pipelineId) {
          logger.debug('Skipping contact - already in pipeline', { jobId, participantId: task.participantId, operation: 'background-sync' });
          return false;
        }

        return true; // Contact needs processing
      });

      logger.info('Participants processing summary', { jobId, toProcess: tasksToProcess.length, skipped: participantTasks.length - tasksToProcess.length, operation: 'background-sync' });

      // Set initial total contacts estimate for progress tracking
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          totalContacts: tasksToProcess.length,
        },
      });

      // Initialize concurrency limiters
      const messageFetchLimiter = new ConcurrencyLimiter(50);
      const analysisLimiter = new ConcurrencyLimiter(100); // Increased to 100 to maximize parallel processing with 20 API keys

      // Process in batches to update progress incrementally
      const BATCH_SIZE = 50; // Process 50 contacts at a time
      const batches = [];
      for (let i = 0; i < tasksToProcess.length; i += BATCH_SIZE) {
        batches.push(tasksToProcess.slice(i, i + BATCH_SIZE));
      }

      logger.info('Processing contacts in batches', { jobId, totalContacts: tasksToProcess.length, batchCount: batches.length, batchSize: BATCH_SIZE, operation: 'background-sync' });

      // Process each batch
      for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
        const batch = batches[batchIndex];
        
        // Check if cancelled
        if (await isJobCancelled(jobId)) {
          console.log(`[Background Sync ${jobId}] Sync cancelled by user`);
          return;
        }

        logger.debug('Processing batch', { jobId, batchIndex: batchIndex + 1, totalBatches: batches.length, batchSize: batch.length, operation: 'background-sync' });

        // Step 1: Fetch messages for this batch (SAFE OPTIMIZATION: Use recent messages only)
        const messageResults = await Promise.all(
          batch.map(task =>
            messageFetchLimiter.execute(async () => {
              try {
                const existing = existingContactsMap.get(task.participantId);
                const conversationUpdatedTime = new Date(task.updatedTime);
                
                // Fetch ALL messages for the conversation (paginated, up to 50 pages = 5000 messages)
                // This ensures we have complete conversation history for analysis and storage
                const messages = await Promise.race([
                  client.getAllMessagesForConversation(task.conversationId, 50), // Get all messages (paginated)
                  new Promise<any[]>((_, reject) => 
                    setTimeout(() => reject(new Error(`Timeout: Fetching messages for conversation ${task.conversationId} took longer than 60 seconds`)), 60000)
                  )
                ]);
                return { task, messages, error: null, existing };
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                logger.warn('Failed to fetch messages for conversation', { jobId, conversationId: task.conversationId, error: errorMessage, operation: 'background-sync' });
                return { task, messages: null, error: { message: errorMessage, code: errorCode }, existing: undefined };
              }
            })
          )
        );

        // Step 2: Analyze this batch (SAFE OPTIMIZATION: Skip AI if conversation unchanged)
        const analysisResults = await Promise.all(
          messageResults.map(({ task, messages, error, existing }) =>
            analysisLimiter.execute(async () => {
              if (error) {
                return { task, processed: null, error, messages: null };
              }

              if (!messages || messages.length === 0) {
                return {
                  task,
                  processed: {
                    participantId: task.participantId,
                    firstName: `User ${task.participantId.slice(-6)}`,
                    lastName: null,
                    aiContext: null,
                    aiAnalysis: null,
                    lastInteraction: new Date(task.updatedTime),
                    skipAI: false,
                  },
                  error: null,
                  messages: null,
                };
              }

              try {
                // Extract name
                let firstName = `User ${task.participantId.slice(-6)}`;
            let lastName: string | null = null;

                const userMessage = messages.find(
                  (msg: { from?: { id?: string } }) => msg.from?.id === task.participantId
              );

              if (userMessage?.from?.name) {
                const nameParts = userMessage.from.name.trim().split(' ');
                firstName = nameParts[0] || firstName;
                if (nameParts.length > 1) {
                  lastName = nameParts.slice(1).join(' ');
                }
            }

                // SAFE OPTIMIZATION: Skip AI analysis if conversation hasn't changed since last analysis
                // This saves 5-10 seconds per unchanged contact
                const conversationUpdatedTime = new Date(task.updatedTime);
                const shouldSkipAI = existing?.aiContextUpdatedAt && 
                                   conversationUpdatedTime <= existing.aiContextUpdatedAt;
                
                let aiContext: string | null = null;
                let aiAnalysis = null;
                
                if (shouldSkipAI && existing?.aiContextUpdatedAt) {
                  logger.debug('Skipping AI analysis - conversation unchanged', { jobId, participantId: task.participantId, aiContextUpdatedAt: existing.aiContextUpdatedAt.toISOString(), operation: 'background-sync' });
                  // Keep existing AI context, don't re-analyze
                  aiContext = null; // Will be preserved in update if not provided
                  aiAnalysis = null;
                } else {
                  // Analyze with AI
                  const messagesToAnalyze = messages
                    .filter((msg: { message?: string }) => msg.message)
                    .map((msg: { from?: { name?: string; id?: string }; message?: string; created_time?: string }) => ({
                      from: msg.from?.name || msg.from?.id || 'Unknown',
                      text: msg.message || '',
                      timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
                    }))
                    .reverse(); // Oldest first

                  if (messagesToAnalyze.length > 0) {
                    const { analysis, usedFallback } = await analyzeWithFallback(
                        messagesToAnalyze,
                      page.autoPipelineId && page.autoPipeline ? page.autoPipeline.stages : undefined,
                      new Date(task.updatedTime)
                      );
                    
                    aiAnalysis = analysis;
                    aiContext = analysis.summary;
                    
                    if (usedFallback) {
                      logger.warn('Used fallback scoring', { jobId, participantId: task.participantId, leadScore: analysis.leadScore, operation: 'background-sync' });
                    }
                  }
                }

                return {
                  task,
                  processed: {
                    participantId: task.participantId,
                    firstName,
                    lastName,
                    aiContext,
                    aiAnalysis,
                    lastInteraction: new Date(task.updatedTime),
                    skipAI: shouldSkipAI,
                  },
                  error: null,
                  messages,
                };
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                return { task, processed: null, error: { message: errorMessage, code: undefined }, messages: null };
              }
            })
          )
        );

        // Step 3: Save this batch to database
        await Promise.all(
          analysisResults.map(({ task, processed, error, messages }) => {
            if (error) {
              failedCount++;
              errors.push({
                platform: 'Messenger',
                id: task.participantId,
                error: error.message,
                code: error.code,
              });
              if (error.code && error.code === 190) {
                tokenExpired = true;
              }
              return null;
            }

            if (!processed) {
              return null;
            }

            // SAFE OPTIMIZATION: Preserve existing AI context if we skipped analysis
            const updateData: any = {
                  firstName: processed.firstName,
                  lastName: processed.lastName,
                  lastInteraction: processed.lastInteraction,
                hasMessenger: true,
            };
            
            // Only update AI context if we actually analyzed (not skipped)
            if (!processed.skipAI) {
              updateData.aiContext = processed.aiContext;
              updateData.aiContextUpdatedAt = processed.aiContext ? new Date() : null;
            }
            // If skipAI is true, aiContext and aiContextUpdatedAt remain unchanged (preserved)
            
            return prisma.contact
              .upsert({
              where: {
                messengerPSID_facebookPageId: {
                    messengerPSID: task.participantId,
                  facebookPageId: page.id,
                },
              },
              create: {
                  messengerPSID: task.participantId,
                  firstName: processed.firstName,
                  lastName: processed.lastName,
                hasMessenger: true,
                organizationId: page.organizationId,
                facebookPageId: page.id,
                  lastInteraction: processed.lastInteraction,
                  aiContext: processed.aiContext,
                  aiContextUpdatedAt: processed.aiContext ? new Date() : null,
              },
              update: updateData,
              })
              .then(async (savedContact) => {
            // Save messages to database if we have them
            if (messages && messages.length > 0 && !error) {
              try {
                // Find or create conversation
                let conversation = await prisma.conversation.findFirst({
                  where: {
                    contactId: savedContact.id,
                    platform: Platform.MESSENGER,
                  },
                });

                if (!conversation) {
                  conversation = await prisma.conversation.create({
                    data: {
                      contactId: savedContact.id,
                      facebookPageId: page.id,
                      platform: Platform.MESSENGER,
                      status: 'OPEN',
                      lastMessageAt: new Date(task.updatedTime),
                    },
                  });
                }

                // Prepare messages for bulk insert
                const messagesToSave = messages
                  .filter((msg: any) => msg.message && msg.created_time) // Only save messages with content and timestamp
                  .map((msg: any) => {
                    const isFromBusiness = msg.from?.id === page.pageId;
                    const createdAt = new Date(msg.created_time);
                    
                    return {
                      contactId: savedContact.id,
                      conversationId: conversation.id,
                      content: msg.message || '[Media]',
                      platform: Platform.MESSENGER,
                      facebookMessageId: msg.id,
                      isFromBusiness,
                      status: MessageStatus.DELIVERED,
                      createdAt,
                      sentAt: createdAt,
                      deliveredAt: createdAt,
                    };
                  });

                // Save messages in batches to avoid overwhelming the database
                if (messagesToSave.length > 0) {
                  const BATCH_SIZE = 100;
                  let savedCount = 0;
                  
                  // Check which messages already exist (by facebookMessageId) to avoid duplicates
                  const messageIds = messagesToSave
                    .map(m => m.facebookMessageId)
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
                  
                  // Filter out messages that already exist
                  const newMessagesToSave = messagesToSave.filter(
                    msg => !msg.facebookMessageId || !existingIds.has(msg.facebookMessageId)
                  );
                  
                  logger.debug('Filtering messages for saving', { 
                    jobId, 
                    contactId: savedContact.id, 
                    total: messagesToSave.length,
                    existing: existingIds.size,
                    new: newMessagesToSave.length,
                    operation: 'background-sync' 
                  });
                  
                  for (let i = 0; i < newMessagesToSave.length; i += BATCH_SIZE) {
                    const batch = newMessagesToSave.slice(i, i + BATCH_SIZE);
                    try {
                      await prisma.message.createMany({
                        data: batch,
                      });
                      savedCount += batch.length;
                    } catch (batchError) {
                      // If batch fails, try individual inserts
                      logger.warn('Batch insert failed, trying individual inserts', { jobId, contactId: savedContact.id, error: batchError, operation: 'background-sync' });
                      for (const msg of batch) {
                        try {
                          await prisma.message.create({
                            data: msg,
                          });
                          savedCount++;
                        } catch (individualError: any) {
                          // Log but continue - message might already exist
                          logger.warn('Failed to save individual message (may already exist)', { 
                            jobId, 
                            contactId: savedContact.id, 
                            error: individualError?.message,
                            operation: 'background-sync' 
                          });
                        }
                      }
                    }
                  }
                  
                  // Update conversation's lastMessageAt to the most recent message
                  if (savedCount > 0 && messagesToSave.length > 0) {
                    const mostRecentMessage = messagesToSave.reduce((latest, msg) => {
                      return msg.createdAt > latest.createdAt ? msg : latest;
                    });
                    await prisma.conversation.update({
                      where: { id: conversation.id },
                      data: { lastMessageAt: mostRecentMessage.createdAt },
                    });
                  }
                  
                  logger.debug('Saved messages for contact', { jobId, contactId: savedContact.id, messageCount: savedCount, operation: 'background-sync' });
                }
              } catch (msgError) {
                // Log but don't fail the sync if message saving fails
                logger.error('Failed to save messages for contact', { jobId, contactId: savedContact.id, error: msgError, operation: 'background-sync' });
              }
            }

            // Auto-assign to pipeline if enabled
                if (processed.aiAnalysis && page.autoPipelineId) {
              await autoAssignContactToPipeline({
                contactId: savedContact.id,
                    aiAnalysis: processed.aiAnalysis,
                pipelineId: page.autoPipelineId,
                updateMode: page.autoPipelineMode,
              });
            }
            
            // Automatically assign best contact times (non-blocking, runs in background)
            // Uses fallback: compute from messages -> similar contact -> default times
            autoAssignBestContactTimes(savedContact.id, page.organizationId).catch((error) => {
              logger.error('Failed to assign best contact times', { jobId, contactId: savedContact.id, error, operation: 'background-sync' });
            });
            
            syncedCount++;
                return savedContact;
              })
              .catch((err) => {
                failedCount++;
                const errorMessage = err instanceof Error ? err.message : 'Unknown error';
                const errorCode = err instanceof FacebookApiError ? err.code : undefined;
                errors.push({
                  platform: 'Messenger',
                  id: task.participantId,
                  error: errorMessage,
                  code: errorCode,
                });
                if (err instanceof FacebookApiError && err.isTokenExpired) {
                  tokenExpired = true;
                }
                return null;
              });
          })
        );

        // SAFE OPTIMIZATION: Update progress more frequently (every 5 contacts or after batch)
        // This improves perceived performance without affecting actual speed
        const progressUpdateInterval = 5;
        if (syncedCount % progressUpdateInterval === 0 || batchIndex === batches.length - 1) {
          await prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: syncedCount,
              failedContacts: failedCount,
            },
          });
        }
        logger.info('Batch complete', { jobId, batchIndex: batchIndex + 1, totalBatches: batches.length, syncedCount, failedCount, operation: 'background-sync' });
      }
    } catch (error) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }

      logger.error('Failed to fetch Messenger conversations', error as Error, { 
        jobId, 
        errorCode, 
        errorMessage,
        operation: 'background-sync',
        isTokenExpired: tokenExpired,
        errorType: error instanceof FacebookApiError ? error.type : 'Unknown',
      });
      
      // SECURITY: Sanitize error messages to prevent sensitive data exposure
      const { formatSyncError } = await import('@/lib/facebook/error-messages');
      errors.push({
        platform: 'Messenger',
        id: 'conversations',
        error: formatSyncError(error),
        code: errorCode,
      });
      
      // If we failed to fetch conversations and have no contacts, mark as failed
      if (syncedCount === 0 && errors.length > 0) {
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            status: tokenExpired ? 'FAILED' : 'FAILED',
            failedContacts: errors.length,
            syncedContacts: 0,
            totalContacts: 0,
            errors: errors.length > 0 ? errors : Prisma.JsonNull,
            completedAt: new Date(),
          },
        });
        console.error(`[Background Sync ${jobId}] ❌ Sync failed: Could not fetch conversations. Error: ${errorMessage}`);
        return; // Exit early if we can't fetch conversations
      }
    }

    // Sync Instagram contacts (if connected)
    if (page.instagramAccountId) {
      try {
        console.log(`[Background Sync ${jobId}] Fetching Instagram conversations...`);
        const igConvos = await client.getInstagramConversations(page.instagramAccountId);
        console.log(`[Background Sync ${jobId}] Fetched ${igConvos.length} Instagram conversations`);

        // Collect all participants from all conversations
        interface InstagramParticipantTask {
          participantId: string;
          conversationId: string;
          updatedTime: string;
        }

        const igParticipantTasks: InstagramParticipantTask[] = [];
      for (const convo of igConvos) {
          for (const participant of convo.participants.data) {
            if (participant.id === page.instagramAccountId) continue; // Skip page itself
            igParticipantTasks.push({
              participantId: participant.id,
              conversationId: convo.id,
              updatedTime: convo.updated_time,
            });
          }
        }

        console.log(`[Background Sync ${jobId}] Processing ${igParticipantTasks.length} Instagram participants`);

        // Batch fetch existing contacts for early skip checks
        const igParticipantIds = igParticipantTasks.map(t => t.participantId);
        const existingIgContactsMap = await getExistingContactsMap(
          page.id,
          igParticipantIds,
          'instagram'
        );

        // Filter out contacts that should be skipped (incremental sync optimization)
        const igTasksToProcess = igParticipantTasks.filter(task => {
          const existing = existingIgContactsMap.get(task.participantId);
          
          if (!existing) {
            return true; // New contact, must process
          }

          // SAFE OPTIMIZATION: Skip if conversation hasn't been updated since last interaction
          const conversationUpdatedTime = new Date(task.updatedTime);
          if (existing.lastInteraction && conversationUpdatedTime <= existing.lastInteraction) {
            console.log(`[Background Sync ${jobId}] Skipping IG ${task.participantId} - conversation unchanged since ${existing.lastInteraction.toISOString()}`);
            return false; // Skip unchanged contact
          }

          // SKIP_EXISTING mode: Skip if already in pipeline
          if (page.autoPipelineMode === 'SKIP_EXISTING' && page.autoPipelineId && existing.pipelineId) {
            console.log(`[Background Sync ${jobId}] Skipping IG ${task.participantId} - contact already in pipeline`);
            return false;
          }

          return true; // Contact needs processing
        });

        console.log(`[Background Sync ${jobId}] ${igTasksToProcess.length} IG participants need processing (${igParticipantTasks.length - igTasksToProcess.length} skipped)`);

        // Update total contacts to include Instagram participants
        const currentTotal = await prisma.syncJob.findUnique({
          where: { id: jobId },
          select: { totalContacts: true },
        });
        const newTotal = (currentTotal?.totalContacts || 0) + igTasksToProcess.length;
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            totalContacts: newTotal,
          },
        });

        // Initialize concurrency limiters for Instagram
        const igMessageFetchLimiter = new ConcurrencyLimiter(50);
        const igAnalysisLimiter = new ConcurrencyLimiter(100); // Increased to 100 to maximize parallel processing with 20 API keys

        // Process in batches to update progress incrementally
        const IG_BATCH_SIZE = 50; // Process 50 contacts at a time
        const igBatches = [];
        for (let i = 0; i < igTasksToProcess.length; i += IG_BATCH_SIZE) {
          igBatches.push(igTasksToProcess.slice(i, i + IG_BATCH_SIZE));
        }

        console.log(`[Background Sync ${jobId}] Processing ${igTasksToProcess.length} IG contacts in ${igBatches.length} batches of ${IG_BATCH_SIZE}`);

        // Process each batch
        for (let batchIndex = 0; batchIndex < igBatches.length; batchIndex++) {
          const batch = igBatches[batchIndex];
          
          // Check if cancelled
          if (await isJobCancelled(jobId)) {
            console.log(`[Background Sync ${jobId}] Sync cancelled by user`);
            return;
          }

          console.log(`[Background Sync ${jobId}] Processing IG batch ${batchIndex + 1}/${igBatches.length} (${batch.length} contacts)...`);

          // Step 1: Fetch messages for this batch (SAFE OPTIMIZATION: Use recent messages only)
          const igMessageResults = await Promise.all(
            batch.map(task =>
              igMessageFetchLimiter.execute(async () => {
                try {
                  const existing = existingIgContactsMap.get(task.participantId);
                  // Fetch ALL messages for AI analysis (paginated, up to 50 pages = 5000 messages)
                  // This ensures complete conversation history for accurate analysis
                  const messages = await client.getAllMessagesForConversation(task.conversationId, 50);
                  return { task, messages, error: null, existing };
                } catch (error) {
                  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                  const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                  return { task, messages: null, error: { message: errorMessage, code: errorCode }, existing: undefined };
                }
              })
            )
          );

          // Step 2: Analyze this batch (SAFE OPTIMIZATION: Skip AI if conversation unchanged)
          const igAnalysisResults = await Promise.all(
            igMessageResults.map(({ task, messages, error, existing }) =>
              igAnalysisLimiter.execute(async () => {
                if (error) {
                  return { task, processed: null, error };
                }

                if (!messages || messages.length === 0) {
                  return {
                    task,
                    processed: {
                      participantId: task.participantId,
                      firstName: `IG User ${task.participantId.slice(-6)}`,
                      lastName: null,
                      aiContext: null,
                      aiAnalysis: null,
                      lastInteraction: new Date(task.updatedTime),
                      skipAI: false,
                    },
                    error: null,
                  };
                }

                try {
                  // Extract name
                  let firstName = `IG User ${task.participantId.slice(-6)}`;
            let lastName: string | null = null;

                  const userMessage = messages.find(
                    (msg: { from?: { id?: string } }) => msg.from?.id === task.participantId
              );

              if (userMessage?.from?.name) {
                const nameParts = userMessage.from.name.trim().split(' ');
                firstName = nameParts[0] || firstName;
                if (nameParts.length > 1) {
                  lastName = nameParts.slice(1).join(' ');
                }
              } else if (userMessage?.from?.username) {
                firstName = userMessage.from.username;
            }

                  // SAFE OPTIMIZATION: Skip AI analysis if conversation hasn't changed since last analysis
                  const conversationUpdatedTime = new Date(task.updatedTime);
                  const shouldSkipAI = existing?.aiContextUpdatedAt && 
                                     conversationUpdatedTime <= existing.aiContextUpdatedAt;
                  
                  let aiContext: string | null = null;
                  let aiAnalysis = null;
                  
                  if (shouldSkipAI && existing?.aiContextUpdatedAt) {
                    console.log(`[Background Sync ${jobId}] IG: Skipping AI analysis for ${task.participantId} - conversation unchanged since ${existing.aiContextUpdatedAt.toISOString()}`);
                    aiContext = null; // Will be preserved in update if not provided
                    aiAnalysis = null;
                  } else {
                    // Analyze with AI
                    const messagesToAnalyze = messages
                      .filter((msg: { message?: string }) => msg.message)
                      .map((msg: { 
                        from?: { name?: string; username?: string; id?: string }; 
                        message?: string; 
                        created_time?: string 
                      }) => ({
                      from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
                        text: msg.message || '',
                        timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
                    }))
                      .reverse(); // Oldest first

                  if (messagesToAnalyze.length > 0) {
                      const { analysis, usedFallback } = await analyzeWithFallback(
                        messagesToAnalyze,
                      page.autoPipelineId && page.autoPipeline ? page.autoPipeline.stages : undefined,
                        new Date(task.updatedTime)
                      );
                    
                    aiAnalysis = analysis;
                    aiContext = analysis.summary;
                    
                    if (usedFallback) {
                        console.warn(`[Background Sync ${jobId}] IG: Used fallback scoring for ${task.participantId} - Score: ${analysis.leadScore}`);
                      }
                    }
                  }

                  return {
                    task,
                    processed: {
                      participantId: task.participantId,
                      firstName,
                      lastName,
                      aiContext,
                      aiAnalysis,
                      lastInteraction: new Date(task.updatedTime),
                      skipAI: shouldSkipAI,
                    },
                    error: null,
                  };
                } catch (error) {
                  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                  return { task, processed: null, error: { message: errorMessage, code: undefined } };
                  }
              })
            )
          );

          // Step 3: Save this batch to database
          await Promise.all(
            igAnalysisResults.map(({ task, processed, error }) => {
              if (error) {
                failedCount++;
                errors.push({
                  platform: 'Instagram',
                  id: task.participantId,
                  error: error.message,
                  code: error.code,
                });
                if (error.code && error.code === 190) {
                  tokenExpired = true;
                }
                return null;
              }

              if (!processed) {
                return null;
              }

              // Check if contact exists by Instagram ID or Messenger PSID
              return prisma.contact
                .findFirst({
                where: {
                  OR: [
                      { instagramSID: task.participantId, facebookPageId: page.id },
                      { messengerPSID: task.participantId, facebookPageId: page.id },
                  ],
                },
                })
                .then(async (existingContact) => {
              // SAFE OPTIMIZATION: Preserve existing AI context if we skipped analysis
              let savedContact;
              if (existingContact) {
                const updateData: any = {
                      instagramSID: task.participantId,
                      firstName: processed.firstName,
                      lastName: processed.lastName,
                  hasInstagram: true,
                      lastInteraction: processed.lastInteraction,
                };
                
                // Only update AI context if we actually analyzed (not skipped)
                if (!processed.skipAI) {
                  updateData.aiContext = processed.aiContext;
                  updateData.aiContextUpdatedAt = processed.aiContext ? new Date() : null;
                }
                
                savedContact = await prisma.contact.update({
                  where: { id: existingContact.id },
                  data: updateData,
                });
              } else {
                savedContact = await prisma.contact.create({
                  data: {
                        instagramSID: task.participantId,
                        firstName: processed.firstName,
                        lastName: processed.lastName,
                    hasInstagram: true,
                    organizationId: page.organizationId,
                    facebookPageId: page.id,
                        lastInteraction: processed.lastInteraction,
                        aiContext: processed.aiContext,
                        aiContextUpdatedAt: processed.aiContext ? new Date() : null,
                  },
                });
              }
              
              // Auto-assign to pipeline if enabled
                  if (processed.aiAnalysis && page.autoPipelineId) {
                await autoAssignContactToPipeline({
                  contactId: savedContact.id,
                      aiAnalysis: processed.aiAnalysis,
                  pipelineId: page.autoPipelineId,
                  updateMode: page.autoPipelineMode,
                });
              }
              
              // Automatically assign best contact times (non-blocking, runs in background)
              // Uses fallback: compute from messages -> similar contact -> default times
              autoAssignBestContactTimes(savedContact.id, page.organizationId).catch((error) => {
                console.error(`[Background Sync ${jobId}] Failed to assign best contact times for IG contact ${savedContact.id}:`, error);
              });
              
              syncedCount++;
                  return savedContact;
                })
                .catch(async (err) => {
                  failedCount++;
                  // SECURITY: Sanitize error messages to prevent sensitive data exposure
                  const { formatSyncError } = await import('@/lib/facebook/error-messages');
                  const errorCode = err instanceof FacebookApiError ? err.code : undefined;
                  errors.push({
                    platform: 'Instagram',
                    id: task.participantId,
                    error: formatSyncError(err),
                    code: errorCode,
                  });
                  if (err instanceof FacebookApiError && err.isTokenExpired) {
                    tokenExpired = true;
                  }
                  return null;
                });
            })
          );

          // SAFE OPTIMIZATION: Update progress more frequently
          const progressUpdateInterval = 5;
          if (syncedCount % progressUpdateInterval === 0 || batchIndex === igBatches.length - 1) {
            await prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: syncedCount,
                failedContacts: failedCount,
              },
            });
          }
          console.log(`[Background Sync ${jobId}] IG Batch ${batchIndex + 1}/${igBatches.length} complete: ${syncedCount} synced, ${failedCount} failed`);
      }
    } catch (error) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }

      console.error(`[Background Sync ${jobId}] Failed to fetch Instagram conversations:`, error);
      errors.push({
        platform: 'Instagram',
        id: 'conversations',
        error: errorMessage,
        code: errorCode,
      });
    }
  }

    // Update last synced time if successful
    if (syncedCount > 0 || !tokenExpired) {
      await prisma.facebookPage.update({
        where: { id: page.id },
        data: { lastSyncedAt: new Date() },
      });
    }

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
      totalContacts: syncedCount + failedCount,
      processedContacts: syncedCount,
      failedContacts: failedCount,
    });

    // Update job with final results
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: tokenExpired ? 'FAILED' : 'COMPLETED',
        syncedContacts: syncedCount,
        failedContacts: failedCount,
        totalContacts: syncedCount + failedCount,
        errors: errors.length > 0 ? errors : Prisma.JsonNull,
        tokenExpired,
        completedAt,
        durationMs: metrics.durationMs,
        contactsPerSecond: metrics.contactsPerSecond,
      },
    });

    // Log metrics
    if (metrics.durationMs) {
      console.log(`[Background Sync ${jobId}] ⏱️ Duration: ${(metrics.durationMs / 1000).toFixed(1)}s`);
    }
    if (metrics.contactsPerSecond) {
      console.log(`[Background Sync ${jobId}] 📊 Contacts/sec: ${metrics.contactsPerSecond.toFixed(2)}`);
    }
    
    // Log job completion
    const duration = Date.now() - startTime;
    if (tokenExpired) {
      await logJobFailure(jobType, jobId, 'Sync job failed due to token expiration', new Error('Token expired'), { syncedCount, failedCount, errors }).catch(() => {
        // Silently fail - logging should not break the app
      });
    } else {
      await logJobComplete(jobType, jobId, `Sync completed: ${syncedCount} synced, ${failedCount} failed`, duration, { syncedCount, failedCount, totalContacts: syncedCount + failedCount, errors: errors.length > 0 ? errors : undefined }).catch(() => {
        // Silently fail - logging should not break the app
      });
    }

    console.log(`[Background Sync ${jobId}] Completed: ${syncedCount} synced, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);
  } catch (error) {
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    const { formatSyncError } = await import('@/lib/facebook/error-messages');
    console.error(`[Background Sync ${jobId}] Fatal error:`, error);

    // Get job to retrieve startedAt for metrics calculation
    const job = await prisma.syncJob.findUnique({
      where: { id: jobId },
      select: { startedAt: true, totalContacts: true },
    });

    const completedAt = new Date();
    
    // Calculate metrics even for failed jobs
    const { calculateJobMetrics } = await import('@/lib/jobs/job-metrics');
    const metrics = calculateJobMetrics({
      startedAt: job?.startedAt || null,
      completedAt,
      totalContacts: job?.totalContacts || 0,
      processedContacts: 0,
      failedContacts: 0,
    });

    // Mark job as failed
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [{ error: formatSyncError(error) }],
        completedAt,
        durationMs: metrics.durationMs,
        contactsPerSecond: metrics.contactsPerSecond,
      },
    });
    
    // Log job failure
    const duration = Date.now() - startTime;
    await logJobFailure(jobType, jobId, `Sync job failed: ${formatSyncError(error)}`, error as Error, { duration }).catch(() => {
      // Silently fail - logging should not break the app
    });
  }
}

/**
 * Gets the status of a sync job
 */
export async function getSyncJobStatus(jobId: string) {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
  });

  if (!job) {
    throw new Error('Sync job not found');
  }

  return job;
}

/**
 * Gets the latest sync job for a Facebook page
 */
export async function getLatestSyncJob(facebookPageId: string) {
  return prisma.syncJob.findFirst({
    where: {
      facebookPageId,
    },
    orderBy: {
      createdAt: 'desc',
    },
  });
}
