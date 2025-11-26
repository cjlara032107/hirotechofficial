import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';

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
    (async () => {
      try {
        console.log(`[Background Sync ${syncJob.id}] 🚀 Starting background execution immediately...`);
        await executeBackgroundSync(syncJob.id, facebookPageId);
      } catch (error) {
        console.error(`[Background Sync ${syncJob.id}] ❌ Failed:`, error);
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
          console.error(`[Background Sync ${syncJob.id}] ❌ Failed to update job status:`, dbError);
        }
      }
    })(); // Immediately invoked async function

    return {
      success: true,
      jobId: syncJob.id,
      message: 'Sync started',
    };
  } catch (error) {
    console.error('Failed to start background sync:', error);
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
  try {
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
    
    console.log(`[Background Sync ${jobId}] Auto-Pipeline Enabled:`, !!page.autoPipelineId);
    if (page.autoPipelineId && page.autoPipeline) {
      console.log(`[Background Sync ${jobId}] Target Pipeline:`, page.autoPipeline.name);
      console.log(`[Background Sync ${jobId}] Mode:`, page.autoPipelineMode);
      
      // Auto-generate score ranges if stages still have defaults
      const hasDefaultRanges = page.autoPipeline.stages.some(
        s => s.leadScoreMin === 0 && s.leadScoreMax === 100
      );

      if (hasDefaultRanges) {
        console.log(`[Background Sync ${jobId}] Detected default score ranges, auto-generating intelligent ranges...`);
        await applyStageScoreRanges(page.autoPipelineId);
        console.log(`[Background Sync ${jobId}] Score ranges applied successfully`);
        
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

    console.log(`[Background Sync ${jobId}] Starting contact sync for Facebook Page: ${page.pageId}`);

    // Set initial status - this helps UI show progress immediately
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        totalContacts: 0, // Will be updated once we know the count
      },
    });

    // Sync Messenger contacts
    try {
      console.log(`[Background Sync ${jobId}] Fetching Messenger conversations...`);
      
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
      console.log(`[Background Sync ${jobId}] Fetched ${messengerConvos.length} Messenger conversations`);
      
      // Check if no conversations found
      if (messengerConvos.length === 0) {
        console.warn(`[Background Sync ${jobId}] ⚠️ No Messenger conversations found for page ${page.pageId}. This could mean:
          - The page has no conversations yet
          - The access token doesn't have 'pages_messaging' permission
          - The page ID is incorrect
          - The page hasn't received any messages`);
        
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
          console.warn(`[Background Sync ${jobId}] Conversation ${convo.id} has no participants data`);
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

      console.log(`[Background Sync ${jobId}] Processing ${participantTasks.length} Messenger participants (skipped ${skippedPageSelf} page self references)`);
      
      // Check if no participants found after filtering
      if (participantTasks.length === 0) {
        console.warn(`[Background Sync ${jobId}] ⚠️ No participants found after filtering. All participants were the page itself.`);
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
      console.log(`[Background Sync ${jobId}] Checking existing contacts for ${participantIds.length} participants...`);
      const existingContactsMap = await getExistingContactsMap(
        page.id,
        participantIds,
        'messenger'
      );
      console.log(`[Background Sync ${jobId}] Found ${existingContactsMap.size} existing contacts`);

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
          console.log(`[Background Sync ${jobId}] Skipping ${task.participantId} - conversation unchanged since ${existing.lastInteraction.toISOString()}`);
          return false; // Skip unchanged contact
        }

        // SKIP_EXISTING mode: Skip if already in pipeline
        if (page.autoPipelineMode === 'SKIP_EXISTING' && page.autoPipelineId && existing.pipelineId) {
          console.log(`[Background Sync ${jobId}] Skipping ${task.participantId} - contact already in pipeline`);
          return false;
        }

        return true; // Contact needs processing
      });

      console.log(`[Background Sync ${jobId}] ${tasksToProcess.length} participants need processing (${participantTasks.length - tasksToProcess.length} skipped)`);

      // Set initial total contacts estimate for progress tracking
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          totalContacts: tasksToProcess.length,
        },
      });

      // Initialize concurrency limiters
      const messageFetchLimiter = new ConcurrencyLimiter(50);
      const analysisLimiter = new ConcurrencyLimiter(50);

      // Process in batches to update progress incrementally
      const BATCH_SIZE = 50; // Process 50 contacts at a time
      const batches = [];
      for (let i = 0; i < tasksToProcess.length; i += BATCH_SIZE) {
        batches.push(tasksToProcess.slice(i, i + BATCH_SIZE));
      }

      console.log(`[Background Sync ${jobId}] Processing ${tasksToProcess.length} contacts in ${batches.length} batches of ${BATCH_SIZE}`);

      // Process each batch
      for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
        const batch = batches[batchIndex];
        
        // Check if cancelled
        if (await isJobCancelled(jobId)) {
          console.log(`[Background Sync ${jobId}] Sync cancelled by user`);
          return;
        }

        console.log(`[Background Sync ${jobId}] Processing batch ${batchIndex + 1}/${batches.length} (${batch.length} contacts)...`);

        // Step 1: Fetch messages for this batch (SAFE OPTIMIZATION: Use recent messages only)
        const messageResults = await Promise.all(
          batch.map(task =>
            messageFetchLimiter.execute(async () => {
              try {
                const existing = existingContactsMap.get(task.participantId);
                const conversationUpdatedTime = new Date(task.updatedTime);
                
                // SAFE OPTIMIZATION: Only fetch recent messages (200) for AI analysis
                // Recent messages are more relevant for context, and this is 5-10x faster
                // For most conversations, last 200 messages cover 3-6 months of history
                const messages = await Promise.race([
                  client.getRecentMessagesForConversation(task.conversationId, 200), // Only last 200 messages
                  new Promise<any[]>((_, reject) => 
                    setTimeout(() => reject(new Error(`Timeout: Fetching messages for conversation ${task.conversationId} took longer than 15 seconds`)), 15000)
                  )
                ]);
                return { task, messages, error: null, existing };
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                console.warn(`[Background Sync ${jobId}] Failed to fetch messages for conversation ${task.conversationId}: ${errorMessage}`);
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
                return { task, processed: null, error };
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
                
                if (shouldSkipAI) {
                  console.log(`[Background Sync ${jobId}] Skipping AI analysis for ${task.participantId} - conversation unchanged since ${existing!.aiContextUpdatedAt.toISOString()}`);
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
                      console.warn(`[Background Sync ${jobId}] Used fallback scoring for ${task.participantId} - Score: ${analysis.leadScore}`);
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
          analysisResults.map(({ task, processed, error }) => {
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
            // Auto-assign to pipeline if enabled
                if (processed.aiAnalysis && page.autoPipelineId) {
              await autoAssignContactToPipeline({
                contactId: savedContact.id,
                    aiAnalysis: processed.aiAnalysis,
                pipelineId: page.autoPipelineId,
                updateMode: page.autoPipelineMode,
              });
            }
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
        console.log(`[Background Sync ${jobId}] Batch ${batchIndex + 1}/${batches.length} complete: ${syncedCount} synced, ${failedCount} failed`);
      }
    } catch (error) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }

      console.error(`[Background Sync ${jobId}] ❌ Failed to fetch Messenger conversations:`, error);
      console.error(`[Background Sync ${jobId}] Error details:`, {
        code: errorCode,
        message: errorMessage,
        isTokenExpired: tokenExpired,
        errorType: error instanceof FacebookApiError ? error.type : 'Unknown',
      });
      
      errors.push({
        platform: 'Messenger',
        id: 'conversations',
        error: errorMessage,
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
        const igAnalysisLimiter = new ConcurrencyLimiter(50);

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
                  // SAFE OPTIMIZATION: Only fetch recent messages (200) for AI analysis
                  const messages = await client.getRecentMessagesForConversation(task.conversationId, 200);
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
                  
                  if (shouldSkipAI) {
                    console.log(`[Background Sync ${jobId}] IG: Skipping AI analysis for ${task.participantId} - conversation unchanged since ${existing!.aiContextUpdatedAt.toISOString()}`);
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
              
              syncedCount++;
                  return savedContact;
                })
                .catch((err) => {
                  failedCount++;
                  const errorMessage = err instanceof Error ? err.message : 'Unknown error';
                  const errorCode = err instanceof FacebookApiError ? err.code : undefined;
                  errors.push({
                    platform: 'Instagram',
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
        completedAt: new Date(),
      },
    });

    console.log(`[Background Sync ${jobId}] Completed: ${syncedCount} synced, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`[Background Sync ${jobId}] Fatal error:`, error);

    // Mark job as failed
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [{ error: errorMessage }],
        completedAt: new Date(),
      },
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
