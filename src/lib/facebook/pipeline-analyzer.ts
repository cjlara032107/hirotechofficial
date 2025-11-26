import { prisma } from '@/lib/db';
import { Prisma, LeadStatus } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';

interface PipelineAnalysisResult {
  success: boolean;
  jobId: string;
  message: string;
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
 * Starts a pipeline analysis job that analyzes contacts without pipelines
 */
export async function startPipelineAnalysis(facebookPageId: string): Promise<PipelineAnalysisResult> {
  try {
    // Check if there's already an active analysis job for this page
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
        message: 'Pipeline analysis already in progress',
      };
    }

    // Create a new sync job for analysis
    const syncJob = await prisma.syncJob.create({
      data: {
        facebookPageId,
        status: 'PENDING',
      },
    });

    // Start the analysis process asynchronously (don't await)
    executePipelineAnalysis(syncJob.id, facebookPageId).catch((error) => {
      console.error(`Pipeline analysis failed for job ${syncJob.id}:`, error);
    });

    return {
      success: true,
      jobId: syncJob.id,
      message: 'Pipeline analysis started',
    };
  } catch (error) {
    console.error('Failed to start pipeline analysis:', error);
    throw error;
  }
}

/**
 * Check if job has been cancelled
 */
async function isJobCancelled(jobId: string): Promise<boolean> {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
    select: { status: true },
  });
  return job?.status === 'CANCELLED';
}

/**
 * Process batch of contact updates (bulk database operations for speed)
 */
async function processBatch(
  batch: Array<{ contactId: string; aiContext: string; aiAnalysis: any }>,
  jobId: string,
  pipelineId: string,
  updateMode: string
): Promise<void> {
  try {
    // OPTIMIZATION: Fetch pipeline once (shared across all contacts in batch)
    const pipeline = await prisma.pipeline.findUnique({
      where: { id: pipelineId },
      include: { stages: { orderBy: { order: 'asc' } } }
    });

    if (!pipeline) {
      console.error(`[Pipeline Analysis ${jobId}] Pipeline ${pipelineId} not found`);
      return;
    }

    // OPTIMIZATION: Fetch all contacts in batch at once
    const contactIds = batch.map(item => item.contactId);
    const contacts = await prisma.contact.findMany({
      where: { id: { in: contactIds } },
      select: {
        id: true,
        pipelineId: true,
        stageId: true,
        leadScore: true,
        stage: {
          select: {
            order: true,
            leadScoreMin: true,
            name: true
          }
        }
      }
    });

    const contactMap = new Map(contacts.map(c => [c.id, c]));

    // Filter contacts based on update mode
    const contactsToProcess = batch.filter(item => {
      const contact = contactMap.get(item.contactId);
      if (!contact) return false;
      if (updateMode === 'SKIP_EXISTING' && contact.pipelineId) {
        return false; // Skip already assigned
      }
      return true;
    });

    if (contactsToProcess.length === 0) {
      console.log(`[Pipeline Analysis ${jobId}] All contacts in batch already assigned (SKIP_EXISTING mode)`);
      // Still update AI context
      await prisma.$transaction(
        async (tx) => {
          await Promise.all(
            batch.map(item =>
              tx.contact.update({
                where: { id: item.contactId },
                data: {
                  aiContext: item.aiContext,
                  aiContextUpdatedAt: new Date(),
                },
              })
            )
          );
        },
        { timeout: 30000 }
      );
      return;
    }

    // Import utilities
    const { shouldPreventDowngrade } = await import('@/lib/pipelines/stage-analyzer');

    // Process assignments (calculate stage for each contact)
    const assignments: Array<{
      contactId: string;
      stageId: string;
      leadScore: number;
      leadStatus: LeadStatus;
      fromStageId: string | null;
    }> = [];

    for (const item of contactsToProcess) {
      const contact = contactMap.get(item.contactId);
      if (!contact) continue;

      const aiAnalysis = item.aiAnalysis;
      const leadScore = aiAnalysis.leadScore;
      const leadStatus = aiAnalysis.leadStatus || 'NEW';
      
      // Find best matching stage (inline logic to avoid database query)
      let proposedStage: typeof pipeline.stages[0] | undefined;

      // Priority 1: Status-based routing
      if (leadStatus === 'WON') {
        proposedStage = pipeline.stages.find(s => s.type === 'WON');
      } else if (leadStatus === 'LOST') {
        proposedStage = pipeline.stages.find(s => s.type === 'LOST');
      }

      // Priority 2: Score-based routing (if no status match)
      if (!proposedStage) {
        proposedStage = pipeline.stages.find(stage => 
          leadScore >= stage.leadScoreMin && 
          leadScore <= stage.leadScoreMax &&
          stage.type !== 'WON' &&
          stage.type !== 'LOST' &&
          stage.type !== 'ARCHIVED'
        );
      }

      // Priority 3: Try exact name match from AI recommendation
      if (!proposedStage && aiAnalysis.recommendedStage) {
        proposedStage = pipeline.stages.find(
          s => s.name.toLowerCase() === aiAnalysis.recommendedStage.toLowerCase()
        );
      }

      // Priority 4: Closest match fallback
      if (!proposedStage) {
        let closestStage = pipeline.stages[0];
        let closestDistance = Math.abs((pipeline.stages[0].leadScoreMin + pipeline.stages[0].leadScoreMax) / 2 - leadScore);

        for (const stage of pipeline.stages) {
          if (stage.type === 'ARCHIVED') continue;
          const stageMidpoint = (stage.leadScoreMin + stage.leadScoreMax) / 2;
          const distance = Math.abs(stageMidpoint - leadScore);
          if (distance < closestDistance) {
            closestDistance = distance;
            closestStage = stage;
          }
        }
        proposedStage = closestStage;
      }

      // Final fallback to first stage (should never happen, but safety check)
      if (!proposedStage) {
        proposedStage = pipeline.stages[0];
      }

      // Check downgrade protection
      if (proposedStage && contact.stage) {
        const shouldBlock = shouldPreventDowngrade(
          contact.stage.order,
          proposedStage.order,
          contact.leadScore || 0,
          aiAnalysis.leadScore,
          proposedStage.leadScoreMin
        );

        if (shouldBlock) {
          continue; // Skip this contact
        }
      }

      assignments.push({
        contactId: item.contactId,
        stageId: proposedStage.id,
        leadScore: aiAnalysis.leadScore,
        leadStatus: (aiAnalysis.leadStatus || 'NEW') as LeadStatus,
        fromStageId: contact.stageId,
      });
    }

    // OPTIMIZATION: Batch all updates in a single transaction
    await prisma.$transaction(
      async (tx) => {
        // Update AI context for all contacts
        await Promise.all(
          batch.map(item =>
            tx.contact.update({
              where: { id: item.contactId },
              data: {
                aiContext: item.aiContext,
                aiContextUpdatedAt: new Date(),
              },
            })
          )
        );

        // Update pipeline assignments for contacts that need assignment
        await Promise.all(
          assignments.map(assignment =>
            tx.contact.update({
              where: { id: assignment.contactId },
              data: {
                pipelineId,
                stageId: assignment.stageId,
                stageEnteredAt: new Date(),
                leadScore: assignment.leadScore,
                leadStatus: assignment.leadStatus,
              },
            })
          )
        );

        // Create activity logs in batch
        await Promise.all(
          assignments.map(assignment => {
            const item = batch.find(b => b.contactId === assignment.contactId);
            if (!item) return Promise.resolve();
            
            return tx.contactActivity.create({
              data: {
                contactId: assignment.contactId,
                type: 'STAGE_CHANGED',
                title: 'AI auto-assigned to pipeline',
                description: item.aiAnalysis.reasoning || 'AI analysis',
                toStageId: assignment.stageId,
                fromStageId: assignment.fromStageId || undefined,
                metadata: {
                  confidence: item.aiAnalysis.confidence,
                  aiRecommendation: item.aiAnalysis.recommendedStage,
                  leadScore: assignment.leadScore,
                  leadStatus: assignment.leadStatus
                }
              }
            });
          })
        );
      },
      { timeout: 30000 }
    );

    console.log(`[Pipeline Analysis ${jobId}] Processed batch: ${assignments.length} contacts assigned to pipeline`);
  } catch (error) {
    console.error(`[Pipeline Analysis ${jobId}] Batch processing error:`, error);
    // Fallback: process individually if batch fails
    for (const item of batch) {
      try {
        await prisma.contact.update({
          where: { id: item.contactId },
          data: {
            aiContext: item.aiContext,
            aiContextUpdatedAt: new Date(),
          },
        });
        const { autoAssignContactToPipeline } = await import('@/lib/pipelines/auto-assign');
        await autoAssignContactToPipeline({
          contactId: item.contactId,
          aiAnalysis: item.aiAnalysis,
          pipelineId,
          updateMode: updateMode as any,
        });
      } catch (itemError) {
        console.error(`[Pipeline Analysis ${jobId}] Failed to process contact ${item.contactId}:`, itemError);
      }
    }
  }
}

/**
 * Executes the pipeline analysis - fetches conversations on-demand and analyzes contacts
 */
async function executePipelineAnalysis(jobId: string, facebookPageId: string): Promise<void> {
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

    if (!page.autoPipelineId || !page.autoPipeline) {
      throw new Error('Auto-pipeline not configured for this page');
    }

    const client = new FacebookClient(page.pageAccessToken);
    let analyzedCount = 0;
    let failedCount = 0;
    let tokenExpired = false;
    const errors: Array<{ platform: string; id: string; error: string; code?: number }> = [];

    console.log(`[Pipeline Analysis ${jobId}] Starting analysis for Facebook Page: ${page.pageId}`);
    console.log(`[Pipeline Analysis ${jobId}] Target Pipeline: ${page.autoPipeline.name}`);
    console.log(`[Pipeline Analysis ${jobId}] Mode: ${page.autoPipelineMode}`);

    // Auto-generate score ranges if stages still have defaults
    const hasDefaultRanges = page.autoPipeline.stages.some(
      s => s.leadScoreMin === 0 && s.leadScoreMax === 100
    );

    if (hasDefaultRanges) {
      console.log(`[Pipeline Analysis ${jobId}] Detected default score ranges, auto-generating intelligent ranges...`);
      await applyStageScoreRanges(page.autoPipelineId);
      console.log(`[Pipeline Analysis ${jobId}] Score ranges applied successfully`);
      
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

    // Query contacts without pipelineId for this page
    const contactsWithoutPipeline = await prisma.contact.findMany({
      where: {
        facebookPageId: page.id,
        pipelineId: null,
        OR: [
          { messengerPSID: { not: null } },
          { instagramSID: { not: null } },
        ],
      },
      select: {
        id: true,
        messengerPSID: true,
        instagramSID: true,
        firstName: true,
        lastName: true,
        lastInteraction: true,
      },
    });

    console.log(`[Pipeline Analysis ${jobId}] Found ${contactsWithoutPipeline.length} contacts without pipeline`);

    if (contactsWithoutPipeline.length === 0) {
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          status: 'COMPLETED',
          syncedContacts: 0,
          failedContacts: 0,
          totalContacts: 0,
          completedAt: new Date(),
        },
      });
      console.log(`[Pipeline Analysis ${jobId}] No contacts to analyze`);
      return;
    }

    // Update total contacts
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        totalContacts: contactsWithoutPipeline.length,
      },
    });

    // Fetch all conversations once (to match contacts to conversations)
    console.log(`[Pipeline Analysis ${jobId}] Fetching conversations to match contacts...`);
    const messengerConvos = await client.getMessengerConversations(page.pageId);
    console.log(`[Pipeline Analysis ${jobId}] Fetched ${messengerConvos.length} Messenger conversations`);

    // Create a map of participantId -> conversationId for Messenger
    // Store both conversation ID and updated_time for comparison
    const messengerConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    for (const convo of messengerConvos) {
      for (const participant of convo.participants.data) {
        if (participant.id !== page.pageId) {
          // Use the most recent conversation for each participant
          const existing = messengerConversationMap.get(participant.id);
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            messengerConversationMap.set(participant.id, {
              conversationId: convo.id,
              updatedTime: convo.updated_time,
            });
          }
        }
      }
    }

    // Fetch Instagram conversations if connected
    const instagramConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    if (page.instagramAccountId) {
      try {
        console.log(`[Pipeline Analysis ${jobId}] Fetching Instagram conversations...`);
        const igConvos = await client.getInstagramConversations(page.instagramAccountId);
        console.log(`[Pipeline Analysis ${jobId}] Fetched ${igConvos.length} Instagram conversations`);

        for (const convo of igConvos) {
          for (const participant of convo.participants.data) {
            if (participant.id !== page.instagramAccountId) {
              const existing = instagramConversationMap.get(participant.id);
              if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
                instagramConversationMap.set(participant.id, {
                  conversationId: convo.id,
                  updatedTime: convo.updated_time,
                });
              }
            }
          }
        }
      } catch (error) {
        console.error(`[Pipeline Analysis ${jobId}] Failed to fetch Instagram conversations:`, error);
      }
    }

    // Process all contacts continuously - each contact completes independently
    // CRITICAL: Further reduced concurrency to prevent database pool exhaustion
    // Must leave connections available for cron jobs and other operations
    const conversationFetchLimiter = new ConcurrencyLimiter(10); // Reduced from 20 to 10
    const analysisLimiter = new ConcurrencyLimiter(5); // Reduced from 10 to 5
    
    console.log(`[Pipeline Analysis ${jobId}] Processing ${contactsWithoutPipeline.length} contacts continuously...`);

    // Batch database updates for efficiency (process in smaller batches to leave connections for other operations)
    const BATCH_SIZE = 10; // Reduced from 20 to 10 to leave more connections available
    const updateQueue: Array<{
      contactId: string;
      aiContext: string;
      aiAnalysis: any;
    }> = [];
    
    // Sequential batch processor to prevent multiple batches from running simultaneously
    // Capture pipeline values to avoid closure issues
    const pipelineId = page.autoPipelineId!;
    const pipelineMode = page.autoPipelineMode;
    let batchProcessorPromise: Promise<void> | null = null;
    const pendingBatches: Array<Array<{ contactId: string; aiContext: string; aiAnalysis: any }>> = [];
    
    async function processBatchSequentially() {
      // If already processing, just queue and return (the existing processor will handle it)
      if (batchProcessorPromise) {
        return; // Don't create a new processor, the existing one will process all batches
      }
      
      // Start processing if there are pending batches
      if (pendingBatches.length > 0) {
        batchProcessorPromise = (async () => {
          while (pendingBatches.length > 0) {
            const batch = pendingBatches.shift();
            if (batch) {
              try {
                await processBatch(batch, jobId, pipelineId, pipelineMode);
              } catch (error) {
                console.error(`[Pipeline Analysis ${jobId}] Batch processing error:`, error);
              }
            }
          }
          batchProcessorPromise = null;
        })();
      }
    }

    // Process all contacts in one continuous flow
    await Promise.all(
      contactsWithoutPipeline.map(async (contact) => {
        // Check for cancellation periodically
        if (await isJobCancelled(jobId)) {
          return;
        }

        try {
          // Step 1: Find conversation ID for this contact (try Messenger first, then Instagram)
          let conversationInfo = contact.messengerPSID 
            ? messengerConversationMap.get(contact.messengerPSID)
            : null;

          if (!conversationInfo && contact.instagramSID) {
            conversationInfo = instagramConversationMap.get(contact.instagramSID);
          }

          if (!conversationInfo) {
            failedCount++;
            errors.push({
              platform: 'Messenger',
              id: contact.id,
              error: 'Conversation not found',
              code: undefined,
            });
            return;
          }

          // Step 2: Fetch messages (concurrency limited)
          const messages = await conversationFetchLimiter.execute(async () => {
            try {
              return await client.getAllMessagesForConversation(conversationInfo!.conversationId);
            } catch (error) {
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              const errorCode = error instanceof FacebookApiError ? error.code : undefined;
              throw { message: errorMessage, code: errorCode };
            }
          });

          if (!messages || messages.length === 0) {
            failedCount++;
            errors.push({
              platform: 'Messenger',
              id: contact.id,
              error: 'No messages found',
              code: undefined,
            });
            return;
          }

          // Step 3: Prepare messages for analysis
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

          if (messagesToAnalyze.length === 0) {
            failedCount++;
            errors.push({
              platform: 'Messenger',
              id: contact.id,
              error: 'No valid messages to analyze',
              code: undefined,
            });
            return;
          }

          // Step 4: Analyze with AI (concurrency limited)
          // Use fallback scoring directly for maximum speed (100+ contacts/minute)
          // AI analysis is slow (5-10s) and rate-limited, so we skip it for pipeline assignment
          // Fallback scoring is instant (<100ms) and provides good enough scores for pipeline routing
          const { analysis } = await analysisLimiter.execute(async () => {
            if (!page.autoPipeline) {
              throw new Error('Auto-pipeline not configured');
            }
            
            // FAST MODE: Use fallback scoring only (instant, no AI API calls)
            // This allows processing 100+ contacts per minute
            // AI analysis can be done later in background if needed
            const { calculateFallbackScore } = await import('@/lib/ai/fallback-scoring');
            const fallback = calculateFallbackScore(messagesToAnalyze, contact.lastInteraction || undefined);
            
            // Create analysis object compatible with pipeline assignment
            return {
              analysis: {
                summary: `Contact with ${messagesToAnalyze.length} messages. ${fallback.reasoning}`,
                recommendedStage: page.autoPipeline.stages[0]?.name || 'New Lead',
                leadScore: fallback.leadScore,
                leadStatus: fallback.leadStatus,
                confidence: fallback.confidence,
                reasoning: `Fast mode: ${fallback.reasoning}`
              },
              usedFallback: true,
              retryCount: 0
            };
            
            // UNCOMMENT BELOW TO USE AI ANALYSIS (slower, ~5-10s per contact, rate-limited)
            // return await analyzeWithFallback(
            //   messagesToAnalyze,
            //   page.autoPipeline.stages,
            //   contact.lastInteraction || undefined
            // );
          });

          // Step 5 & 6: Queue for batch database update (much faster than individual updates)
          updateQueue.push({
            contactId: contact.id,
            aiContext: analysis.summary,
            aiAnalysis: analysis,
          });

          // Process batch when queue reaches BATCH_SIZE (sequential processing to prevent pool exhaustion)
          if (updateQueue.length >= BATCH_SIZE) {
            const batch = updateQueue.splice(0, BATCH_SIZE);
            pendingBatches.push(batch);
            // Trigger sequential batch processing (non-blocking)
            processBatchSequentially().catch((error) => {
              console.error(`[Pipeline Analysis ${jobId}] Batch processing error:`, error);
            });
          }

          // Increment counter (atomic operation in JavaScript)
          const currentCount = ++analyzedCount;

          // Update progress more frequently (every 5 contacts) for better visibility - non-blocking fire-and-forget
          if (currentCount % 5 === 0) {
            // Fire-and-forget: don't await, don't block contact processing
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: currentCount,
                failedContacts: failedCount,
              },
            }).catch((error) => {
              // Silently handle errors - progress update failures shouldn't stop processing
              console.error(`[Pipeline Analysis ${jobId}] Failed to update progress:`, error);
            });
          }
        } catch (error: unknown) {
          // Increment failed counter (atomic operation in JavaScript)
          const currentFailedCount = ++failedCount;
          const errorMessage = error instanceof Error ? error.message : (typeof error === 'object' && error !== null && 'message' in error ? String(error.message) : 'Unknown error');
          const errorCode = error instanceof FacebookApiError ? error.code : (typeof error === 'object' && error !== null && 'code' in error ? (typeof error.code === 'number' ? error.code : undefined) : undefined);
          
          errors.push({
            platform: 'Messenger',
            id: contact.id,
            error: errorMessage,
            code: errorCode,
          });
          
          // Update progress more frequently (every 5 failures) - non-blocking fire-and-forget
          if (currentFailedCount % 5 === 0) {
            // Fire-and-forget: don't await, don't block contact processing
            prisma.syncJob.update({
              where: { id: jobId },
              data: {
                syncedContacts: analyzedCount,
                failedContacts: currentFailedCount,
              },
            }).catch((error) => {
              // Silently handle errors - progress update failures shouldn't stop processing
              console.error(`[Pipeline Analysis ${jobId}] Failed to update progress:`, error);
            });
          }
          
          if (error instanceof FacebookApiError && error.isTokenExpired) {
            tokenExpired = true;
          } else if (typeof error === 'object' && error !== null && 'code' in error && error.code === 190) {
            tokenExpired = true;
          }
        }
      })
    );

    // Process remaining items in queue (wait for all pending batches first)
    if (batchProcessorPromise) {
      await batchProcessorPromise;
    }
    
    if (updateQueue.length > 0) {
      console.log(`[Pipeline Analysis ${jobId}] Processing final batch of ${updateQueue.length} contacts...`);
      await processBatch(updateQueue, jobId, pipelineId, pipelineMode);
    }

    // Update job with final results
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: tokenExpired ? 'FAILED' : 'COMPLETED',
        syncedContacts: analyzedCount,
        failedContacts: failedCount,
        totalContacts: analyzedCount + failedCount,
        errors: errors.length > 0 ? errors : Prisma.JsonNull,
        tokenExpired,
        completedAt: new Date(),
      },
    });

    console.log(`[Pipeline Analysis ${jobId}] Completed: ${analyzedCount} analyzed, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`[Pipeline Analysis ${jobId}] Fatal error:`, error);

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
 * Gets the status of a pipeline analysis job
 */
export async function getPipelineAnalysisJobStatus(jobId: string) {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
  });

  if (!job) {
    throw new Error('Analysis job not found');
  }

  return job;
}

/**
 * Gets the latest pipeline analysis job for a Facebook page
 */
export async function getLatestPipelineAnalysisJob(facebookPageId: string) {
  return prisma.syncJob.findFirst({
    where: {
      facebookPageId,
    },
    orderBy: {
      createdAt: 'desc',
    },
  });
}

