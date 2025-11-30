import { prisma } from '@/lib/db';
import { Prisma, LeadStatus } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';
import { withRetry } from '@/lib/db-retry';
import { filterSystemMessages, hasUserMessages } from './message-filtering';
import { progressBatcher } from './pipeline-analyzer/progress-batcher';
import { memoryMonitor } from '@/lib/utils/memory-monitor';
import {
  isJobActive,
  verifyPageExists,
  verifyPipelineExists,
  isTokenExpiredError,
  markJobFailedDueToPageDeletion,
  markJobFailedDueToPipelineDeletion,
  markJobFailedDueToTokenExpiration,
} from './job-safety-checks';

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
      // Handle boundary cases: score 0 matches stages with min <= 0, score 100 matches stages with max >= 100
      if (!proposedStage) {
        proposedStage = pipeline.stages.find(stage => {
          // Handle null/undefined stage properties
          const stageMin = stage.leadScoreMin ?? 0;
          const stageMax = stage.leadScoreMax ?? 100;
          
          // Handle exact boundary scores (0 and 100) and all scores in between
          // Score 0 matches if stageMin <= 0, score 100 matches if stageMax >= 100
          // All other scores match if they fall within the range [stageMin, stageMax]
          const scoreMatches = (leadScore === 0 && stageMin <= 0) ||
                               (leadScore === 100 && stageMax >= 100) ||
                               (leadScore >= stageMin && leadScore <= stageMax);
          
          return scoreMatches &&
                 stage.type !== 'WON' &&
                 stage.type !== 'LOST' &&
                 stage.type !== 'ARCHIVED';
        });
      }

      // Priority 3: Try exact name match from AI recommendation
      if (!proposedStage && aiAnalysis.recommendedStage) {
        proposedStage = pipeline.stages.find(
          s => s.name.toLowerCase() === aiAnalysis.recommendedStage.toLowerCase()
        );
      }

      // Priority 4: Closest match fallback
      if (!proposedStage) {
        if (!pipeline.stages || pipeline.stages.length === 0) {
          console.warn(`[Pipeline Analysis ${jobId}] No stages available in pipeline ${pipelineId}, skipping contact ${item.contactId}`);
          continue;
        }
        
        let closestStage = pipeline.stages[0];
        if (!closestStage) {
          continue;
        }
        
        const stageMin1 = closestStage.leadScoreMin ?? 0;
        const stageMax1 = closestStage.leadScoreMax ?? 100;
        let closestDistance = Math.abs((stageMin1 + stageMax1) / 2 - leadScore);

        for (const stage of pipeline.stages) {
          if (stage.type === 'ARCHIVED') continue;
          // Handle null/undefined stage properties
          const stageMin = stage.leadScoreMin ?? 0;
          const stageMax = stage.leadScoreMax ?? 100;
          const stageMidpoint = (stageMin + stageMax) / 2;
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
        if (pipeline.stages && pipeline.stages.length > 0) {
          proposedStage = pipeline.stages[0];
        } else {
          console.warn(`[Pipeline Analysis ${jobId}] ⚠️ No stages available in pipeline ${pipelineId}, skipping contact ${item.contactId}`);
          continue;
        }
      }

      // Safety check: ensure proposedStage is defined before using it
      if (!proposedStage) {
        console.warn(`[Pipeline Analysis ${jobId}] Could not determine stage for contact ${item.contactId}, skipping`);
        continue;
      }

      // Check downgrade protection
      if (proposedStage && contact.stage) {
        const shouldBlock = shouldPreventDowngrade(
          contact.stage.order,
          proposedStage.order,
          contact.leadScore || 0,
          leadScore, // Use clamped score
          proposedStage.leadScoreMin ?? 0
        );

        if (shouldBlock) {
          continue; // Skip this contact
        }
      }

      assignments.push({
        contactId: item.contactId,
        stageId: proposedStage.id,
        leadScore: leadScore, // Use clamped score
        leadStatus: leadStatus,
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
      { timeout: 120000 } // Increased to 120 seconds (2 minutes) to handle large batches
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
    // Update job status to in progress (with retry)
    await withRetry(() => prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'IN_PROGRESS',
        startedAt: new Date(),
      },
    }));

    const page = await withRetry(() => prisma.facebookPage.findUnique({
      where: { id: facebookPageId },
      include: {
        autoPipeline: {
          include: {
            stages: { orderBy: { order: 'asc' } }
          }
        }
      }
    }));

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

    // Query contacts for this page based on update mode
    // UPDATE_EXISTING: Process ALL contacts (including those already assigned)
    // SKIP_EXISTING: Only process contacts without pipeline (default)
    const whereClause: any = {
      facebookPageId: page.id,
      OR: [
        { messengerPSID: { not: null } },
        { instagramSID: { not: null } },
      ],
    };
    
    // Only filter by pipelineId if mode is SKIP_EXISTING
    if (page.autoPipelineMode === 'SKIP_EXISTING') {
      whereClause.pipelineId = null;
    }
    
    const contactsToAnalyze = await withRetry(() => prisma.contact.findMany({
      where: whereClause,
      select: {
        id: true,
        messengerPSID: true,
        instagramSID: true,
        firstName: true,
        lastName: true,
        lastInteraction: true,
      },
    }));

    const modeDescription = page.autoPipelineMode === 'UPDATE_EXISTING' 
      ? 'all contacts (UPDATE_EXISTING mode)' 
      : 'contacts without pipeline (SKIP_EXISTING mode)';
    console.log(`[Pipeline Analysis ${jobId}] Found ${contactsToAnalyze.length} ${modeDescription}`);
    
    // Log contact statistics for debugging
    const contactsWithMessengerPSID = contactsToAnalyze.filter(c => c.messengerPSID).length;
    const contactsWithInstagramSID = contactsToAnalyze.filter(c => c.instagramSID).length;
    console.log(`[Pipeline Analysis ${jobId}] Contact breakdown: ${contactsWithMessengerPSID} with Messenger PSID, ${contactsWithInstagramSID} with Instagram SID`);

    if (contactsToAnalyze.length === 0) {
      await withRetry(() => prisma.syncJob.update({
        where: { id: jobId },
        data: {
          status: 'COMPLETED',
          syncedContacts: 0,
          failedContacts: 0,
          totalContacts: 0,
          completedAt: new Date(),
        },
      }));
      console.log(`[Pipeline Analysis ${jobId}] No contacts to analyze`);
      return;
    }

    // Update total contacts (with retry)
    await withRetry(() => prisma.syncJob.update({
      where: { id: jobId },
      data: {
        totalContacts: contactsToAnalyze.length,
      },
    }));

    // OPTIMIZED: Fetch conversations incrementally until all needed participants are found
    // This is MUCH faster than fetching ALL conversations - stops early when all contacts are found
    console.log(`[Pipeline Analysis ${jobId}] Fetching conversations to match ${contactsToAnalyze.length} contacts...`);
    
    // Build set of participant IDs we need to find
    const neededParticipantIds = new Set<string>();
    for (const contact of contactsToAnalyze) {
      if (contact.messengerPSID) neededParticipantIds.add(contact.messengerPSID);
      if (contact.instagramSID) neededParticipantIds.add(contact.instagramSID);
    }
    
    console.log(`[Pipeline Analysis ${jobId}] Looking for ${neededParticipantIds.size} unique participants...`);
    
    let messengerConvos: any[] = [];
    try {
      // Use optimized method that stops early when all participants are found
      // This is 10-100x faster for large contact lists (stops after finding all, doesn't fetch thousands)
      messengerConvos = await client.getMessengerConversationsUntilFound(
        page.pageId,
        neededParticipantIds
      );
      console.log(`[Pipeline Analysis ${jobId}] ✅ Fetched ${messengerConvos.length} Messenger conversations`);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      console.error(`[Pipeline Analysis ${jobId}] ⚠️ Error fetching Messenger conversations: ${errorMsg}`);
      console.log(`[Pipeline Analysis ${jobId}] Continuing with ${messengerConvos.length} conversations already fetched`);
      if (messengerConvos.length === 0) {
        console.warn(`[Pipeline Analysis ${jobId}] ⚠️ WARNING: No conversations fetched. Many contacts will fail.`);
      }
    }

    // Create a map of participantId -> conversationId for Messenger
    // Store both conversation ID and updated_time for comparison
    const messengerConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    for (const convo of messengerConvos) {
      // Handle cases where participants might be missing or malformed
      if (!convo.participants || !convo.participants.data || !Array.isArray(convo.participants.data)) {
        console.warn(`[Pipeline Analysis ${jobId}] Conversation ${convo.id} has invalid participants structure`);
        continue;
      }
      
      for (const participant of convo.participants.data) {
        if (participant.id && participant.id !== page.pageId) {
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
    
    console.log(`[Pipeline Analysis ${jobId}] Mapped ${messengerConversationMap.size} unique Messenger participants to conversations`);
    console.log(`[Pipeline Analysis ${jobId}] Fetched ${messengerConvos.length} Messenger conversations total`);
    
    // Diagnostic: Check if we have enough conversations for the contacts
    if (contactsToAnalyze.length > 0 && messengerConversationMap.size < contactsToAnalyze.length * 0.1) {
      console.warn(`[Pipeline Analysis ${jobId}] ⚠️ WARNING: Only ${messengerConversationMap.size} conversations mapped for ${contactsToAnalyze.length} contacts (${((messengerConversationMap.size / contactsToAnalyze.length) * 100).toFixed(1)}% coverage)`);
      console.warn(`[Pipeline Analysis ${jobId}] This suggests conversation fetching may have been incomplete. Many contacts will fail.`);
      console.warn(`[Pipeline Analysis ${jobId}] Debug: Fetched ${messengerConvos.length} conversations, but only ${messengerConversationMap.size} participants matched`);
    }
    
    // Additional diagnostic: Show sample of contacts that will fail
    if (contactsToAnalyze.length > 0 && messengerConversationMap.size < contactsToAnalyze.length) {
      const contactsWithoutConversations = contactsToAnalyze.filter(c => {
        const hasMessenger = c.messengerPSID && messengerConversationMap.has(c.messengerPSID);
        const hasInstagram = c.instagramSID && instagramConversationMap.has(c.instagramSID);
        return !hasMessenger && !hasInstagram;
      });
      console.warn(`[Pipeline Analysis ${jobId}] ⚠️ ${contactsWithoutConversations.length} contacts will fail because their conversations weren't found`);
      if (contactsWithoutConversations.length <= 10) {
        console.warn(`[Pipeline Analysis ${jobId}] Contacts without conversations:`, contactsWithoutConversations.map(c => ({ id: c.id, messengerPSID: c.messengerPSID, instagramSID: c.instagramSID })));
      }
    }
    
    // Fetch Instagram conversations if connected (using optimized method)
    const instagramConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    if (page.instagramAccountId) {
      try {
        console.log(`[Pipeline Analysis ${jobId}] Fetching Instagram conversations...`);
        // Use optimized method that stops early when all participants are found
        const igConvos = await client.getInstagramConversationsUntilFound(
          page.instagramAccountId,
          neededParticipantIds
        );
        console.log(`[Pipeline Analysis ${jobId}] ✅ Successfully fetched ${igConvos.length} Instagram conversations (stopped early when all participants found)`);

        for (const convo of igConvos) {
          // Handle cases where participants might be missing or malformed
          if (!convo.participants || !convo.participants.data || !Array.isArray(convo.participants.data)) {
            console.warn(`[Pipeline Analysis ${jobId}] Instagram conversation ${convo.id} has invalid participants structure`);
            continue;
          }
          
          for (const participant of convo.participants.data) {
            if (participant.id && participant.id !== page.instagramAccountId) {
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
        
        console.log(`[Pipeline Analysis ${jobId}] Mapped ${instagramConversationMap.size} unique Instagram participants to conversations`);
      } catch (error) {
        console.error(`[Pipeline Analysis ${jobId}] Failed to fetch Instagram conversations:`, error);
      }
    }

    // Process all contacts continuously - each contact completes independently
    // OPTIMIZED: Maximum concurrency for fastest processing (fast mode uses fallback scoring, no AI calls)
    // Fast mode processes 200+ contacts/minute with recent messages only
    
    // Start memory monitoring
    memoryMonitor.startMonitoring(
      (stats) => {
        console.warn(`[Pipeline Analysis ${jobId}] ⚠️ High memory usage: ${memoryMonitor.formatStats(stats)}`);
      },
      (stats) => {
        console.error(`[Pipeline Analysis ${jobId}] 🚨 CRITICAL memory usage: ${memoryMonitor.formatStats(stats)}`);
      }
    );
    
    const conversationFetchLimiter = new ConcurrencyLimiter(50); // Increased to 50 for maximum parallel fetching
    const analysisLimiter = new ConcurrencyLimiter(100); // Fast mode is instant, can handle very high concurrency
    
    console.log(`[Pipeline Analysis ${jobId}] Processing ${contactsToAnalyze.length} contacts continuously...`);
    console.log(`[Pipeline Analysis ${jobId}] 💾 Memory monitoring: ${memoryMonitor.formatStats()}`);

    // Batch database updates for efficiency (larger batches for maximum throughput)
    // Fast mode makes analysis instant, so we can process much larger batches
    const BATCH_SIZE = 25; // Increased to 25 for maximum throughput (fast mode is instant)
    const updateQueue: Array<{
      contactId: string;
      aiContext: string;
      aiAnalysis: any;
    }> = [];
    
    // Parallel batch processor (allows 3 batches to run simultaneously for faster throughput)
    // Capture pipeline values to avoid closure issues
    const pipelineId = page.autoPipelineId!;
    const pipelineMode = page.autoPipelineMode;
    const batchProcessorLimiter = new ConcurrencyLimiter(3); // Allow 3 batches in parallel
    const activeBatchPromises: Promise<void>[] = [];
    
    async function processBatchInParallel(batch: Array<{ contactId: string; aiContext: string; aiAnalysis: any }>) {
      // Process batch with concurrency limiter (allows up to 3 batches in parallel)
      const promise = batchProcessorLimiter.execute(async () => {
        try {
          await processBatch(batch, jobId, pipelineId, pipelineMode);
        } catch (error) {
          console.error(`[Pipeline Analysis ${jobId}] Batch processing error:`, error);
        }
      });
      
      // Track active batches
      activeBatchPromises.push(promise);
      
      // Remove from tracking when done
      promise.finally(() => {
        const index = activeBatchPromises.indexOf(promise);
        if (index > -1) {
          activeBatchPromises.splice(index, 1);
        }
      });
      
      return promise;
    }

    // Process all contacts in one continuous flow
    await Promise.all(
      contactsToAnalyze.map(async (contact) => {
        // Check for cancellation and verify page/pipeline still exist periodically
        try {
          const statusCheck = await isJobActive(jobId, 'sync');
          if (!statusCheck.active) {
            console.log(`[Pipeline Analysis ${jobId}] ${statusCheck.reason || 'Job stopped'}`);
            return;
          }
          // Note: Page and pipeline verification would require passing them as parameters
          // For now, we rely on the initial checks and status checks
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : 'Job stopped';
          console.log(`[Pipeline Analysis ${jobId}] ${errorMsg}`);
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
            // FALLBACK: Try to fetch conversation on-demand if not in initial map
            // This handles cases where conversation fetching was incomplete
            try {
              const psid = contact.messengerPSID || contact.instagramSID;
              if (psid) {
                // Try to find conversation by fetching conversations for this specific participant
                // Note: Facebook API doesn't have a direct "get conversation by participant" endpoint
                // So we'll mark as failed but log it for debugging
                failedCount++;
                const platform = contact.messengerPSID ? 'Messenger' : 'Instagram';
                const errorMsg = `Conversation not found in initial fetch for ${platform} PSID: ${psid}`;
                errors.push({
                  platform,
                  id: contact.id,
                  error: errorMsg,
                  code: undefined,
                });
                
                // Log first 20 failures for debugging (to avoid log spam)
                if (failedCount <= 20) {
                  console.warn(`[Pipeline Analysis ${jobId}] ${errorMsg} (Contact: ${contact.firstName} ${contact.lastName || ''})`);
                }
              } else {
                failedCount++;
                errors.push({
                  platform: 'Unknown',
                  id: contact.id,
                  error: 'No PSID or Instagram SID found',
                  code: undefined,
                });
              }
            } catch (fallbackError) {
              failedCount++;
              const errorMsg = `Failed to fetch conversation on-demand: ${fallbackError instanceof Error ? fallbackError.message : 'Unknown error'}`;
              errors.push({
                platform: contact.messengerPSID ? 'Messenger' : 'Instagram',
                id: contact.id,
                error: errorMsg,
                code: undefined,
              });
            }
            return;
          }

          // Step 2: Fetch messages (OPTIMIZED: Use recent messages only - 10x faster)
          // Only need last 30 messages for fallback scoring - much faster than fetching all messages
          const messages = await Promise.race([
            conversationFetchLimiter.execute(async () => {
              try {
                // CRITICAL OPTIMIZATION: Use getRecentMessagesForConversation instead of getAllMessagesForConversation
                // This is 10-50x faster (1 API call vs 1-50 API calls) and sufficient for fallback scoring
                return await client.getRecentMessagesForConversation(conversationInfo!.conversationId, 30);
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                
                // Log API errors for debugging (first 10 only)
                if (failedCount < 10) {
                  console.error(`[Pipeline Analysis ${jobId}] Failed to fetch messages for conversation ${conversationInfo!.conversationId}:`, errorMessage, errorCode ? `(code: ${errorCode})` : '');
                }
                
                throw { message: errorMessage, code: errorCode };
              }
            }),
            // Timeout after 10 seconds (recent messages should be much faster)
            new Promise<never>((_, reject) => 
              setTimeout(() => reject(new Error('Message fetch timeout after 10 seconds')), 10000)
            )
          ]);

          if (!messages || messages.length === 0) {
            failedCount++;
            const errorMsg = `No messages found for conversation ${conversationInfo!.conversationId}`;
            errors.push({
              platform: contact.messengerPSID ? 'Messenger' : 'Instagram',
              id: contact.id,
              error: errorMsg,
              code: undefined,
            });
            
            // Log first 10 failures for debugging
            if (failedCount <= 10) {
              console.warn(`[Pipeline Analysis ${jobId}] ${errorMsg} (Contact: ${contact.firstName} ${contact.lastName || ''})`);
            }
            return;
          }

          // Step 3: Filter out system messages and prepare messages for analysis
          // Handle conversations with only system messages
          if (!hasUserMessages(messages, page.pageId)) {
            failedCount++;
            const errorMsg = `No user messages found (only system messages) - ${messages.length} total messages`;
            errors.push({
              platform: contact.messengerPSID ? 'Messenger' : 'Instagram',
              id: contact.id,
              error: errorMsg,
              code: undefined,
            });
            
            // Log first 10 failures for debugging
            if (failedCount <= 10) {
              console.warn(`[Pipeline Analysis ${jobId}] ${errorMsg} (Contact: ${contact.firstName} ${contact.lastName || ''})`);
            }
            return;
          }

          // Filter system messages and prepare for analysis
          const messagesToAnalyze = filterSystemMessages(messages, page.pageId)
            .map((msg, index) => {
              // Find original message to get timestamp if available
              const originalMsg = messages.find(m => 
                (m.message || '').trim() === msg.text.trim() ||
                (m.from?.id === msg.from) ||
                (m.from?.name === msg.from)
              );
              
              return {
                from: msg.from,
                text: msg.text,
                timestamp: originalMsg?.created_time ? new Date(originalMsg.created_time) : undefined,
              };
            })
            .reverse(); // Oldest first

          if (messagesToAnalyze.length === 0) {
            failedCount++;
            const errorMsg = `No valid messages to analyze after filtering (${messages.length} total messages, all were system messages)`;
            errors.push({
              platform: contact.messengerPSID ? 'Messenger' : 'Instagram',
              id: contact.id,
              error: errorMsg,
              code: undefined,
            });
            
            // Log first 10 failures for debugging
            if (failedCount <= 10) {
              console.warn(`[Pipeline Analysis ${jobId}] ${errorMsg} (Contact: ${contact.firstName} ${contact.lastName || ''})`);
            }
            return;
          }

          // Step 4: Analyze with AI (concurrency limited with timeout)
          // Use fallback scoring directly for maximum speed (100+ contacts/minute)
          // AI analysis is slow (5-10s) and rate-limited, so we skip it for pipeline assignment
          // Fallback scoring is instant (<100ms) and provides good enough scores for pipeline routing
          const { analysis } = await Promise.race([
            analysisLimiter.execute(async () => {
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
            }),
            // Timeout after 2 seconds (fallback scoring should be instant)
            new Promise<never>((_, reject) => 
              setTimeout(() => reject(new Error('Analysis timeout after 2 seconds')), 2000)
            )
          ]);

          // Step 5 & 6: Queue for batch database update (much faster than individual updates)
          updateQueue.push({
            contactId: contact.id,
            aiContext: analysis.summary,
            aiAnalysis: analysis,
          });

          // Process batch when queue reaches BATCH_SIZE (parallel processing for speed)
          if (updateQueue.length >= BATCH_SIZE) {
            const batch = updateQueue.splice(0, BATCH_SIZE);
            // Process batch in parallel (non-blocking, up to 3 at once)
            processBatchInParallel(batch).catch((error) => {
              console.error(`[Pipeline Analysis ${jobId}] Batch processing error:`, error);
            });
          }

          // Increment counter (atomic operation in JavaScript)
          const currentCount = ++analyzedCount;

          // Update progress more frequently (every 3 contacts for small jobs, every 10 for large) - non-blocking fire-and-forget
          const progressInterval = contactsToAnalyze.length <= 50 ? 3 : 10;
          if (currentCount % progressInterval === 0) {
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
          
          // Update progress more frequently (every 3 failures for small jobs, every 10 for large) - non-blocking fire-and-forget
          const progressInterval = contactsToAnalyze.length <= 50 ? 3 : 10;
          if (currentFailedCount % progressInterval === 0) {
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

    // Wait for all active batches to complete
    if (activeBatchPromises.length > 0) {
      console.log(`[Pipeline Analysis ${jobId}] Waiting for ${activeBatchPromises.length} active batches to complete...`);
      await Promise.allSettled(activeBatchPromises);
    }
    
    // Process final queue items
    if (updateQueue.length > 0) {
      console.log(`[Pipeline Analysis ${jobId}] Processing final batch of ${updateQueue.length} contacts...`);
      await processBatch(updateQueue, jobId, pipelineId, pipelineMode);
    }

    // Get job to retrieve startedAt for metrics calculation
    const job = await prisma.syncJob.findUnique({
      where: { id: jobId },
      select: { startedAt: true },
    });

    const completedAt = new Date();
    
    // CRITICAL: Flush all batched progress updates before final job update
    // This ensures all progress updates are written to the database
    try {
      await progressBatcher.flushBatch();
      console.log(`[Pipeline Analysis ${jobId}] ✅ Flushed all batched progress updates`);
    } catch (flushError) {
      console.warn(`[Pipeline Analysis ${jobId}] ⚠️ Error flushing progress updates:`, flushError);
      // Continue with job completion even if flush fails
    }

    // Calculate performance metrics
    const { calculateJobMetrics } = await import('@/lib/jobs/job-metrics');
    const metrics = calculateJobMetrics({
      startedAt: job?.startedAt || null,
      completedAt,
      totalContacts: analyzedCount + failedCount,
      processedContacts: analyzedCount,
      failedContacts: failedCount,
    });

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
        completedAt,
        durationMs: metrics.durationMs,
        contactsPerSecond: metrics.contactsPerSecond,
      },
    });

    // Log metrics
    if (metrics.durationMs) {
      console.log(`[Pipeline Analysis ${jobId}] ⏱️ Duration: ${(metrics.durationMs / 1000).toFixed(1)}s`);
    }
    if (metrics.contactsPerSecond) {
      console.log(`[Pipeline Analysis ${jobId}] 📊 Contacts/sec: ${metrics.contactsPerSecond.toFixed(2)}`);
    }

    console.log(`[Pipeline Analysis ${jobId}] Completed: ${analyzedCount} analyzed, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);
    
    // Log detailed failure breakdown for debugging
    if (failedCount > 0) {
      const errorBreakdown = new Map<string, number>();
      errors.forEach(err => {
        const key = err.error || 'Unknown error';
        errorBreakdown.set(key, (errorBreakdown.get(key) || 0) + 1);
      });
      
      console.log(`[Pipeline Analysis ${jobId}] Failure breakdown:`);
      const sortedErrors = Array.from(errorBreakdown.entries()).sort((a, b) => b[1] - a[1]);
      sortedErrors.slice(0, 10).forEach(([error, count]) => {
        console.log(`[Pipeline Analysis ${jobId}]   - ${error}: ${count} contacts`);
      });
      if (sortedErrors.length > 10) {
        console.log(`[Pipeline Analysis ${jobId}]   ... and ${sortedErrors.length - 10} more error types`);
      }
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`[Pipeline Analysis ${jobId}] Fatal error:`, error);

    // Get job to retrieve startedAt for metrics calculation
    const job = await prisma.syncJob.findUnique({
      where: { id: jobId },
      select: { startedAt: true, totalContacts: true },
    });

    const completedAt = new Date();
    
    // CRITICAL: Flush all batched progress updates before final job update
    try {
      await progressBatcher.flushBatch();
      console.log(`[Pipeline Analysis ${jobId}] ✅ Flushed all batched progress updates (on error)`);
    } catch (flushError) {
      console.warn(`[Pipeline Analysis ${jobId}] ⚠️ Error flushing progress updates:`, flushError);
      // Continue with job failure marking even if flush fails
    }
    
    // Calculate metrics even for failed jobs
    const metrics = calculateJobMetrics({
      startedAt: job?.startedAt || null,
      completedAt,
      totalContacts: job?.totalContacts || 0,
      processedContacts: 0,
      failedContacts: 0,
    });

    // Mark job as failed
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [{ error: errorMessage }],
        completedAt,
        durationMs: metrics.durationMs,
        contactsPerSecond: metrics.contactsPerSecond,
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

