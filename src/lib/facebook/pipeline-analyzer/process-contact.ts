/**
 * TASK-015: Process Contact Function
 * 
 * Processes a single contact through the analysis pipeline:
 * - Finds conversation for contact
 * - Fetches messages from conversation
 * - Runs AI analysis
 * - Builds update data structure
 * 
 * Returns null on any error (doesn't throw) to allow graceful error handling.
 */

import { FacebookClient, FacebookApiError } from '../client';
import { analyzeContact } from './analyze-contact';
import { analyzeContactQueued, isQueueEnabled } from '@/lib/ai/analyze-contact-queued';
import { jobStatusCache } from './job-status-cache';

export interface ConversationInfo {
  conversationId: string;
  updatedTime: string;
}

export interface Contact {
  id: string;
  messengerPSID?: string | null;
  instagramSID?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  lastInteraction?: Date | null;
}

export interface PipelineStage {
  name: string;
  type: string;
  description?: string | null;
  leadScoreMin?: number;
  leadScoreMax?: number;
}

export interface ProcessContactResult {
  contactId: string;
  aiContext: string;
  aiSummary?: string;
  aiAnalysis: any;
  conversionProbability?: number;
  buyerIntent?: string;
  sentiment?: string;
  productInterests?: string[];
  intentSignals?: any;
  nextBestAction?: string;
  agentSuggestions?: any;
  conversionPath?: string[];
  similarLeadsInsight?: string;
  botAccuracyScore?: number;
  conversationPatterns?: any;
  indirectIntent?: any;
  buyerReliability?: any;
  buyerStyle?: string;
  leadRiskLevel?: string;
  leadRiskReasons?: string[];
}

/**
 * Checks if a job has been cancelled
 * Uses cache to reduce database queries (80-90% reduction)
 */
async function isJobCancelled(jobId: string): Promise<boolean> {
  // Check cache first
  const cachedStatus = await jobStatusCache.getStatus(jobId);
  
  if (cachedStatus !== null) {
    // Cache hit - return immediately without DB query
    return cachedStatus === 'CANCELLED';
  }

  // Cache miss or expired - query database
  const { prisma } = await import('@/lib/db');
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
    select: { status: true },
  });
  
  if (!job) {
    throw new Error('Job not found');
  }
  
  // Update cache with fresh status
  jobStatusCache.setStatus(jobId, job.status);
  
  return job.status === 'CANCELLED';
}

/**
 * Processes a single contact through the analysis pipeline
 * 
 * @param contact - Contact object with required fields
 * @param messengerConversationMap - Map of Messenger PSID to conversation info
 * @param instagramConversationMap - Map of Instagram SID to conversation info
 * @param pipelineStages - Array of pipeline stages for analysis
 * @param jobId - Job ID for logging and cancellation checks
 * @param client - FacebookClient instance for fetching messages
 * @param conversationFetchLimiter - Concurrency limiter for message fetching
 * @param analysisLimiter - Concurrency limiter for AI analysis
 * @returns Update data object or null if processing fails
 */
export async function processContact(
  contact: Contact,
  messengerConversationMap: Map<string, ConversationInfo>,
  instagramConversationMap: Map<string, ConversationInfo>,
  pipelineStages: PipelineStage[],
  jobId: string,
  client: FacebookClient,
  conversationFetchLimiter: { execute: <T>(fn: () => Promise<T>) => Promise<T> },
  analysisLimiter: { execute: <T>(fn: () => Promise<T>) => Promise<T> }
): Promise<ProcessContactResult | null> {
  try {
    // Check for cancellation
    if (await isJobCancelled(jobId)) {
      return null;
    }

    // Step 1: Find conversation ID for this contact (try Messenger first, then Instagram)
    let conversationInfo = contact.messengerPSID 
      ? messengerConversationMap.get(contact.messengerPSID)
      : null;

    if (!conversationInfo && contact.instagramSID) {
      conversationInfo = instagramConversationMap.get(contact.instagramSID);
    }

    if (!conversationInfo) {
      // No conversation found - return null (doesn't throw)
      return null;
    }

    // Step 2: Fetch messages (with timeout)
    // Store conversationId in a const to avoid non-null assertion issues
    const conversationId = conversationInfo.conversationId;
    let messages;
    try {
      messages = await Promise.race([
        conversationFetchLimiter.execute(async () => {
          try {
            return await client.getRecentMessagesForConversation(conversationId, 20);
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const errorCode = error instanceof FacebookApiError ? error.code : undefined;
            throw { message: errorMessage, code: errorCode };
          }
        }),
        // Timeout after 10 seconds
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Message fetch timeout after 10 seconds')), 10000)
        )
      ]);
    } catch (error) {
      // Messages can't be fetched - return null (doesn't throw)
      return null;
    }

    if (!messages || messages.length === 0) {
      // No messages found - return null (doesn't throw)
      return null;
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
      // No valid messages to analyze - return null (doesn't throw)
      return null;
    }

    // Step 4: Analyze with AI
    let analysisResult;
    try {
      // Check cancellation before starting AI analysis
      if (await isJobCancelled(jobId)) {
        return null;
      }

      // Use longer timeout if queue is enabled (queue has 2-minute timeout + processing time)
      // Queue operations can take longer due to waiting in queue
      const queueEnabled = isQueueEnabled();
      const analysisTimeout = queueEnabled ? 180000 : 90000; // 3 minutes with queue, 90s without
      const timeoutMessage = queueEnabled 
        ? 'Analysis timeout after 3 minutes (queue may be busy)' 
        : 'Analysis timeout after 90 seconds';

      analysisResult = await Promise.race([
        analysisLimiter.execute(async () => {
          // Check cancellation inside the analysis limiter
          if (await isJobCancelled(jobId)) {
            throw new Error('Job cancelled during AI analysis');
          }

          // Use queued analysis if enabled, otherwise direct analysis
          // Queue prevents connection pool exhaustion by controlling concurrency
          const result = await analyzeContactQueued(
            messagesToAnalyze,
            pipelineStages,
            contact.lastInteraction || undefined,
            jobId,
            'normal' // Priority: normal for batch processing
          );

          // Check cancellation after AI analysis completes
          if (await isJobCancelled(jobId)) {
            throw new Error('Job cancelled after AI analysis');
          }

          return result;
        }),
        // Dynamic timeout based on queue status
        new Promise<never>((_, reject) => {
          const timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), analysisTimeout);
          // Check cancellation periodically during timeout
          const checkInterval = setInterval(async () => {
            if (await isJobCancelled(jobId)) {
              clearInterval(checkInterval);
              clearTimeout(timeoutId);
              reject(new Error('Job cancelled during AI analysis'));
            }
          }, 1000); // Check every second
          
          // Clean up interval when timeout completes
          setTimeout(() => clearInterval(checkInterval), analysisTimeout);
        })
      ]);
    } catch (error) {
      // If cancelled, return null gracefully
      if (error instanceof Error && error.message.includes('cancelled')) {
        return null;
      }
      // AI analysis failed or timed out - return null (doesn't throw)
      return null;
    }

    if (!analysisResult || !analysisResult.analysis) {
      // AI analysis returned null - return null (doesn't throw)
      return null;
    }

    const { analysis } = analysisResult;

    // Step 5: Build update data structure
    // Store reasoning in aiContext (detailed analysis) and summary in aiSummary (user-friendly)
    // Ensure we use the most detailed text available (prefer summary if it's longer/more detailed)
    const detailedContext = analysis.summary && analysis.summary.length > (analysis.reasoning?.length || 0)
      ? analysis.summary
      : (analysis.reasoning || analysis.summary || 'Analysis pending');

    return {
      contactId: contact.id,
      aiContext: detailedContext,
      aiSummary: analysis.summary || detailedContext,
      aiAnalysis: analysis,
      // Extract fields from enhanced analysis (only if EnhancedAnalysisResult)
      conversionProbability: 'conversionProbability' in analysis ? analysis.conversionProbability : undefined,
      buyerIntent: 'buyerIntent' in analysis ? analysis.buyerIntent : undefined,
      sentiment: 'sentiment' in analysis ? analysis.sentiment : undefined,
      productInterests: 'productInterests' in analysis ? analysis.productInterests : undefined,
      intentSignals: 'intentSignals' in analysis ? analysis.intentSignals : undefined,
      nextBestAction: 'nextBestAction' in analysis ? analysis.nextBestAction : undefined,
      agentSuggestions: 'agentSuggestions' in analysis ? analysis.agentSuggestions : undefined,
      conversionPath: 'conversionPath' in analysis ? analysis.conversionPath : undefined,
      similarLeadsInsight: 'similarLeadsInsight' in analysis ? analysis.similarLeadsInsight : undefined,
      botAccuracyScore: 'botAccuracyScore' in analysis ? analysis.botAccuracyScore : undefined,
      conversationPatterns: 'conversationPatterns' in analysis ? analysis.conversationPatterns : undefined,
      indirectIntent: 'indirectIntent' in analysis ? analysis.indirectIntent : undefined,
      buyerReliability: 'buyerReliability' in analysis ? analysis.buyerReliability : undefined,
      buyerStyle: 'buyerStyle' in analysis ? analysis.buyerStyle : undefined,
      leadRiskLevel: 'leadRiskLevel' in analysis ? analysis.leadRiskLevel : undefined,
      leadRiskReasons: 'leadRiskReasons' in analysis ? analysis.leadRiskReasons : undefined,
    };
  } catch (error) {
    // Handle all error cases gracefully - return null (doesn't throw)
    return null;
  }
}

