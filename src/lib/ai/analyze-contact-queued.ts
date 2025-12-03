/**
 * Queued AI Analysis Wrapper
 * 
 * Provides a queued version of analyzeContact that uses the analysis queue
 * to prevent connection pool exhaustion. Can be enabled/disabled via config.
 */

import { analysisQueue } from './analysis-queue';
import { analyzeContact, type AnalysisResult } from '@/lib/facebook/pipeline-analyzer/analyze-contact';

interface Message {
  from: string;
  text: string;
  timestamp?: Date;
}

interface PipelineStage {
  name: string;
  type: string;
  description?: string | null;
  leadScoreMin?: number;
  leadScoreMax?: number;
}

/**
 * Check if queue is enabled
 */
function isQueueEnabled(): boolean {
  return process.env.USE_ANALYSIS_QUEUE === 'true';
}

/**
 * Analyze contact with optional queuing
 * 
 * If queue is enabled, requests are queued and processed in controlled batches.
 * If queue is disabled, processes immediately (current behavior).
 */
export async function analyzeContactQueued(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  lastInteraction?: Date,
  jobId?: string,
  priority: 'low' | 'normal' | 'high' = 'normal'
): Promise<AnalysisResult | null> {
  if (!messages || messages.length === 0) {
    return null;
  }

  // If queue is disabled, use direct analysis
  if (!isQueueEnabled()) {
    return analyzeContact(messages, pipelineStages, lastInteraction, jobId);
  }

  // Use queue for controlled processing
  try {
    // Add timeout to queue operation (prevent indefinite waiting)
    // Use 3 minutes to match outer timeout in process-contact.ts
    // This accounts for queue wait time + processing time
    const queueTimeout = 180000; // 3 minutes (matches process-contact.ts timeout)
    const result = await Promise.race([
      analysisQueue.enqueue(messages, {
        pipelineStages,
        lastInteraction,
        jobId,
        priority,
      }),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('Queue operation timed out after 3 minutes')), queueTimeout)
      ),
    ]);

    return result;
  } catch (error) {
    // If queue fails (e.g., full, timeout, or shutdown), fall back to direct analysis
    if (jobId) {
      console.warn(`[Analysis Queue ${jobId}] ⚠️ Queue unavailable, falling back to direct analysis:`, 
        error instanceof Error ? error.message : String(error));
    }

    // Fallback to direct analysis
    return analyzeContact(messages, pipelineStages, lastInteraction, jobId);
  }
}

/**
 * Get queue statistics
 */
export function getQueueStats() {
  return analysisQueue.getStats();
}

/**
 * Check if queue is enabled
 */
export { isQueueEnabled };

