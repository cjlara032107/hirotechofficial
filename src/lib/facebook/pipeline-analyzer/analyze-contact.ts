/**
 * Analyzes a contact's conversation using AI analysis methods with fallback
 * 
 * Tries edge function first (if enabled), then local fast analysis, then enhanced analysis.
 * Returns null if all methods fail (doesn't throw).
 */

import type { FastDetailedAnalysis } from '@/lib/ai/fast-detailed-analysis';
import type { EnhancedAnalysisResult } from '@/lib/ai/enhanced-analysis-v2';
import { analyzeContactViaEdgeFunction, isEdgeFunctionEnabled } from '@/lib/ai/edge-function-client';

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

export interface AnalysisResult {
  analysis: FastDetailedAnalysis | EnhancedAnalysisResult;
  usedFallback: boolean;
  retryCount: number;
}

/**
 * Analyzes a contact's conversation with fast analysis first, then enhanced analysis fallback
 * 
 * @param messages - Array of messages to analyze
 * @param pipelineStages - Optional pipeline stages for stage recommendation
 * @param lastInteraction - Optional last interaction date
 * @param jobId - Job ID for logging purposes
 * @returns Analysis result with metadata, or null if all methods fail
 */
export async function analyzeContact(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  lastInteraction?: Date,
  jobId?: string
): Promise<AnalysisResult | null> {
  if (!messages || messages.length === 0) {
    return null;
  }

  // Try edge function first (if enabled) - reduces connection pool pressure
  if (isEdgeFunctionEnabled()) {
    try {
      const edgeResult = await analyzeContactViaEdgeFunction(
        messages,
        pipelineStages,
        lastInteraction,
        jobId,
        true // Use fast analysis
      );

      if (edgeResult && edgeResult.analysis) {
        if (jobId) {
          console.log(`[Pipeline Analysis ${jobId}] ✅ Analysis successful via edge function`);
        }
        return {
          analysis: edgeResult.analysis,
          usedFallback: edgeResult.usedFallback,
          retryCount: 0,
        };
      }
    } catch (edgeError) {
      if (jobId) {
        console.warn(`[Pipeline Analysis ${jobId}] ⚠️ Edge function failed, falling back to local analysis:`, 
          edgeError instanceof Error ? edgeError.message : String(edgeError));
      }
      // Continue to local analysis fallback
    }
  }

  // Fallback to local analysis
  try {
    // Try fast analysis first
    const { analyzeConversationFast } = await import('@/lib/ai/fast-detailed-analysis');
    const fastResult = await analyzeConversationFast(
      messages,
      pipelineStages,
      lastInteraction
    );

    if (fastResult && fastResult.summary) {
      const summaryLength = fastResult.summary.length;
      // Accept summaries >= 200 chars (was strict > 200)
      if (summaryLength >= 200) {
        if (jobId) {
          console.log(`[Pipeline Analysis ${jobId}] ✅ Fast AI analysis successful (${summaryLength} chars, score: ${fastResult.leadScore}, stage: ${fastResult.recommendedStage})`);
        }
        return {
          analysis: fastResult,
          usedFallback: false,
          retryCount: 0
        };
      } else {
        if (jobId) {
          console.warn(`[Pipeline Analysis ${jobId}] ⚠️ Fast AI analysis too short (${summaryLength} chars), trying enhanced analysis`);
        }
      }
    } else {
      if (jobId) {
        console.warn(`[Pipeline Analysis ${jobId}] ⚠️ Fast AI analysis returned null, trying enhanced analysis`);
      }
    }
  } catch (fastError) {
    if (jobId) {
      const errorMsg = fastError instanceof Error ? fastError.message : String(fastError);
      const errorStack = fastError instanceof Error ? fastError.stack : undefined;
      console.error(`[Pipeline Analysis ${jobId}] ❌ Fast AI analysis failed: ${errorMsg}`, errorStack ? `\nStack: ${errorStack.substring(0, 500)}` : '');
    }
  }

  // Fallback to enhanced analysis
  try {
    if (jobId) {
      console.log(`[Pipeline Analysis ${jobId}] 🔄 Trying enhanced analysis fallback...`);
    }
    const { analyzeConversationEnhanced } = await import('@/lib/ai/enhanced-analysis-v2');
    const enhancedResult = await analyzeConversationEnhanced(
      messages,
      pipelineStages,
      lastInteraction
    );

    if (enhancedResult) {
      if (jobId) {
        console.log(`[Pipeline Analysis ${jobId}] ✅ Enhanced analysis successful: intent=${enhancedResult.buyerIntent}, sentiment=${enhancedResult.sentiment}, conversion=${enhancedResult.conversionProbability}%`);
      }
      return {
        analysis: enhancedResult,
        usedFallback: true, // Enhanced analysis IS the fallback method
        retryCount: 0
      };
    } else {
      if (jobId) {
        console.warn(`[Pipeline Analysis ${jobId}] ⚠️ Enhanced analysis returned null`);
      }
    }
  } catch (enhancedError) {
    const errorMsg = enhancedError instanceof Error ? enhancedError.message : String(enhancedError);
    const errorStack = enhancedError instanceof Error ? enhancedError.stack : undefined;
    if (jobId) {
      console.error(`[Pipeline Analysis ${jobId}] ❌ Enhanced analysis failed: ${errorMsg}`);
      if (errorStack) {
        console.error(`[Pipeline Analysis ${jobId}] Enhanced analysis stack:`, errorStack.split('\n').slice(0, 5).join('\n'));
      }
    }
  }

  // All methods failed - return null (don't throw)
  if (jobId) {
    console.error(`[Pipeline Analysis ${jobId}] ⚠️ All analysis methods failed, returning null`);
  }
  return null;
}

