import { analyzeConversation, analyzeConversationWithStageRecommendation, AIContactAnalysis } from './google-ai-service';
import { calculateFallbackScore } from './fallback-scoring';

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

interface EnhancedAnalysisResult {
  analysis: AIContactAnalysis;
  usedFallback: boolean;
  retryCount: number;
}

/**
 * Enhanced AI Analysis with Retry Logic and Fallback Scoring
 * PREVENTS contacts from having 0 lead scores
 */
export async function analyzeWithFallback(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  conversationAge?: Date,
  maxRetries = 3
): Promise<EnhancedAnalysisResult> {
  
  let retryCount = 0;
  let lastError: Error | null = null;

  // Attempt AI analysis with retries
  while (retryCount < maxRetries) {
    try {
      if (pipelineStages && pipelineStages.length > 0) {
        // Full analysis with stage recommendation
        const analysis = await analyzeConversationWithStageRecommendation(
          messages,
          pipelineStages,
          maxRetries - retryCount // Pass remaining retries
        );

        if (analysis) {
          console.log(`[Enhanced Analysis] AI success on attempt ${retryCount + 1}`);
          return {
            analysis,
            usedFallback: false,
            retryCount
          };
        }
      } else {
        // Simple summary only
        const summary = await analyzeConversation(messages, maxRetries - retryCount);
        
        if (summary) {
          // Create basic analysis from summary
          const fallback = calculateFallbackScore(messages, conversationAge);
          console.log(`[Enhanced Analysis] Summary success on attempt ${retryCount + 1}, using fallback scoring`);
          
          return {
            analysis: {
              summary,
              recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
              leadScore: fallback.leadScore,
              leadStatus: fallback.leadStatus,
              confidence: fallback.confidence,
              reasoning: fallback.reasoning
            },
            usedFallback: true,
            retryCount
          };
        }
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      console.warn(`[Enhanced Analysis] Attempt ${retryCount + 1} failed:`, lastError.message);
    }

    retryCount++;
    
    // Reduced backoff: 500ms, 1s, 2s (faster retries)
    if (retryCount < maxRetries) {
      const delayMs = Math.min(Math.pow(2, retryCount) * 500, 2000); // Max 2s delay
      console.log(`[Enhanced Analysis] Retrying in ${delayMs}ms...`);
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  // All retries exhausted - use fallback scoring
  console.warn(`[Enhanced Analysis] All AI attempts failed, using fallback scoring`);
  console.warn(`[Enhanced Analysis] Last error:`, lastError?.message);
  
  const fallback = calculateFallbackScore(messages, conversationAge);
  
  return {
    analysis: {
      summary: `Analyzed ${messages.length} messages. ${fallback.reasoning}`,
      recommendedStage: determineStageByScore(fallback.leadScore, pipelineStages),
      leadScore: fallback.leadScore,
      leadStatus: fallback.leadStatus,
      confidence: fallback.confidence,
      reasoning: fallback.reasoning
    },
    usedFallback: true,
    retryCount
  };
}

/**
 * Determine best stage based on fallback score
 */
function determineStageByScore(
  score: number,
  stages?: PipelineStage[]
): string {
  if (!stages || stages.length === 0) {
    return 'New Lead';
  }

  // Find stage where score falls within range
  const matchingStage = stages.find(stage => {
    const min = stage.leadScoreMin ?? 0;
    const max = stage.leadScoreMax ?? 100;
    return score >= min && score <= max;
  });

  if (matchingStage) {
    return matchingStage.name;
  }

  // Fallback: find closest stage
  let closestStage = stages[0];
  let closestDistance = Math.abs(
    ((stages[0].leadScoreMin ?? 0) + (stages[0].leadScoreMax ?? 100)) / 2 - score
  );

  for (const stage of stages) {
    const min = stage.leadScoreMin ?? 0;
    const max = stage.leadScoreMax ?? 100;
    const midpoint = (min + max) / 2;
    const distance = Math.abs(midpoint - score);

    if (distance < closestDistance) {
      closestDistance = distance;
      closestStage = stage;
    }
  }

  return closestStage.name;
}

/**
 * Batch analyze multiple contacts with rate limiting
 * Useful for re-analyzing failed contacts
 */
export async function batchAnalyzeWithFallback(
  contactsWithMessages: Array<{
    contactId: string;
    messages: Message[];
    conversationAge?: Date;
  }>,
  pipelineStages?: PipelineStage[],
  delayBetweenMs = 1500
): Promise<Map<string, EnhancedAnalysisResult>> {
  
  const results = new Map<string, EnhancedAnalysisResult>();

  console.log(`[Batch Analysis] Processing ${contactsWithMessages.length} contacts...`);

  for (const { contactId, messages, conversationAge } of contactsWithMessages) {
    try {
      const result = await analyzeWithFallback(
        messages,
        pipelineStages,
        conversationAge,
        2 // Fewer retries for batch to avoid long delays
      );

      results.set(contactId, result);

      // Log fallback usage
      if (result.usedFallback) {
        console.warn(`[Batch Analysis] Contact ${contactId}: Used fallback (score: ${result.analysis.leadScore})`);
      } else {
        console.log(`[Batch Analysis] Contact ${contactId}: AI success (score: ${result.analysis.leadScore})`);
      }

      // Reduced rate limiting delay for faster processing
      // Only delay if we have multiple API keys to avoid rate limits
      if (delayBetweenMs > 0) {
        await new Promise(resolve => setTimeout(resolve, Math.min(delayBetweenMs, 500))); // Max 500ms
      }

    } catch (error) {
      console.error(`[Batch Analysis] Failed to analyze contact ${contactId}:`, error);
      
      // Even if error, provide minimum fallback
      const fallback = calculateFallbackScore(messages, conversationAge);
      results.set(contactId, {
        analysis: {
          summary: 'Analysis failed - minimum score assigned',
          recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
          leadScore: fallback.leadScore,
          leadStatus: fallback.leadStatus,
          confidence: 30,
          reasoning: 'Emergency fallback due to repeated failures'
        },
        usedFallback: true,
        retryCount: 0
      });
    }
  }

  const fallbackCount = Array.from(results.values()).filter(r => r.usedFallback).length;
  console.log(`[Batch Analysis] Complete: ${results.size} total, ${fallbackCount} used fallback`);

  return results;
}

