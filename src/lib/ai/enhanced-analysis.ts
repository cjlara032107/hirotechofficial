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
 * NEVER THROWS - always returns a result with fallback scoring
 * 
 * Production-ready with:
 * - Input validation and sanitization
 * - Memory optimization for large message arrays
 * - Timeout protection
 * - Comprehensive error handling
 */
export async function analyzeWithFallback(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  conversationAge?: Date,
  maxRetries = 3,
  returnComprehensive = true, // Request comprehensive format by default
  timeoutMs = 30000 // 30 second timeout for AI analysis
): Promise<EnhancedAnalysisResult> {
  const analysisId = `analysis-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  
  // Wrap entire function in try-catch to ensure it never throws
  try {
    // Validate and sanitize inputs
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      console.warn(`[Enhanced Analysis ${analysisId}] No messages provided, using fallback`);
      const fallback = calculateFallbackScore([], conversationAge);
      return {
        analysis: {
          summary: `No messages to analyze. ${fallback.reasoning}`,
          recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
          leadScore: fallback.leadScore,
          leadStatus: fallback.leadStatus,
          confidence: fallback.confidence,
          reasoning: fallback.reasoning
        },
        usedFallback: true,
        retryCount: 0
      };
    }

    // Validate message content and filter invalid messages
    const validMessages = messages.filter(msg => {
      if (!msg || typeof msg !== 'object') return false;
      if (typeof msg.text !== 'string' || msg.text.trim().length === 0) return false;
      if (typeof msg.from !== 'string' || msg.from.trim().length === 0) return false;
      return true;
    });

    if (validMessages.length === 0) {
      console.warn(`[Enhanced Analysis ${analysisId}] All ${messages.length} messages invalid, using fallback`);
      const fallback = calculateFallbackScore([], conversationAge);
      return {
        analysis: {
          summary: `${messages.length} invalid messages filtered out. ${fallback.reasoning}`,
          recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
          leadScore: fallback.leadScore,
          leadStatus: fallback.leadStatus,
          confidence: fallback.confidence,
          reasoning: fallback.reasoning
        },
        usedFallback: true,
        retryCount: 0
      };
    }

    if (validMessages.length < messages.length) {
      console.warn(`[Enhanced Analysis ${analysisId}] Filtered out ${messages.length - validMessages.length} invalid messages`);
    }

    // Memory optimization: limit message array size for very large conversations
    const MAX_MESSAGES_FOR_ANALYSIS = 500;
    const messagesToAnalyze = validMessages.length > MAX_MESSAGES_FOR_ANALYSIS
      ? [...validMessages.slice(0, 100), ...validMessages.slice(-400)] // Keep first 100 and last 400
      : validMessages;

    if (messagesToAnalyze.length < validMessages.length) {
      console.warn(`[Enhanced Analysis ${analysisId}] Truncated ${validMessages.length} messages to ${messagesToAnalyze.length} for performance`);
    }

    // Validate maxRetries is reasonable
    const safeMaxRetries = Math.max(1, Math.min(maxRetries, 5)); // Between 1 and 5
    if (safeMaxRetries !== maxRetries) {
      console.warn(`[Enhanced Analysis ${analysisId}] Adjusted maxRetries from ${maxRetries} to ${safeMaxRetries}`);
    }

    let retryCount = 0;
    let lastError: Error | null = null;
    const errorLog: Array<{ attempt: number; error: string; stack?: string }> = [];

    // Log analysis start with detailed context
    const analysisStartTime = Date.now();
    console.log(`[Enhanced Analysis ${analysisId}] ============================================`);
    console.log(`[Enhanced Analysis ${analysisId}] Starting analysis`);
    console.log(`[Enhanced Analysis ${analysisId}] - Messages: ${messagesToAnalyze.length} (original: ${messages.length}, filtered: ${validMessages.length})`);
    console.log(`[Enhanced Analysis ${analysisId}] - Pipeline stages: ${pipelineStages?.length || 0}`);
    console.log(`[Enhanced Analysis ${analysisId}] - Max retries: ${safeMaxRetries}`);
    console.log(`[Enhanced Analysis ${analysisId}] - Timeout: ${timeoutMs}ms`);
    console.log(`[Enhanced Analysis ${analysisId}] - Conversation age: ${conversationAge ? new Date(conversationAge).toISOString() : 'N/A'}`);
    console.log(`[Enhanced Analysis ${analysisId}] ============================================`);

    // Attempt AI analysis with retries
    while (retryCount < safeMaxRetries) {
      try {
        if (pipelineStages && pipelineStages.length > 0) {
          // Full analysis with stage recommendation
          console.log(`[Enhanced Analysis ${analysisId}] Attempt ${retryCount + 1}/${safeMaxRetries}: Full analysis with stage recommendation`);
          
          // Add timeout protection
          const analysisPromise = analyzeConversationWithStageRecommendation(
            messagesToAnalyze,
            pipelineStages,
            safeMaxRetries - retryCount // Pass remaining retries
          );
          
          const timeoutPromise = new Promise<null>((_, reject) =>
            setTimeout(() => reject(new Error(`Analysis timeout after ${timeoutMs}ms`)), timeoutMs)
          );
          
          const analysis = await Promise.race([analysisPromise, timeoutPromise]);

          if (analysis) {
            const analysisDuration = Date.now() - analysisStartTime;
            console.log(`[Enhanced Analysis ${analysisId}] ============================================`);
            console.log(`[Enhanced Analysis ${analysisId}] ✅ AI ANALYSIS SUCCESS on attempt ${retryCount + 1}`);
            console.log(`[Enhanced Analysis ${analysisId}] - Duration: ${analysisDuration}ms`);
            console.log(`[Enhanced Analysis ${analysisId}] - Lead Score: ${analysis.leadScore}/100`);
            console.log(`[Enhanced Analysis ${analysisId}] - Recommended Stage: ${analysis.recommendedStage}`);
            console.log(`[Enhanced Analysis ${analysisId}] - Lead Status: ${analysis.leadStatus}`);
            console.log(`[Enhanced Analysis ${analysisId}] - Confidence: ${analysis.confidence}%`);
            console.log(`[Enhanced Analysis ${analysisId}] - Used Fallback: false`);
            console.log(`[Enhanced Analysis ${analysisId}] ============================================`);
            return {
              analysis,
              usedFallback: false,
              retryCount
            };
          } else {
            console.warn(`[Enhanced Analysis ${analysisId}] ⚠️ Attempt ${retryCount + 1} returned null, will retry`);
            console.warn(`[Enhanced Analysis ${analysisId}] - This usually indicates API response parsing issue`);
          }
        } else {
          // Simple summary only - but request comprehensive format if requested
          console.log(`[Enhanced Analysis ${analysisId}] Attempt ${retryCount + 1}/${safeMaxRetries}: ${returnComprehensive ? 'Comprehensive' : 'Simple'} summary analysis`);
          
          // Add timeout protection
          const summaryPromise = analyzeConversation(
            messagesToAnalyze, 
            safeMaxRetries - retryCount,
            undefined, // context
            returnComprehensive // Request comprehensive format
          );
          
          const timeoutPromise = new Promise<null>((_, reject) =>
            setTimeout(() => reject(new Error(`Analysis timeout after ${timeoutMs}ms`)), timeoutMs)
          );
          
          const summaryResult = await Promise.race([summaryPromise, timeoutPromise]);
          
          if (summaryResult) {
            // Handle both string and AnalyzeConversationResult types
            let summary: string;
            let comprehensiveAnalysis: any = null;
            
            if (typeof summaryResult === 'string') {
              summary = summaryResult;
            } else if (summaryResult.summary) {
              summary = summaryResult.summary;
              comprehensiveAnalysis = summaryResult.comprehensiveAnalysis;
            } else {
              summary = JSON.stringify(summaryResult);
            }
            
            // If we got comprehensive analysis, use it
            if (comprehensiveAnalysis) {
              console.log(`[Enhanced Analysis ${analysisId}] ✅ Comprehensive analysis received on attempt ${retryCount + 1}`);
              return {
                analysis: {
                  summary: comprehensiveAnalysis.executiveSummary || summary,
                  recommendedStage: comprehensiveAnalysis.pipelineRecommendation?.recommendedStage || pipelineStages?.[0]?.name || 'New Lead',
                  leadScore: comprehensiveAnalysis.scoring?.leadScore ?? 50,
                  leadStatus: comprehensiveAnalysis.pipelineRecommendation?.leadStatus || 'NEW',
                  confidence: comprehensiveAnalysis.scoring?.confidence ?? 80,
                  reasoning: comprehensiveAnalysis.reasoning || '',
                  // Include all comprehensive fields
                  executiveSummary: comprehensiveAnalysis.executiveSummary,
                  conversationAnalysis: comprehensiveAnalysis.conversationAnalysis,
                  customerInsights: comprehensiveAnalysis.customerInsights,
                  engagementMetrics: comprehensiveAnalysis.engagementMetrics,
                  businessIntelligence: comprehensiveAnalysis.businessIntelligence,
                  actionItems: comprehensiveAnalysis.actionItems,
                  greenFlags: comprehensiveAnalysis.greenFlags,
                  redFlags: comprehensiveAnalysis.redFlags,
                  upsellOpportunities: comprehensiveAnalysis.upsellOpportunities,
                  conversationTips: comprehensiveAnalysis.conversationTips,
                  objectionHandling: comprehensiveAnalysis.objectionHandling,
                },
                usedFallback: false,
                retryCount
              };
            }
            
            // Create basic analysis from summary if no comprehensive format
            const fallback = calculateFallbackScore(messagesToAnalyze, conversationAge);
            console.log(`[Enhanced Analysis ${analysisId}] ✅ Summary success on attempt ${retryCount + 1}, using fallback scoring`);
            
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
          } else {
            console.warn(`[Enhanced Analysis ${analysisId}] ⚠️ Attempt ${retryCount + 1} returned null summary, will retry`);
          }
        }
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        const attemptDuration = Date.now() - analysisStartTime;
        const errorDetails = {
          attempt: retryCount + 1,
          error: lastError.message,
          stack: lastError.stack?.split('\n').slice(0, 5).join('\n'),
          duration: attemptDuration
        };
        errorLog.push(errorDetails);
        
        console.error(`[Enhanced Analysis ${analysisId}] ============================================`);
        console.error(`[Enhanced Analysis ${analysisId}] ❌ ATTEMPT ${retryCount + 1}/${safeMaxRetries} FAILED`);
        console.error(`[Enhanced Analysis ${analysisId}] - Duration: ${attemptDuration}ms`);
        console.error(`[Enhanced Analysis ${analysisId}] - Error: ${lastError.message}`);
        console.error(`[Enhanced Analysis ${analysisId}] - Error Type: ${lastError.constructor.name}`);
        console.error(`[Enhanced Analysis ${analysisId}] - Messages Analyzed: ${messagesToAnalyze.length}`);
        if (lastError.stack) {
          console.error(`[Enhanced Analysis ${analysisId}] - Stack trace (first 5 lines):`);
          lastError.stack.split('\n').slice(0, 5).forEach((line, idx) => {
            console.error(`[Enhanced Analysis ${analysisId}]   ${idx + 1}. ${line.trim()}`);
          });
        }
        console.error(`[Enhanced Analysis ${analysisId}] ============================================`);
      }

      retryCount++;
      
      // Reduced backoff: 500ms, 1s, 2s (faster retries)
      if (retryCount < safeMaxRetries) {
        const delayMs = Math.min(Math.pow(2, retryCount) * 500, 2000); // Max 2s delay
        console.log(`[Enhanced Analysis ${analysisId}] Retrying in ${delayMs}ms... (attempt ${retryCount + 1}/${safeMaxRetries})`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }

    // All retries exhausted - use fallback scoring
    const totalDuration = Date.now() - analysisStartTime;
    console.error(`[Enhanced Analysis ${analysisId}] ============================================`);
    console.error(`[Enhanced Analysis ${analysisId}] ❌ ALL ${safeMaxRetries} AI ATTEMPTS FAILED - USING FALLBACK`);
    console.error(`[Enhanced Analysis ${analysisId}] - Total Duration: ${totalDuration}ms`);
    console.error(`[Enhanced Analysis ${analysisId}] - Messages: ${messagesToAnalyze.length}`);
    console.error(`[Enhanced Analysis ${analysisId}] - Stages: ${pipelineStages?.length || 0}`);
    if (lastError) {
      console.error(`[Enhanced Analysis ${analysisId}] - Last Error: ${lastError.message}`);
      console.error(`[Enhanced Analysis ${analysisId}] - Error Type: ${lastError.constructor.name}`);
      if (lastError.stack) {
        console.error(`[Enhanced Analysis ${analysisId}] - Stack trace (first 10 lines):`);
        lastError.stack.split('\n').slice(0, 10).forEach((line, idx) => {
          console.error(`[Enhanced Analysis ${analysisId}]   ${idx + 1}. ${line.trim()}`);
        });
      }
      console.error(`[Enhanced Analysis ${analysisId}] - Full Error Log:`);
      errorLog.forEach((err, idx) => {
        console.error(`[Enhanced Analysis ${analysisId}]   Attempt ${err.attempt}: ${err.error} (${err.duration}ms)`);
      });
    } else {
      console.error(`[Enhanced Analysis ${analysisId}] - No error captured - all attempts returned null`);
      console.error(`[Enhanced Analysis ${analysisId}] - This indicates API returning empty/invalid responses`);
    }
    console.error(`[Enhanced Analysis ${analysisId}] ============================================`);
    
    // Ensure fallback scoring never throws
    let fallback;
    try {
      fallback = calculateFallbackScore(messagesToAnalyze, conversationAge);
    } catch (fallbackError) {
      console.error(`[Enhanced Analysis ${analysisId}] ❌ Fallback scoring failed:`, fallbackError instanceof Error ? fallbackError.message : String(fallbackError));
      // Emergency fallback with minimum values
      fallback = {
        leadScore: 20,
        leadStatus: 'NEW',
        confidence: 30,
        reasoning: 'Emergency fallback: Unable to calculate score due to errors'
      };
    }
    
    return {
      analysis: {
        summary: `Analyzed ${messagesToAnalyze.length} messages. ${fallback.reasoning}`,
        recommendedStage: determineStageByScore(fallback.leadScore, pipelineStages),
        leadScore: fallback.leadScore,
        leadStatus: fallback.leadStatus,
        confidence: fallback.confidence,
        reasoning: fallback.reasoning
      },
      usedFallback: true,
      retryCount
    };
  } catch (outerError) {
    // This should never happen, but ensure we never throw
    console.error(`[Enhanced Analysis ${analysisId}] 💥 CRITICAL: Outer catch block triggered (this should never happen):`, outerError);
    const errorMsg = outerError instanceof Error ? outerError.message : String(outerError);
    const errorStack = outerError instanceof Error ? outerError.stack : undefined;
    console.error(`[Enhanced Analysis ${analysisId}] Error details:`, { message: errorMsg, stack: errorStack?.split('\n').slice(0, 10) });
    
    // Emergency fallback - ensure we always return something
    try {
      const emergencyMessages = messages || [];
      const emergencyFallback = calculateFallbackScore(emergencyMessages, conversationAge);
      return {
        analysis: {
          summary: `Analysis encountered critical error: ${errorMsg}. ${emergencyFallback.reasoning}`,
          recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
          leadScore: emergencyFallback.leadScore,
          leadStatus: emergencyFallback.leadStatus,
          confidence: Math.max(emergencyFallback.confidence - 30, 20),
          reasoning: `Critical error fallback: ${errorMsg}. ${emergencyFallback.reasoning}`
        },
        usedFallback: true,
        retryCount: 0
      };
    } catch (finalError) {
      // Absolute last resort - return minimum viable result
      console.error(`[Enhanced Analysis ${analysisId}] 💥💥 ABSOLUTE CRITICAL: Even emergency fallback failed:`, finalError);
      return {
        analysis: {
          summary: `Analysis failed due to critical errors. Contact has ${messages?.length || 0} messages.`,
          recommendedStage: 'New Lead',
          leadScore: 15,
          leadStatus: 'NEW',
          confidence: 10,
          reasoning: 'Multiple critical errors prevented analysis'
        },
        usedFallback: true,
        retryCount: 0
      };
    }
  }
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

