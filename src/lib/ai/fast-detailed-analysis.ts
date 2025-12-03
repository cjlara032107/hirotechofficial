/**
 * Fast Detailed AI Analysis
 * Optimized for speed (2-4s) while maintaining detail
 * Uses shorter prompts and optimized parameters with 120B model
 */

import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';
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

export interface FastDetailedAnalysis {
  summary: string;
  recommendedStage: string;
  leadScore: number;
  leadStatus: string;
  confidence: number;
  reasoning: string;
}

// Use NVIDIA API model (same as main service for compatibility)
// NVIDIA API at integrate.api.nvidia.com/v1 supports: openai/gpt-oss-120b, meta/llama-3.1-8b-instruct, etc.
const MODEL = 'openai/gpt-oss-120b'; // NVIDIA API model - 120B parameters for better reasoning and accuracy
const TIMEOUT_MS = 90000; // 90 second timeout (increased for 120b model)
const MAX_MESSAGES = 20; // Reduced from 30 to 20 (still comprehensive, faster processing)
const MAX_MESSAGE_LENGTH = 200; // Truncate very long messages for faster processing

/**
 * Get API key with rotation
 */
async function getApiKey(): Promise<string | null> {
  try {
    console.log('[Fast AI] 🔑 Retrieving API key from database...');
    const dbKey = await apiKeyManager.getNextKey({ operation: 'fastDetailedAnalysis' });
    if (dbKey) {
      console.log(`[Fast AI] ✅ API key retrieved from database (length: ${dbKey.length}, prefix: ${dbKey.substring(0, 12)}...)`);
      return dbKey;
    }
    
    console.warn('[Fast AI] ⚠️ No API key from database, checking environment variables...');
    // Fall back to environment variables if no database keys available
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    if (envKey) {
      console.warn('[Fast AI] ⚠️ Using environment variable API key (database keys not available)');
      return envKey;
    }
    
    console.error('[Fast AI] ❌ No API key available from database or environment variables');
    return null;
  } catch (keyError) {
    const errorMsg = keyError instanceof Error ? keyError.message : String(keyError);
    console.error(`[Fast AI] ❌ Error retrieving API key: ${errorMsg}`);
    if (keyError instanceof Error && keyError.stack) {
      console.error(`[Fast AI] API key error stack:`, keyError.stack.split('\n').slice(0, 5).join('\n'));
    }
    
    // Try environment variable as fallback
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    if (envKey) {
      console.warn('[Fast AI] ⚠️ Using environment variable API key after database error');
      return envKey;
    }
    
    return null;
  }
}

/**
 * Create NVIDIA client
 */
function createNvidiaClient(apiKey: string): OpenAI {
  return new OpenAI({
    baseURL: 'https://integrate.api.nvidia.com/v1',
    apiKey: apiKey,
  });
}

/**
 * Fast detailed AI analysis - optimized for speed + detail
 * Target: 2-4 seconds per contact with detailed context
 */
export async function analyzeConversationFast(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  conversationAge?: Date
): Promise<FastDetailedAnalysis | null> {
  // Validate inputs
  if (!messages || messages.length === 0) {
    console.warn('[Fast AI] No messages provided');
    return null;
  }

  // Get API key with detailed logging
  let apiKey: string | null = null;
  try {
    apiKey = await getApiKey();
    if (apiKey) {
      console.log(`[Fast AI] ✅ API key retrieved (length: ${apiKey.length}, prefix: ${apiKey.substring(0, 12)}...)`);
    } else {
      console.warn('[Fast AI] ⚠️ No API key available, will use fallback');
      return null;
    }
  } catch (keyError) {
    const errorMsg = keyError instanceof Error ? keyError.message : String(keyError);
    console.error(`[Fast AI] ❌ Error retrieving API key: ${errorMsg}`);
    if (keyError instanceof Error && keyError.stack) {
      console.error(`[Fast AI] Stack trace:`, keyError.stack.split('\n').slice(0, 5).join('\n'));
    }
    return null;
  }

  try {
    console.log(`[Fast AI] Starting analysis: ${messages.length} messages, ${pipelineStages?.length || 0} stages`);
    const openai = createNvidiaClient(apiKey);

    // OPTIMIZED: Limit to last 20 messages (still comprehensive, faster processing)
    const recentMessages = messages.slice(-MAX_MESSAGES);
    
    // OPTIMIZED: Truncate very long messages to speed up processing (preserves key info)
    const conversationText = recentMessages
      .map(msg => {
        const text = msg.text.length > MAX_MESSAGE_LENGTH 
          ? msg.text.substring(0, MAX_MESSAGE_LENGTH) + '...'
          : msg.text;
        return `${msg.from}: ${text}`;
      })
      .join('\n');

    // OPTIMIZED: Ultra-concise but comprehensive prompt (faster processing, same quality)
    // Only include essential stage info (name and score range) to reduce prompt size
    const stageInfo = pipelineStages && pipelineStages.length > 0
      ? `\nStages: ${pipelineStages.slice(0, 10).map(s => `${s.name}(${s.leadScoreMin ?? 0}-${s.leadScoreMax ?? 100})`).join(' ')}`
      : '';

    // Enhanced prompt with clearer JSON format requirements
    const prompt = `Analyze this customer conversation and provide a comprehensive analysis.

Conversation:
${conversationText}${stageInfo}

Provide your analysis as a valid JSON object with the following structure. Do not include any text before or after the JSON. Return ONLY valid JSON:

{
  "summary": "Provide a detailed 15-30 sentence analysis covering: the main purpose and topics discussed, key points and decisions made, customer intent and needs, engagement level, sentiment and tone, any action items or requests, and overall assessment. Be specific and reference actual conversation content.",
  "leadScore": 0,
  "recommendedStage": "stage name from the stages list above, or 'New Lead' if no stages provided",
  "reasoning": "Provide a detailed 5-8 sentence explanation of why this stage and score were chosen, citing specific examples from the conversation, customer behavior patterns, engagement signals, and buying indicators."
}

CRITICAL: 
- Return ONLY valid JSON, no markdown, no code blocks, no explanations
- The summary must be at least 15 sentences and 500+ characters
- Use actual stage names from the stages list if provided
- Base leadScore on conversation quality, engagement, and buying signals (0-100)`;

    // OPTIMIZED: Lower temperature for more consistent, structured JSON output
    const completionPromise = openai.chat.completions.create({
      model: MODEL,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.4, // Lower temperature for more consistent, structured JSON output
      max_tokens: 4000, // Increased to 4000 to allow for deep reasoning chain + JSON output
    });

    // OPTIMIZED: Race with aggressive timeout for ultra-fast failure
    // Start timeout immediately (don't wait for API call to start)
    const requestStartTime = Date.now();
    let timeoutId: NodeJS.Timeout | null = null;
    let isTimeout = false;
    
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        isTimeout = true;
        reject(new Error(`AI timeout after ${TIMEOUT_MS}ms`));
      }, TIMEOUT_MS);
    });
    
    console.log(`[Fast AI] 📤 Sending request to ${MODEL} (timeout: ${TIMEOUT_MS}ms, prompt length: ${prompt.length} chars)`);
    
    let completion;
    try {
      completion = await Promise.race([
        completionPromise.then(result => {
          // Clear timeout on success
          if (timeoutId) {
            clearTimeout(timeoutId);
            timeoutId = null;
          }
          return result;
        }),
        timeoutPromise
      ]);
      const requestDuration = Date.now() - requestStartTime;
      console.log(`[Fast AI] 📥 Received response in ${requestDuration}ms`);
    } catch (raceError) {
      // Clear timeout if still set
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      
      const errorMsg = raceError instanceof Error ? raceError.message : String(raceError);
      const requestDuration = Date.now() - requestStartTime;
      const errorType = isTimeout ? 'TIMEOUT' : 'API_ERROR';
      console.error(`[Fast AI] ❌ Request failed after ${requestDuration}ms (${errorType}): ${errorMsg}`);
      
      // Log timeout-specific information
      if (isTimeout) {
        console.error(`[Fast AI] ⏱️ Request exceeded ${TIMEOUT_MS}ms timeout limit`);
        console.error(`[Fast AI] 💡 Consider: increasing timeout, reducing prompt size, or using faster model`);
      }
      
      throw raceError; // Re-throw to be caught by outer try-catch
    } finally {
      // Ensure timeout is always cleared
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }

    // Check for errors in response
    if ('error' in completion && (completion as any).error !== undefined) {
      const errorMsg = (completion as any).error?.message || (completion as any).error || 'Unknown API error';
      const errorCode = (completion as any).error?.code;
      const errorType = (completion as any).error?.type;
      console.error(`[Fast AI] ❌ API returned error: ${errorMsg}`);
      if (errorCode) console.error(`[Fast AI] Error code: ${errorCode}`);
      if (errorType) console.error(`[Fast AI] Error type: ${errorType}`);
      return null;
    }

    if (!completion.choices || completion.choices.length === 0) {
      console.error('[Fast AI] ❌ No choices in API response');
      console.error('[Fast AI] Response structure:', JSON.stringify(completion, null, 2).substring(0, 500));
      return null;
    }

    const content = completion.choices[0]?.message?.content || (completion.choices[0]?.message as any)?.reasoning_content;
    if (!content || content.trim().length === 0) {
      console.error('[Fast AI] ❌ Empty content in API response');
      console.error('[Fast AI] Response structure:', JSON.stringify(completion, null, 2).substring(0, 500));
      return null;
    }
    
    console.log(`[Fast AI] ✅ Received response (${content.length} chars, first 100: "${content.substring(0, 100)}...")`);

    // Parse JSON response with improved error handling and multiple strategies
    let parsed: any;
    try {
      // Strategy 1: Clean content: remove markdown code blocks, trim whitespace
      let cleanedContent = content.trim();
      
      // Remove markdown code blocks if present
      cleanedContent = cleanedContent.replace(/^```json\s*/i, '').replace(/^```\s*/i, '');
      cleanedContent = cleanedContent.replace(/\s*```$/i, '');
      
      // Strategy 2: Extract last valid JSON object (handle reasoning chains)
      // Reasoning models often put the answer at the END.
      const lastBrace = cleanedContent.lastIndexOf('}');
      if (lastBrace !== -1) {
        // Find the matching opening brace by scanning backwards
        let depth = 0;
        let firstBrace = -1;
        for (let i = lastBrace; i >= 0; i--) {
          if (cleanedContent[i] === '}') depth++;
          if (cleanedContent[i] === '{') {
            depth--;
            if (depth === 0) {
              firstBrace = i;
              break;
            }
          }
        }
        
        if (firstBrace !== -1) {
           const potentialJson = cleanedContent.substring(firstBrace, lastBrace + 1);
           try {
             parsed = JSON.parse(potentialJson);
           } catch {
             // Failed to parse last object, try strict regex approach
           }
        }
      }

      if (!parsed) {
        // Fallback Strategy: Strict JSON extraction regex
        const jsonMatch = cleanedContent.match(/\{(?:[^{}]|{[^{}]*})*\}/g);
        if (jsonMatch && jsonMatch.length > 0) {
          // Try the last match first as it's likely the final answer
          try {
            parsed = JSON.parse(jsonMatch[jsonMatch.length - 1]);
          } catch {
             // Try first match
             try {
                parsed = JSON.parse(jsonMatch[0]);
             } catch {
                throw new Error('Regex found JSON-like structure but parsing failed');
             }
          }
        } else {
           throw new Error('No JSON structure found');
        }
      }
      
      // Validate required fields with detailed error messages
      if (!parsed || typeof parsed !== 'object') {
        throw new Error('Parsed result is not an object');
      }
      
      if (!parsed.summary || typeof parsed.summary !== 'string') {
        throw new Error(`Missing or invalid summary field. Got: ${typeof parsed.summary}, keys: ${Object.keys(parsed).join(', ')}`);
      }
      
      // Ensure summary is long enough (at least 200 chars)
      if (parsed.summary.length < 200) {
        console.warn(`[Fast AI] ⚠️ Summary too short (${parsed.summary.length} chars), enhancing with fallback reasoning`);
        const fallback = calculateFallbackScore(messages, conversationAge);
        parsed.summary = `${parsed.summary.trim()} ${fallback.reasoning}`;
      }
      
    } catch (parseError) {
      const parseErrorMsg = parseError instanceof Error ? parseError.message : String(parseError);
      const parseErrorType = parseError instanceof Error ? parseError.constructor.name : typeof parseError;
      console.error(`[Fast AI] ❌ JSON parsing failed: ${parseErrorMsg}`);
      console.error(`[Fast AI] Parse error type: ${parseErrorType}`);
      console.error(`[Fast AI] Response content length: ${content.length} chars`);
      console.error(`[Fast AI] Response content (first 500 chars):`, content.substring(0, 500));
      console.error(`[Fast AI] Response content (last 200 chars):`, content.substring(Math.max(0, content.length - 200)));
      
      if (parseError instanceof Error && parseError.stack) {
        console.error(`[Fast AI] Parse error stack:`, parseError.stack.split('\n').slice(0, 5).join('\n'));
      }
      
      // Try to extract any useful text before giving up
      try {
        const fallback = calculateFallbackScore(messages, conversationAge);
        const extractedText = content.split('\n').find((line: string) => line.length > 50) || content.substring(0, 300);
        
        return {
          summary: extractedText.trim() || `Contact conversation analysis. ${fallback.reasoning}`,
          recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
          leadScore: fallback.leadScore,
          leadStatus: fallback.leadStatus,
          confidence: 60, // Lower confidence for failed parsing
          reasoning: `JSON parsing failed: ${parseErrorMsg}. ${fallback.reasoning}`
        };
      } catch (fallbackError) {
        console.error(`[Fast AI] ❌ Even fallback scoring failed during parse error recovery:`, fallbackError);
        // Absolute minimum fallback
        return {
          summary: `Analysis encountered parsing errors. Contact has ${messages.length} messages.`,
          recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
          leadScore: 20,
          leadStatus: 'NEW',
          confidence: 30,
          reasoning: `Multiple errors: JSON parsing failed (${parseErrorMsg})`
        };
      }
    }

    // Validate and enhance parsed response with comprehensive validation
    const fallback = calculateFallbackScore(messages, conversationAge);
    
    // Validate summary
    let finalSummary = parsed.summary;
    if (!finalSummary || typeof finalSummary !== 'string') {
      console.warn(`[Fast AI] ⚠️ Invalid summary in parsed response, using fallback`);
      finalSummary = `Contact with ${messages.length} messages. ${fallback.reasoning}`;
    }
    
    // Ensure summary meets minimum length requirement
    if (finalSummary.length < 200) {
      console.warn(`[Fast AI] ⚠️ Summary too short (${finalSummary.length} chars), enhancing`);
      finalSummary = `${finalSummary.trim()} ${fallback.reasoning}`;
    }
    
    // Validate and normalize leadScore with bounds checking
    let leadScore = fallback.leadScore;
    if (parsed.leadScore !== undefined && parsed.leadScore !== null) {
      if (typeof parsed.leadScore === 'number' && !isNaN(parsed.leadScore)) {
        leadScore = Math.max(0, Math.min(100, Math.round(parsed.leadScore)));
        console.log(`[Fast AI] ✅ Using AI-provided leadScore: ${leadScore}`);
      } else {
        console.warn(`[Fast AI] ⚠️ Invalid leadScore type (${typeof parsed.leadScore}), using fallback: ${fallback.leadScore}`);
      }
    } else {
      console.log(`[Fast AI] ℹ️ No leadScore in response, using fallback: ${fallback.leadScore}`);
    }
    
    // Validate recommendedStage with existence check
    let recommendedStage = pipelineStages?.[0]?.name || 'New Lead';
    if (parsed.recommendedStage && typeof parsed.recommendedStage === 'string') {
      const recommendedStageTrimmed = parsed.recommendedStage.trim();
      if (recommendedStageTrimmed.length > 0) {
        // Check if the recommended stage exists in pipeline stages
        const stageExists = pipelineStages?.some(s => 
          s.name.toLowerCase() === recommendedStageTrimmed.toLowerCase()
        );
        if (stageExists || !pipelineStages || pipelineStages.length === 0) {
          recommendedStage = recommendedStageTrimmed;
          console.log(`[Fast AI] ✅ Using AI-provided stage: ${recommendedStage}`);
        } else {
          console.warn(`[Fast AI] ⚠️ Recommended stage "${recommendedStageTrimmed}" not found in pipeline stages, using fallback: ${recommendedStage}`);
        }
      } else {
        console.warn(`[Fast AI] ⚠️ Empty recommendedStage, using fallback: ${recommendedStage}`);
      }
    } else {
      console.log(`[Fast AI] ℹ️ No recommendedStage in response, using fallback: ${recommendedStage}`);
    }
    
    // Determine leadStatus based on score (with validation)
    let leadStatus = fallback.leadStatus;
    if (leadScore >= 60) {
      leadStatus = 'QUALIFIED';
    } else if (leadScore >= 40) {
      leadStatus = 'CONTACTED';
    } else {
      leadStatus = 'NEW';
    }
    
    // Validate reasoning
    let finalReasoning = parsed.reasoning;
    if (!finalReasoning || typeof finalReasoning !== 'string' || finalReasoning.trim().length === 0) {
      console.warn(`[Fast AI] ⚠️ Invalid or missing reasoning, using fallback`);
      finalReasoning = fallback.reasoning;
    }
    
    console.log(`[Fast AI] ✅ Analysis successful: score=${leadScore}, stage=${recommendedStage}, status=${leadStatus}, summary=${finalSummary.length} chars`);
    
    // Final validation before returning
    const result = {
      summary: finalSummary,
      recommendedStage,
      leadScore,
      leadStatus,
      confidence: 85, // High confidence for successful AI analysis
      reasoning: finalReasoning
    };
    
    // Validate all required fields are present
    if (!result.summary || !result.recommendedStage || typeof result.leadScore !== 'number') {
      console.error(`[Fast AI] ❌ Result validation failed:`, result);
      throw new Error('Result validation failed: missing required fields');
    }
    
    return result;

  } catch (error) {
    // Enhanced error logging
    const errorMsg = error instanceof Error ? error.message : String(error);
    const errorType = error instanceof Error ? error.constructor.name : typeof error;
    const errorStack = error instanceof Error ? error.stack : undefined;
    
    console.error(`[Fast AI] ❌ Analysis failed: ${errorMsg}`);
    console.error(`[Fast AI] Error type: ${errorType}`);
    
    // Check for specific error types
    if (errorMsg.includes('timeout') || errorMsg.includes('Timeout')) {
      console.error(`[Fast AI] ⏱️ Timeout error - request took longer than ${TIMEOUT_MS}ms`);
    } else if (errorMsg.includes('401') || errorMsg.includes('403')) {
      console.error(`[Fast AI] 🔐 Authentication/Authorization error - check API key permissions`);
    } else if (errorMsg.includes('429')) {
      console.error(`[Fast AI] 🚫 Rate limit error - too many requests`);
    } else if (errorMsg.includes('network') || errorMsg.includes('fetch')) {
      console.error(`[Fast AI] 🌐 Network error - check internet connection`);
    }
    
    if (errorStack) {
      console.error(`[Fast AI] Stack trace (first 10 lines):`, errorStack.split('\n').slice(0, 10).join('\n'));
    }
    
    // Log request context for debugging
    console.error(`[Fast AI] Request context: messages=${messages.length}, stages=${pipelineStages?.length || 0}, conversationAge=${conversationAge?.toISOString() || 'none'}`);
    
    return null;
  }
}

