import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';
import { executeAIRequest, getTimeoutForOperation, getPriorityForOperation } from './ai-request-wrapper';
import { RequestPriority } from './request-queue';

const MAX_ATTEMPTS = 3;
const BASE_RETRY_DELAY_MS = 500; // Base delay: 500ms (optimized for speed)
const MAX_RETRY_DELAY_MS = 2000; // Max delay: 2 seconds (optimized for speed)

// Model configuration - prefer faster models when available
const PRIMARY_MODEL = process.env.AI_PRIMARY_MODEL || 'openai/gpt-oss-120b';
const FAST_MODEL = process.env.AI_FAST_MODEL || 'openai/gpt-oss-20b'; // Faster, smaller model for simple operations
const MODEL = PRIMARY_MODEL; // Default model

// Determine if we should use a faster model based on operation complexity
function getModelForOperation(operation: 'simple' | 'complex' = 'complex'): string {
  if (operation === 'simple') {
    return FAST_MODEL;
  }
  return PRIMARY_MODEL;
}

// Log model configuration on module load
import { logger } from '@/lib/utils/logger';
logger.debug('NVIDIA Model Configuration', { 
  model: MODEL, 
  baseURL: 'https://integrate.api.nvidia.com/v1' 
});

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculates exponential backoff delay for rate limit retries
 * 
 * Uses exponential backoff formula: baseDelay * (2 ^ attemptNumber), capped at maxDelay.
 * This provides increasing delays between retry attempts to avoid overwhelming the API.
 * 
 * @param attemptNumber - Zero-based attempt number (0 = first retry, 1 = second retry, etc.)
 * @returns Delay in milliseconds, capped at MAX_RETRY_DELAY_MS
 * 
 * @example
 * ```typescript
 * // First retry: 500ms
 * calculateExponentialBackoff(0); // 500
 * // Second retry: 1000ms
 * calculateExponentialBackoff(1); // 1000
 * // Third retry: 2000ms (capped)
 * calculateExponentialBackoff(2); // 2000
 * ```
 */
function calculateExponentialBackoff(attemptNumber: number): number {
  const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attemptNumber);
  return Math.min(delay, MAX_RETRY_DELAY_MS);
}

// Get API key from database first, then fall back to environment variables
async function getApiKey(requestContext?: { operation?: string; contactId?: string; campaignId?: string }): Promise<string | null> {
  // Try database first (preferred method - can be managed through UI)
  const dbKey = await apiKeyManager.getNextKey(requestContext);
  if (dbKey) {
    return dbKey;
  }
  
  // Fall back to environment variables if no database keys available
  const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
  if (envKey) {
    console.warn('[NVIDIA] ⚠️ Using environment variable API key (database keys not available)');
  }
  return envKey;
}

/**
 * Helper function to log rate limit exhaustion information when no API key is available
 */
async function logRateLimitExhaustion(): Promise<void> {
  const rateLimitInfo = await apiKeyManager.getRateLimitExhaustionInfo();
  if (rateLimitInfo.allRateLimited) {
    const timeUntilAvailable = rateLimitInfo.earliestAvailableAt 
      ? Math.max(0, rateLimitInfo.earliestAvailableAt.getTime() - Date.now())
      : null;
    const minutesUntilAvailable = timeUntilAvailable 
      ? Math.ceil(timeUntilAvailable / 60000)
      : null;
    
    console.error(
      `[NVIDIA] 🚫 All API keys are rate-limited. ` +
      (minutesUntilAvailable 
        ? `Earliest key available in ~${minutesUntilAvailable} minute(s). ` 
        : '') +
      `Please wait or add additional API keys through Settings → API Keys.`
    );
  } else {
    console.error('[NVIDIA] No API key available. Add one through Settings → API Keys or set NVIDIA_API_KEY environment variable.');
  }
}

// Helper function to create OpenAI client configured for NVIDIA API
function createNvidiaClient(apiKey: string): OpenAI {
  console.log(`[NVIDIA] Creating client with baseURL: https://integrate.api.nvidia.com/v1`);
  console.log(`[NVIDIA] API Key length: ${apiKey.length}, starts with: ${apiKey.substring(0, 8)}...`);
  
  return new OpenAI({
    baseURL: 'https://integrate.api.nvidia.com/v1',
    apiKey: apiKey,
  });
}

/**
 * Analyzes a conversation and generates a summary using AI
 * 
 * This function processes a conversation between a contact and the business,
 * using AI to generate a concise summary (3-5 sentences) that captures the
 * key points, sentiment, and context of the conversation.
 * 
 * Features:
 * - Automatic API key rotation and rate limit handling
 * - Retry logic with exponential backoff
 * - Circuit breaker protection
 * - Performance monitoring and timeout handling
 * - Uses faster model for simple analysis operations
 * 
 * @param messages - Array of conversation messages with sender and text
 * @param messages[].from - Sender identifier (e.g., contact ID or 'business')
 * @param messages[].text - Message text content
 * @param messages[].timestamp - Optional message timestamp
 * @param retries - Number of retry attempts on failure (default: 2)
 * @param context - Optional context for API key selection and logging
 * @param context.contactId - Contact ID for context-aware key selection
 * @param context.conversationId - Conversation ID for logging
 * @returns Promise resolving to AI-generated summary string, or null if analysis fails
 * 
 * @example
 * ```typescript
 * const summary = await analyzeConversation([
 *   { from: 'contact_123', text: 'Hello, I need help with my order' },
 *   { from: 'business', text: 'Hi! I can help you with that.' }
 * ], 2, { contactId: 'contact_123' });
 * ```
 */
export async function analyzeConversation(
  messages: Array<{
    from: string;
    text: string;
    timestamp?: Date;
  }>,
  retries = 2,
  context?: { contactId?: string; conversationId?: string }
): Promise<string | null> {
  const operation = 'analyzeConversation';
  const apiKey = await getApiKey({ 
    operation,
    contactId: context?.contactId 
  });
  if (!apiKey) {
    await logRateLimitExhaustion();
    return null;
  }

  try {
    // Use faster model for simple conversation analysis
    const model = getModelForOperation('simple');
    const result = await executeAIRequest(
      () => analyzeConversationWithKey(apiKey, messages, retries, 0, model),
      {
        operation,
        priority: getPriorityForOperation(operation, false),
        timeout: getTimeoutForOperation(operation),
        circuitBreaker: 'conversationAnalysis',
        apiKeyId: apiKey.substring(0, 16), // Use key prefix for tracking
      }
    );

    // Record success
    if (result) {
      await apiKeyManager.recordSuccess(apiKey, { 
        operation,
      });
    }
    
    return result;
  } catch (error) {
    // Error already logged by performance monitor
    // Try retry logic if not a circuit breaker error
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (!errorMessage.includes('Circuit breaker') && retries > 0) {
      console.log(`[NVIDIA] Retrying analyzeConversation (${retries} retries left)...`);
      const backoffDelay = calculateExponentialBackoff(0); // Use base delay for general retries
      await sleep(backoffDelay);
      return analyzeConversation(messages, retries - 1, context);
    }
    throw error;
  }
}

async function analyzeConversationWithKey(
  apiKey: string,
  messages: Array<{
    from: string;
    text: string;
    timestamp?: Date;
  }>,
  retries: number,
  keyAttempts: number,
  modelOverride?: string
): Promise<string | null> {
  const modelToUse = modelOverride || MODEL;
  try {
    const openai = createNvidiaClient(apiKey);

    // Format conversation for AI
    const conversationText = messages
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');

    const prompt = `Analyze this conversation and provide a concise 3-5 sentence summary covering:
- The main topic or purpose of the conversation
- Key points discussed
- Customer intent or needs
- Any action items or requests

Conversation:
${conversationText}

Summary:`;

    console.log(
      `[NVIDIA] Sending request - Model: ${modelToUse}, Messages: ${messages.length}`
    );

    const completion = await openai.chat.completions.create({
      model: modelToUse,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3, // Lower temperature for faster, more consistent responses
      max_tokens: 500, // Limit tokens for faster response (3-5 sentence summary)
    });

    console.log(
      `[NVIDIA] Received response - Choices: ${
        completion.choices?.length || 0
      }, Usage: ${JSON.stringify(completion.usage || {})}`
    );

    // Check for error in response (API returned error object)
    // Check if error property exists (even if empty string)
    if ('error' in completion && (completion as any).error !== undefined) {
      const errorMsg = (completion as any).error?.message || (completion as any).error || 'Unknown API error';
      console.error(`[NVIDIA] API returned error in conversation analysis response: ${errorMsg}. Full response:`, JSON.stringify(completion, null, 2));
      return null;
    }

    // Check if choices array exists and has items
    if (!completion.choices || completion.choices.length === 0) {
      console.error('[NVIDIA] No choices in response. Full response:', JSON.stringify(completion, null, 2));
      return null;
    }

    const summary = completion.choices[0]?.message?.content;
    if (!summary) {
      console.error('[NVIDIA] No response content received. Full response:', JSON.stringify(completion, null, 2));
      return null;
    }
    
    // Cache the result
    const { setCachedAnalysis, hashConversation } = await import('./conversation-cache');
    const hash = hashConversation(messages);
    await setCachedAnalysis(hash, {
      summary,
      recommendedStage: 'New Lead',
      leadScore: 50,
      leadStatus: 'NEW',
      confidence: 80,
      reasoning: 'Cached conversation analysis'
    }).catch(() => {
      // Non-critical if caching fails
    });
    
    // Success will be recorded by caller with duration
    
    console.log(`[NVIDIA] ✅ Generated summary (${summary.length} chars)`);
    
    return summary.trim();
  } catch (error: unknown) {
    // Enhanced error logging
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStatus = (error as any)?.status || (error as any)?.response?.status || 
                       (errorMessage?.match(/(\d{3})\s+status/i)?.[1]);
    const errorDetails = error instanceof Error ? {
      name: error.name,
      message: error.message,
      status: errorStatus,
      stack: error.stack?.split('\n').slice(0, 3).join('\n'),
    } : { raw: String(error), status: errorStatus };
    
    console.error('[NVIDIA] ❌ Analysis failed:', errorMessage);
    if (errorStatus) {
      console.error(`[NVIDIA] HTTP Status: ${errorStatus}`);
    }
    console.error('[NVIDIA] Error details:', JSON.stringify(errorDetails, null, 2));
    
    // Check if it's a rate limit error (429)
    if (errorMessage?.includes('429') || errorMessage?.includes('quota') || errorMessage?.includes('rate limit')) {
      const attemptNumber = keyAttempts + 1;
      if (attemptNumber < MAX_ATTEMPTS) {
        const backoffDelay = calculateExponentialBackoff(keyAttempts);
        console.warn(
          `[NVIDIA] Rate limit hit, retrying (attempt ${attemptNumber + 1}/${MAX_ATTEMPTS}) after ${backoffDelay}ms (exponential backoff)...`
        );
        await sleep(backoffDelay);
        return analyzeConversationWithKey(apiKey, messages, retries, keyAttempts + 1, modelOverride);
      }

      console.error('[NVIDIA] Rate limit persists after multiple attempts');
      
      // Mark key as rate-limited in database if it came from there
      await apiKeyManager.markRateLimited(apiKey);
      
      // Try again if we have retries left (will get a different key from rotation)
      if (retries > 0) {
        const backoffDelay = calculateExponentialBackoff(0); // Reset backoff for new key
        await sleep(backoffDelay);
        return analyzeConversation(messages, retries - 1);
      }
      
      return null;
    }
    
    // Check for 401/403 authentication/authorization errors
    const statusCode = errorStatus || 
                      ((error as any)?.status) || 
                      ((error as any)?.response?.status) ||
                      (errorMessage?.includes('403') ? 403 : errorMessage?.includes('401') ? 401 : null);
    
    const isAuthError = statusCode === 401 || 
                       statusCode === 403 ||
                       errorMessage?.includes('401') || 
                       errorMessage?.includes('403') ||
                       errorMessage?.includes('Forbidden') ||
                       errorMessage?.includes('No auth') || 
                       errorMessage?.includes('Unauthorized') || 
                       errorMessage?.includes('User not found');
    
    if (isAuthError) {
      const finalStatusCode = statusCode || (errorMessage?.includes('403') ? 403 : 401);
      console.error(`[NVIDIA] 🔐 Authentication failed (${finalStatusCode}) - Invalid or expired API key`);
      console.error('[NVIDIA] API key should start with "nvapi-" for NVIDIA API');
      console.error(`[NVIDIA] Current key prefix: ${apiKey.substring(0, 12)}...`);
      
      // Mark key as invalid in database if it came from there
      await apiKeyManager.markInvalid(apiKey, `NVIDIA API authentication failed (${finalStatusCode})`);
      
      // Try again if we have retries left (will get a different key from rotation)
      if (retries > 0) {
        console.log('[NVIDIA] Retrying with next available key...');
        return analyzeConversation(messages, retries - 1);
      }
      
      return null;
    }
    
    return null;
  }
}

export async function getAvailableKeyCount(): Promise<number> {
  // Get count from database first
  const dbCount = await apiKeyManager.getKeyCount();
  if (dbCount > 0) {
    return dbCount;
  }
  
  // Fall back to environment variable check
  return (process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY) ? 1 : 0;
}

// Generate follow-up message for AI automation
export interface AIFollowUpResult {
  message: string;
  reasoning: string;
}

export async function generateFollowUpMessage(
  contactName: string,
  conversationHistory: Array<{ from: string; text: string; timestamp?: Date }>,
  customPrompt?: string | null,
  languageStyle?: string | null,
  retries = 2
): Promise<AIFollowUpResult | null> {
  const apiKey = await getApiKey();
  if (!apiKey) {
    await logRateLimitExhaustion();
    return null;
  }

  return generateFollowUpWithKey(
    apiKey,
    contactName,
    conversationHistory,
    customPrompt,
    languageStyle,
    retries,
    0
  );
}

async function generateFollowUpWithKey(
  apiKey: string,
  contactName: string,
  conversationHistory: Array<{ from: string; text: string; timestamp?: Date }>,
  customPrompt: string | null | undefined,
  languageStyle: string | null | undefined,
  retries: number,
  keyAttempts: number
): Promise<AIFollowUpResult | null> {
  try {
    const openai = createNvidiaClient(apiKey);

    // Format conversation history
    const historyText = conversationHistory
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');

    // Build prompt based on custom instructions and language style
    const styleInstruction = languageStyle 
      ? `\n\nLanguage Style: ${languageStyle}`
      : '\n\nUse a friendly, professional tone that feels natural and conversational.';

    const customInstruction = customPrompt
      ? `\n\nCustom Instructions: ${customPrompt}`
      : '';

    const prompt = `You are a helpful business assistant generating a follow-up message for a customer named ${contactName}.

Previous Conversation:
${historyText}
${styleInstruction}${customInstruction}

Generate a natural, engaging follow-up message that:
1. References the previous conversation context
2. Provides value or continues the conversation naturally
3. Encourages further engagement
4. Feels personalized and human (not robotic)
5. Is concise (2-4 sentences)

Respond ONLY with valid JSON (no markdown, no explanation):
{
  "message": "the follow-up message text here",
  "reasoning": "brief explanation of why this message was chosen"
}`;

    const completion = await openai.chat.completions.create({
      model: MODEL,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    // Check for error in response (API returned error object)
    // Check if error property exists (even if empty string)
    if ('error' in completion && (completion as any).error !== undefined) {
      const errorMsg = (completion as any).error?.message || (completion as any).error || 'Unknown API error';
      console.error(`[NVIDIA] API returned error in response: ${errorMsg}. Full response:`, JSON.stringify(completion, null, 2));
      
      // Retry with different API key if available
      if (retries > 0) {
        console.log(`[NVIDIA] Retrying with different API key (${retries} retries remaining)...`);
        await sleep(500); // Reduced delay for faster retries
        return generateFollowUpMessage(
          contactName,
          conversationHistory,
          customPrompt,
          languageStyle,
          retries - 1
        );
      }
      
      return null;
    }

    // Check if choices array exists and has items
    if (!completion.choices || completion.choices.length === 0) {
      console.error('[NVIDIA] No choices in response for follow-up message. Full response:', JSON.stringify(completion, null, 2));
      
      // Retry with different API key if available
      if (retries > 0) {
        console.log(`[NVIDIA] Retrying with different API key (${retries} retries remaining)...`);
        await sleep(500); // Reduced delay for faster retries
        return generateFollowUpMessage(
          contactName,
          conversationHistory,
          customPrompt,
          languageStyle,
          retries - 1
        );
      }
      
      return null;
    }

    const text = completion.choices[0]?.message?.content?.trim();
    if (!text) {
      console.error('[NVIDIA] No response content received');
      return null;
    }
    
    // Parse JSON response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.error('[NVIDIA] No JSON found in response');
      return null;
    }
    
    const followUp = JSON.parse(jsonMatch[0]) as AIFollowUpResult;
    console.log(
      `[NVIDIA] Generated follow-up message for ${contactName}: "${followUp.message}"`
    );
    
    return followUp;
  } catch (error: unknown) {
    // Check if it's a rate limit error (429)
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (
      errorMessage?.includes('429') ||
      errorMessage?.includes('quota') ||
      errorMessage?.includes('rate limit')
    ) {
      const attemptNumber = keyAttempts + 1;
      if (attemptNumber < MAX_ATTEMPTS) {
        const backoffDelay = calculateExponentialBackoff(keyAttempts);
        console.warn(
          `[NVIDIA] Rate limit hit (follow-up), retrying (attempt ${attemptNumber + 1}/${MAX_ATTEMPTS}) after ${backoffDelay}ms (exponential backoff)...`
        );
        await sleep(backoffDelay);
        return generateFollowUpWithKey(
          apiKey,
          contactName,
          conversationHistory,
          customPrompt,
          languageStyle,
          retries,
          keyAttempts + 1
        );
      }

      console.error('[NVIDIA] Rate limit persists for follow-up after multiple attempts');
      
      // Try again if we have retries left
      if (retries > 0) {
        const backoffDelay = calculateExponentialBackoff(0); // Reset backoff for new key
        await sleep(backoffDelay);
        return generateFollowUpMessage(
          contactName,
          conversationHistory,
          customPrompt,
          languageStyle,
          retries - 1
        );
      }
      
      return null;
    }
    
    // Check for 401/403 authentication/authorization errors
    const isAuthError = errorMessage?.includes('401') || 
                       errorMessage?.includes('403') ||
                       errorMessage?.includes('Forbidden') ||
                       errorMessage?.includes('No auth') || 
                       errorMessage?.includes('Unauthorized') || 
                       (error instanceof Error && 'status' in error && (error.status === 401 || error.status === 403));
    
    if (isAuthError) {
      const statusCode = (error as any)?.status || (errorMessage?.includes('403') ? 403 : 401);
      console.error(`[NVIDIA] 🔐 Authentication failed (${statusCode}) - Invalid or expired API key`);
      
      // Get API key to mark as invalid
      const apiKey = await getApiKey();
      if (apiKey) {
        await apiKeyManager.markInvalid(apiKey, `NVIDIA API authentication failed (${statusCode})`);
      }
    }
    
    console.error('[NVIDIA] Follow-up generation failed:', errorMessage);
    return null;
  }
}

// Structured analysis for pipeline stage recommendation
export interface AIContactAnalysis {
  summary: string;              // Existing 3-5 sentence summary
  recommendedStage: string;     // Stage name recommendation
  leadScore: number;            // 0-100
  leadStatus: string;           // NEW, CONTACTED, QUALIFIED, etc.
  confidence: number;           // 0-100 confidence score
  reasoning: string;            // Why this stage was chosen
}

export async function analyzeConversationWithStageRecommendation(
  messages: Array<{ from: string; text: string; timestamp?: Date }>,
  pipelineStages: Array<{ 
    name: string; 
    type: string; 
    description?: string | null;
    leadScoreMin?: number;
    leadScoreMax?: number;
  }>,
  retries = 2,
  context?: { contactId?: string }
): Promise<AIContactAnalysis | null> {
  const operation = 'analyzeConversationWithStageRecommendation';
  
  // Check cache first (include pipeline stages in hash for accuracy)
  const { hashConversation, getCachedAnalysis } = await import('./conversation-cache');
  const hash = hashConversation([
    ...messages,
    ...pipelineStages.map(s => ({ from: 'system', text: JSON.stringify(s) }))
  ]);
  const cached = await getCachedAnalysis(hash);
  if (cached) {
    console.log(`[NVIDIA] ✅ Using cached stage recommendation for conversation ${hash.substring(0, 8)}...`);
    return cached;
  }
  
  const apiKey = await getApiKey({ 
    operation,
    contactId: context?.contactId 
  });
  if (!apiKey) {
    await logRateLimitExhaustion();
    return null;
  }

  try {
    const result = await executeAIRequest(
      () => analyzeConversationWithStageAndKey(apiKey, messages, pipelineStages, retries, 0),
      {
        operation,
        priority: getPriorityForOperation(operation, false),
        timeout: getTimeoutForOperation(operation),
        circuitBreaker: 'conversationAnalysis',
        apiKeyId: apiKey.substring(0, 16),
      }
    );

    // Record success
    if (result) {
      await apiKeyManager.recordSuccess(apiKey, { 
        operation,
      });
    }
    
    return result;
  } catch (error) {
    // Error already logged by performance monitor
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (!errorMessage.includes('Circuit breaker') && retries > 0) {
      console.log(`[NVIDIA] Retrying analyzeConversationWithStageRecommendation (${retries} retries left)...`);
      const backoffDelay = calculateExponentialBackoff(0); // Use base delay for general retries
      await sleep(backoffDelay);
      return analyzeConversationWithStageRecommendation(messages, pipelineStages, retries - 1, context);
    }
    throw error;
  }
}

async function analyzeConversationWithStageAndKey(
  apiKey: string,
  messages: Array<{ from: string; text: string; timestamp?: Date }>,
  pipelineStages: Array<{ 
    name: string; 
    type: string; 
    description?: string | null;
    leadScoreMin?: number;
    leadScoreMax?: number;
  }>,
  retries: number,
  keyAttempts: number
): Promise<AIContactAnalysis | null> {
  try {
    const openai = createNvidiaClient(apiKey);

    const conversationText = messages
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');

    // Enhanced stage descriptions with lead score ranges
    const stageDescriptions = pipelineStages
      .map((s, i) => {
        let desc = `${i + 1}. ${s.name} (${s.type})`;
        
        // Add score range if available
        if (s.leadScoreMin !== undefined && s.leadScoreMax !== undefined) {
          desc += ` [Score: ${s.leadScoreMin}-${s.leadScoreMax}]`;
        }
        
        // Add description if available
        if (s.description) {
          desc += `: ${s.description}`;
        }
        
        return desc;
      })
      .join('\n');

    const prompt = `Analyze this customer conversation and intelligently assign them to the most appropriate sales/support stage.

Available Pipeline Stages:
${stageDescriptions}

Conversation:
${conversationText}

Analyze the conversation and determine:
1. Which stage best fits this contact's current position in the customer journey
2. Their engagement level and intent (lead score 0-100)
   - Use the stage score ranges as guides for appropriate scoring
   - Score should reflect: conversation maturity, customer intent, engagement level, and commitment signals
3. Their status (NEW, CONTACTED, QUALIFIED, PROPOSAL_SENT, NEGOTIATING, WON, LOST, UNRESPONSIVE)
   - If the conversation indicates a CLOSED deal → status: WON
   - If the conversation indicates LOST opportunity → status: LOST
4. Your confidence in this assessment (0-100)

Scoring Guidelines:
- 0-30: Cold leads, initial contact, minimal engagement, just browsing
- 31-60: Warm leads, asking questions, showing interest, early qualification
- 61-80: Hot leads, high engagement, discussing specifics, budget/timeline mentioned
- 81-100: Ready to close, strong commitment signals, final negotiations, deal imminent

Consider:
- Conversation maturity (new inquiry vs ongoing discussion)
- Customer intent (browsing vs ready to buy)
- Engagement level (responsive vs unresponsive)
- Specific requests or commitments made (pricing, timeline, contracts)
- Timeline and urgency indicators
- Buying signals (budget discussed, decision maker involved, timeline set)

IMPORTANT:
- If customer has AGREED TO BUY, CLOSED THE DEAL, or SIGNED: leadStatus MUST be "WON" (score 85-100)
- If customer has REJECTED, DECLINED, or SAID NO: leadStatus MUST be "LOST" (score 0-20)
- Match your lead score to the appropriate stage's score range when possible

Respond ONLY with valid JSON (no markdown, no explanation):
{
  "summary": "3-5 sentence summary of conversation",
  "recommendedStage": "exact stage name from list above",
  "leadScore": 0-100,
  "leadStatus": "NEW|CONTACTED|QUALIFIED|PROPOSAL_SENT|NEGOTIATING|WON|LOST|UNRESPONSIVE",
  "confidence": 0-100,
  "reasoning": "brief explanation of stage choice and score"
}`;

    const modelToUse = getModelForOperation('complex');
    console.log(
      `[NVIDIA] Sending stage recommendation request - Model: ${modelToUse}, Stages: ${pipelineStages.length}`
    );

    const completion = await openai.chat.completions.create({
      model: modelToUse,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    console.log(
      `[NVIDIA] Received response - Choices: ${
        completion.choices?.length || 0
      }, Usage: ${JSON.stringify(completion.usage || {})}`
    );

    // Check for error in response (API returned error object)
    // Check if error property exists (even if empty string)
    if ('error' in completion && (completion as any).error !== undefined) {
      const errorMsg = (completion as any).error?.message || (completion as any).error || 'Unknown API error';
      console.error(`[NVIDIA] API returned error in stage recommendation response: ${errorMsg}. Full response:`, JSON.stringify(completion, null, 2));
      return null;
    }

    // Check if choices array exists and has items
    if (!completion.choices || completion.choices.length === 0) {
      console.error('[NVIDIA] No choices in response for stage recommendation. Full response:', JSON.stringify(completion, null, 2));
      return null;
    }

    const text = completion.choices[0]?.message?.content?.trim();
    if (!text) {
      console.error('[NVIDIA] No response content received. Full response:', JSON.stringify(completion, null, 2));
      return null;
    }
    
    // Parse JSON response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.error('[NVIDIA] No JSON found in response. Raw text:', text.substring(0, 200));
      return null;
    }
    
    const analysis = JSON.parse(jsonMatch[0]) as AIContactAnalysis;
    
    // Cache the result
    const { setCachedAnalysis, hashConversation } = await import('./conversation-cache');
    const hash = hashConversation([
      ...messages,
      ...pipelineStages.map(s => ({ from: 'system', text: JSON.stringify(s) }))
    ]);
    await setCachedAnalysis(hash, analysis).catch(() => {
      // Non-critical if caching fails
    });
    
    // Success will be recorded by caller with duration
    
    console.log(`[NVIDIA] ✅ Stage recommendation: ${analysis.recommendedStage} (confidence: ${analysis.confidence}%, score: ${analysis.leadScore})`);
    
    return analysis;
  } catch (error: unknown) {
    // Enhanced error logging
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorDetails = error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack?.split('\n').slice(0, 3).join('\n'),
    } : { raw: String(error) };
    
    console.error('[NVIDIA] ❌ Stage recommendation failed:', errorMessage);
    console.error('[NVIDIA] Error details:', JSON.stringify(errorDetails, null, 2));
    
      // Check if it's a rate limit error (429)
    if (errorMessage?.includes('429') || errorMessage?.includes('quota') || errorMessage?.includes('rate limit')) {
      const attemptNumber = keyAttempts + 1;
      if (attemptNumber < MAX_ATTEMPTS) {
        const backoffDelay = calculateExponentialBackoff(keyAttempts);
        console.warn(
          `[NVIDIA] Rate limit hit (stage recommendation), retrying (attempt ${attemptNumber + 1}/${MAX_ATTEMPTS}) after ${backoffDelay}ms (exponential backoff)...`
        );
        await sleep(backoffDelay);
        return analyzeConversationWithStageAndKey(
          apiKey,
          messages,
          pipelineStages,
          retries,
          keyAttempts + 1
        );
      }

      console.error('[NVIDIA] Rate limit persists for stage recommendation after multiple attempts');
      
      // Mark key as rate-limited in database if it came from there
      await apiKeyManager.markRateLimited(apiKey, { operation: 'analyzeConversationWithStageRecommendation' });
      
      // Try again if we have retries left (will get a different key from rotation)
      if (retries > 0) {
        const backoffDelay = calculateExponentialBackoff(0); // Reset backoff for new key
        await sleep(backoffDelay);
        return analyzeConversationWithStageRecommendation(messages, pipelineStages, retries - 1);
      }
      
      return null;
    }
    
    // Check for 401/403 authentication/authorization errors
    const errorStatus = (error as any)?.status || (error as any)?.response?.status || 
                       (errorMessage?.match(/(\d{3})\s+status/i)?.[1]);
    const statusCode = errorStatus || 
                      (errorMessage?.includes('403') ? 403 : errorMessage?.includes('401') ? 401 : null);
    
    const isAuthError = statusCode === 401 || 
                       statusCode === 403 ||
                       errorMessage?.includes('401') || 
                       errorMessage?.includes('403') ||
                       errorMessage?.includes('Forbidden') ||
                       errorMessage?.includes('No auth') || 
                       errorMessage?.includes('Unauthorized') || 
                       errorMessage?.includes('User not found');
    
    if (isAuthError) {
      const finalStatusCode = statusCode || (errorMessage?.includes('403') ? 403 : 401);
      console.error(`[NVIDIA] 🔐 Authentication failed (${finalStatusCode}) - Invalid or expired API key`);
      console.error('[NVIDIA] API key should start with "nvapi-" for NVIDIA API');
      console.error(`[NVIDIA] Current key prefix: ${apiKey.substring(0, 12)}...`);
      
      // Mark key as invalid in database if it came from there
      await apiKeyManager.markInvalid(apiKey, `NVIDIA API authentication failed (${finalStatusCode})`);
      
      // Try again if we have retries left (will get a different key from rotation)
      if (retries > 0) {
        console.log('[NVIDIA] Retrying with next available key...');
        return analyzeConversationWithStageRecommendation(messages, pipelineStages, retries - 1);
      }
      
      return null;
    }
    
    return null;
  }
}

// Generate personalized campaign message
export interface PersonalizedMessageContext {
  contactName: string;
  conversationHistory: Array<{ from: string; message: string; timestamp: string }>;
  templateMessage: string;
  customInstructions?: string;
}

export class GoogleAIService {
  async generatePersonalizedMessage(
    context: PersonalizedMessageContext,
    retries = 2
  ): Promise<string> {
    const apiKey = await getApiKey();
    if (!apiKey) {
      console.error('[NVIDIA] No API key available. Add one through Settings → API Keys or set NVIDIA_API_KEY environment variable.');
      // Fallback to template
      return context.templateMessage
        .replace(/\{firstName\}/g, context.contactName)
        .replace(/\{name\}/g, context.contactName);
    }

    try {
      const openai = createNvidiaClient(apiKey);

      const historyText = context.conversationHistory.length > 0
        ? context.conversationHistory
            .map((msg) => `${msg.from}: ${msg.message}`)
            .join('\n')
        : 'No previous conversation';

      const customInstructions = context.customInstructions
        ? `\n\nCustom Instructions: ${context.customInstructions}`
        : '';

      // If no template message, generate from scratch based on context
      const templateSection = context.templateMessage && context.templateMessage.trim()
        ? `Template Message: ${context.templateMessage}\n\n`
        : '';

      const prompt = templateSection
        ? `Generate a personalized follow-up message for ${context.contactName}.

${templateSection}Previous Conversation History:
${historyText}${customInstructions}

Create a natural, personalized version of the template message that:
1. References specific points from the conversation history (if available)
2. Feels personal and tailored to ${context.contactName}
3. Maintains the intent and key information from the template
4. Uses a conversational, friendly tone
5. Is concise and engaging (2-4 sentences)

Respond with ONLY the personalized message text (no JSON, no markdown, no explanation).`
        : `Generate a personalized follow-up message for ${context.contactName} based on their conversation history and context.

Previous Conversation History:
${historyText}${customInstructions}

Create a natural, personalized message that:
1. References specific points from the conversation history (if available)
2. Feels personal and tailored to ${context.contactName}
3. Uses a conversational, friendly tone
4. Is concise and engaging (2-4 sentences)
5. Provides value and encourages engagement

${customInstructions ? 'Follow the custom instructions provided above.' : ''}

Respond with ONLY the personalized message text (no JSON, no markdown, no explanation).`;

      const completion = await openai.chat.completions.create({
        model: MODEL,
        messages: [
          {
            role: 'user',
            content: prompt,
          },
        ],
      });

      // Check for error in response (API returned error object)
      // Check if error property exists (even if empty string)
      if ('error' in completion && (completion as any).error !== undefined) {
        const errorMsg = (completion as any).error?.message || (completion as any).error || 'Unknown API error';
        console.error(`[NVIDIA] API returned error in personalized message response: ${errorMsg}. Full response:`, JSON.stringify(completion, null, 2));
        // Fallback to template
        return context.templateMessage
          .replace(/\{firstName\}/g, context.contactName)
          .replace(/\{name\}/g, context.contactName);
      }

      // Check if choices array exists and has items
      if (!completion.choices || completion.choices.length === 0) {
        console.error('[NVIDIA] No choices in response for personalized message. Full response:', JSON.stringify(completion, null, 2));
        // Fallback to template
        return context.templateMessage
          .replace(/\{firstName\}/g, context.contactName)
          .replace(/\{name\}/g, context.contactName);
      }

      const personalizedMessage = completion.choices[0]?.message?.content?.trim();
      if (!personalizedMessage) {
        console.error('[NVIDIA] No response content received');
        // Fallback to template
        return context.templateMessage
          .replace(/\{firstName\}/g, context.contactName)
          .replace(/\{name\}/g, context.contactName);
      }

      console.log(`[NVIDIA] Generated personalized message for ${context.contactName}`);
      
      return personalizedMessage;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage?.includes('429') || errorMessage?.includes('quota') || errorMessage?.includes('rate limit')) {
        const backoffDelay = calculateExponentialBackoff(0); // Use base delay for personalization retries
        console.warn(
          `[NVIDIA] Rate limit hit (personalization), retrying after ${backoffDelay}ms (exponential backoff)...`
        );

        if (retries > 0) {
          await sleep(backoffDelay);
          return this.generatePersonalizedMessage(context, retries - 1);
        }

        console.error('[NVIDIA] Rate limit persists after multiple attempts');
      } else {
        // Check for 401/403 authentication/authorization errors
        const isAuthError = errorMessage?.includes('401') || 
                           errorMessage?.includes('403') ||
                           errorMessage?.includes('Forbidden') ||
                           errorMessage?.includes('No auth') || 
                           errorMessage?.includes('Unauthorized') || 
                           (error instanceof Error && 'status' in error && (error.status === 401 || error.status === 403));
        
        if (isAuthError) {
          const statusCode = (error as any)?.status || (errorMessage?.includes('403') ? 403 : 401);
          console.error(`[NVIDIA] 🔐 Authentication failed (${statusCode}) - Invalid or expired API key`);
          
          // Get API key to mark as invalid
          const apiKey = await getApiKey();
          if (apiKey) {
            await apiKeyManager.markInvalid(apiKey, `NVIDIA API authentication failed (${statusCode})`);
          }
        } else {
          console.error('[NVIDIA] Personalization failed:', errorMessage);
        }
      }

      // Fallback to template
      return context.templateMessage
        .replace(/\{firstName\}/g, context.contactName)
        .replace(/\{name\}/g, context.contactName);
    }
  }
}
