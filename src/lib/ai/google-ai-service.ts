import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';
import { executeAIRequest, getTimeoutForOperation, getPriorityForOperation } from './ai-request-wrapper';
import { RequestPriority } from './request-queue';
import { rateTracker } from './rate-tracker';

const MAX_ATTEMPTS = 3;
const BASE_RETRY_DELAY_MS = 500; // Base delay: 500ms (optimized for speed)
const MAX_RETRY_DELAY_MS = 2000; // Max delay: 2 seconds (optimized for speed)

// Model configuration - using 120B model for all operations
const MODEL = process.env.AI_PRIMARY_MODEL || 'openai/gpt-oss-120b';

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
  // CRITICAL: Check environment variable first if USE_ENV_API_KEY is set
  // This allows forcing env var usage when database keys are problematic
  if (process.env.USE_ENV_API_KEY === 'true') {
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    if (envKey) {
      console.log(`[NVIDIA] ✅ Using environment variable API key (forced via USE_ENV_API_KEY)`);
      return envKey;
    }
  }
  
  try {
    // Try database first (preferred method - can be managed through UI)
    const dbKey = await apiKeyManager.getNextKey(requestContext);
    if (dbKey) {
      console.log(`[NVIDIA] ✅ API key retrieved from database (operation: ${requestContext?.operation || 'unknown'})`);
      return dbKey;
    }
    
    console.warn('[NVIDIA] ⚠️ No API key from database, checking environment variables...');
    // Fall back to environment variables if no database keys available
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    if (envKey) {
      console.warn('[NVIDIA] ⚠️ Using environment variable API key (database keys not available)');
      return envKey;
    }
    
    console.error('[NVIDIA] ❌ No API key available from database or environment variables');
    return null;
  } catch (keyError) {
    const errorMsg = keyError instanceof Error ? keyError.message : String(keyError);
    console.error(`[NVIDIA] ❌ Error retrieving API key: ${errorMsg}`);
    console.error(`[NVIDIA] ❌ Error stack:`, keyError instanceof Error ? keyError.stack?.split('\n').slice(0, 5).join('\n') : 'No stack');
    
    // Try environment variable as fallback even on error
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    if (envKey) {
      console.warn('[NVIDIA] ⚠️ Using environment variable API key after database error');
      return envKey;
    }
    
    return null;
  }
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
export interface AnalyzeConversationResult {
  summary: string;
  comprehensiveAnalysis?: any; // Full comprehensive format if available
}

export async function analyzeConversation(
  messages: Array<{
    from: string;
    text: string;
    timestamp?: Date;
  }>,
  retries = 2,
  context?: { contactId?: string; conversationId?: string },
  returnComprehensive = false // New parameter to return full comprehensive format
): Promise<string | AnalyzeConversationResult | null> {
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
    // Use 120B model for all analysis operations
    const result = await executeAIRequest(
      () => analyzeConversationWithKey(apiKey, messages, retries, 0, MODEL, returnComprehensive),
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
      return analyzeConversation(messages, retries - 1, context, returnComprehensive);
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
  modelOverride?: string,
  returnComprehensive = false // New parameter to return full comprehensive format
): Promise<string | AnalyzeConversationResult | null> {
  const modelToUse = modelOverride || MODEL;
  const requestId = `req-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const startTime = Date.now();
  
  // Log request start with rate tracking
  const keyId = apiKey.substring(0, 16);
  const estimatedTokens = Math.min(messages.length * 100, 8000); // Rough estimate
  rateTracker.logRequestStart({
    keyId,
    operation: 'analyzeConversation',
    priority: 'NORMAL',
    tokens: estimatedTokens,
    reqId: requestId,
  });
  
  try {
    const openai = createNvidiaClient(apiKey);

    // Format conversation for AI
    const conversationText = messages
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');

    const prompt = `Analyze this customer conversation THOROUGHLY and extract ALL available information. Return ONLY a valid JSON object. Start your response with { and end with }. Do NOT include any explanations, instructions, reasoning, or text outside the JSON object.

CRITICAL: Your response must be ONLY the JSON object. No text before {. No text after }. No markdown. No code blocks. Just the raw JSON.

IMPORTANT ANALYSIS REQUIREMENTS:
- Read the ENTIRE conversation carefully and extract EVERY detail mentioned
- Extract ALL specific information: names, numbers, dates, prices, quantities, locations, contact details
- Extract ALL buying signals, objections, pain points, preferences, goals, and needs mentioned
- Extract ALL key topics, decisions, questions, and information provided
- Extract ALL product/service interests, competitors mentioned, and risk factors
- Extract ALL green flags (positive indicators) and red flags (concerns)
- Extract ALL upsell opportunities and conversation tips
- Infer values when not explicitly stated (e.g., if customer asks about price, budgetIndicated should be true)
- Analyze message patterns to determine engagement metrics (response time, frequency, depth)
- Determine customer intent based on their questions and statements
- Assess authority level from their decision-making language
- Calculate scores based on actual conversation content, not defaults
- Be SPECIFIC: Instead of "Product interest", extract actual product names mentioned
- Be COMPREHENSIVE: Extract ALL instances (if 3 products mentioned, list all 3)

Conversation:
${conversationText}

Return this JSON structure (executiveSummary must be 2-3 sentences, 50-100 words). Fill ALL fields with actual data from the conversation:

{
  "executiveSummary": "2-3 sentence (50-100 word) brief executive summary covering: high-level opportunity overview, key buying signals or concerns, and immediate next step. Include only the most critical details like key names, numbers, or decisions. Keep it very short and focused.",
  "conversationAnalysis": {
    "mainTopic": "Primary subject of conversation (be specific, extract actual topic mentioned)",
    "keyTopics": ["Extract ALL topics mentioned - be specific with actual names/subjects"],
    "keyPoints": ["Extract ALL important points discussed - include specific details, numbers, names"],
    "decisionsMade": ["Extract ALL decisions made - include who decided what and when"],
    "questionsAsked": ["Extract ALL questions asked - include the actual questions"],
    "informationProvided": ["Extract ALL information shared - include specific details, numbers, dates"]
  },
  "customerInsights": {
    "customerIntent": "What they want (BROWSING|INQUIRING|EVALUATING|READY_TO_BUY|PURCHASING)",
    "customerNeeds": ["Extract ALL needs mentioned - be specific with actual needs stated"],
    "customerGoals": ["Extract ALL goals mentioned - include specific goals and objectives"],
    "painPoints": ["Extract ALL pain points mentioned - include specific problems and challenges"],
    "preferences": ["Extract ALL preferences mentioned - include specific likes, dislikes, requirements"],
    "budgetIndicated": true/false,
    "timelineIndicated": true/false,
    "authorityLevel": "DECISION_MAKER|INFLUENCER|END_USER|GATEKEEPER"
  },
  "engagementMetrics": {
    "engagementLevel": "LOW|MEDIUM|HIGH|VERY_HIGH",
    "responseTime": "FAST|NORMAL|SLOW",
    "messageFrequency": "LOW|MEDIUM|HIGH",
    "conversationDepth": "SURFACE|MODERATE|DEEP",
    "sentiment": "POSITIVE|NEUTRAL|NEGATIVE|MIXED",
    "tone": "FRIENDLY|PROFESSIONAL|CASUAL|FORMAL|FRUSTRATED"
  },
  "businessIntelligence": {
    "buyingSignals": ["Extract ALL buying signals - include specific indicators like 'ready to buy', 'need it soon', price discussions, etc."],
    "objections": ["Extract ALL objections raised - include specific concerns and hesitations"],
    "competitorsMentioned": ["Extract ALL competitor names mentioned - include actual company/product names"],
    "priceSensitivity": "LOW|MEDIUM|HIGH",
    "productInterest": ["Extract ALL products/services mentioned - include actual product names, features, or services"],
    "conversionProbability": 0-100,
    "riskFactors": ["Extract ALL risk factors - include specific concerns, red flags, or potential issues"],
    "opportunitySize": "SMALL|MEDIUM|LARGE|ENTERPRISE"
  },
  "scoring": {
    "leadScore": 0-100,
    "confidence": 0-100,
    "fitScore": 0-100,
    "engagementScore": 0-100,
    "urgencyScore": 0-100
  },
  "pipelineRecommendation": {
    "recommendedStage": "New Lead",
    "leadStatus": "NEW|CONTACTED|QUALIFIED|PROPOSAL_SENT|NEGOTIATING|WON|LOST|UNRESPONSIVE",
    "stageReason": "Why this stage was chosen",
    "nextStage": "What comes next",
    "estimatedCloseDate": null
  },
  "actionItems": {
    "immediateActions": ["Action 1"],
    "followUpActions": ["Action 1"],
    "nextBestAction": "Primary action to take",
    "bestReply": "Suggested response message",
    "followUpMessage": "Suggested follow-up",
    "deadline": null
  },
  "greenFlags": ["Flag 1", "Flag 2"],
  "redFlags": ["Flag 1", "Flag 2"],
  "upsellOpportunities": ["Opportunity 1", "Opportunity 2"],
  "conversationTips": ["Tip 1", "Tip 2"],
  "objectionHandling": ["Rebuttal 1", "Rebuttal 2"],
  "reasoning": "Detailed explanation with specific conversation citations, behavioral patterns, and strategic insights"
}

CRITICAL REQUIREMENTS:
1. Your response MUST start with { and end with }
2. Your response MUST be valid JSON that can be parsed by JSON.parse()
3. Do NOT include any text, explanations, or instructions outside the JSON
4. Do NOT use markdown formatting or code block syntax
5. Do NOT explain your reasoning or thought process
6. executiveSummary: 2-3 sentences (50-100 words), brief and focused
7. All arrays must have at least 1-3 items (use [] if none)
8. Fill ALL fields with actual data from the conversation - DO NOT use UNKNOWN or defaults unless truly unavailable
9. For customerIntent: Analyze their questions and statements to determine intent (BROWSING|INQUIRING|EVALUATING|READY_TO_BUY|PURCHASING)
10. For authorityLevel: Determine from their decision-making language (DECISION_MAKER|INFLUENCER|END_USER|GATEKEEPER)
11. For engagementMetrics: Calculate from message patterns (response times, frequency, depth, sentiment, tone)
12. For budgetIndicated: Set to true if they mention price, cost, budget, affordability, or payment
13. For timelineIndicated: Set to true if they mention when, deadline, urgent, soon, or time-related terms
14. For priceSensitivity: Determine from their reactions to pricing discussions (LOW|MEDIUM|HIGH)
15. For opportunitySize: Assess from their business context, order size, or scale mentioned (SMALL|MEDIUM|LARGE|ENTERPRISE)
16. Extract ALL buying signals, objections, pain points, and preferences mentioned - be SPECIFIC with actual details
17. Extract ALL names, numbers, dates, prices, quantities, locations, and contact information mentioned
18. Extract ALL product/service names, features, and specifications discussed
19. Extract ALL company names, business names, and organization details mentioned
20. Calculate scores (leadScore, confidence, fitScore, engagementScore, urgencyScore) based on actual conversation content
21. Provide specific, actionable recommendations based on the conversation with actual details
22. DO NOT use generic placeholders like "Topic 1", "Need 1", "Product 1" - extract ACTUAL information from the conversation
23. If information is mentioned multiple times, extract ALL instances
24. Be THOROUGH - leave no detail unextracted
25. For arrays: Extract ALL items mentioned, not just 1-2 examples

Remember: Start with {, end with }, nothing else. Extract ALL information - do not leave fields as UNKNOWN unless truly impossible to determine.`;

    console.log(
      `[NVIDIA] Sending request - Model: ${modelToUse}, Messages: ${messages.length}`
    );

    const completion = await openai.chat.completions.create({
      model: modelToUse,
      messages: [
        {
          role: 'system',
          content: 'You are a JSON-only output AI. You MUST respond with ONLY valid JSON objects. Never include explanations, instructions, or reasoning. Your response must start with { and end with }.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.2, // Lower temperature for more consistent JSON output
      max_tokens: 8000, // Increased to accommodate full comprehensive format JSON (was 5000, causing truncation)
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

    const text = completion.choices[0]?.message?.content?.trim() || (completion.choices[0]?.message as any)?.reasoning_content?.trim();
    if (!text) {
      console.error('[NVIDIA] No response content received. Full response:', JSON.stringify(completion, null, 2));
      return null;
    }
    
    // Log response length and preview for debugging
    console.log(`[NVIDIA] Response received: ${text.length} characters`);
    console.log(`[NVIDIA] Response preview (first 200 chars):`, text.substring(0, 200));
    console.log(`[NVIDIA] Response preview (last 200 chars):`, text.substring(Math.max(0, text.length - 200)));
    
    // Check if response starts with JSON (ideal case)
    const startsWithJson = text.trim().startsWith('{');
    const endsWithJson = text.trim().endsWith('}');
    console.log(`[NVIDIA] Response format check - Starts with { : ${startsWithJson}, Ends with } : ${endsWithJson}`);
    
    // Check if response looks like instructions/prompt (common issue with reasoning models)
    const instructionIndicators = [
      'We need to parse',
      'We need to produce',
      'Now we need to',
      'Let\'s fill',
      'Now fill',
      'Now produce',
      'Now ensure',
      'Now check',
      'Now we need to ensure',
      'Now we need to produce',
      'Now we need to fill',
      'Now we need to craft',
      'Now we need to write',
      'Now we need to double-check',
      'Now we need to verify',
      'Interpretation:',
      'Conversation lines:',
      'Thus the conversation',
      'Now we need to produce JSON',
    ];
    
    const looksLikeInstructions = instructionIndicators.some(indicator => 
      text.toLowerCase().includes(indicator.toLowerCase())
    );
    
    if (looksLikeInstructions) {
      console.warn('[NVIDIA] ⚠️ Response appears to contain instructions instead of JSON. Attempting to extract JSON...');
      // Try to extract JSON that might be embedded in the instructions
    }
    
    // Parse JSON response with robust strategy (same as stage recommendation)
    let comprehensiveAnalysis: any = null;
    let jsonText = '';

    // Strategy 1: Find the LAST valid JSON object (handles reasoning chains)
    // Also handle truncated JSON (response cut off mid-JSON)
    const firstBrace = text.indexOf('{');
    const lastBrace = text.lastIndexOf('}');
    
    if (firstBrace !== -1) {
      // If we have a starting brace but no ending brace, JSON was truncated
      if (lastBrace === -1 || lastBrace < firstBrace) {
        console.warn('[NVIDIA] ⚠️ JSON appears truncated (starts with { but no closing }). Attempting to fix...');
        
        // Try to find where the JSON should end and close it
        let jsonCandidate = text.substring(firstBrace);
        
        // Count braces to see how many we need to close
        let openBraces = (jsonCandidate.match(/\{/g) || []).length;
        let closeBraces = (jsonCandidate.match(/\}/g) || []).length;
        const missingBraces = openBraces - closeBraces;
        
        if (missingBraces > 0) {
          // Find the last complete key-value pair or array element
          // Work backwards to find where we can safely close
          let safeCloseIndex = jsonCandidate.length;
          
          // Find the last quote, comma, or bracket that suggests a complete value
          for (let i = jsonCandidate.length - 1; i >= 0; i--) {
            const char = jsonCandidate[i];
            // If we find a quote, comma, bracket, or brace, we might be able to close after it
            if (char === '"' || char === ',' || char === ']' || char === '}') {
              // Check if this looks like a complete value
              let inString = false;
              let quoteCount = 0;
              for (let j = 0; j <= i; j++) {
                if (jsonCandidate[j] === '"' && (j === 0 || jsonCandidate[j-1] !== '\\')) {
                  inString = !inString;
                  quoteCount++;
                }
              }
              
              // If quotes are balanced up to this point, we can try closing here
              if (quoteCount % 2 === 0) {
                safeCloseIndex = i + 1;
                break;
              }
            }
          }
          
          // Close all open structures
          let fixedJson = jsonCandidate.substring(0, safeCloseIndex);
          
          // Close unterminated strings first
          const quotes = [...fixedJson.matchAll(/(?<!\\)"/g)];
          if (quotes.length % 2 !== 0) {
            fixedJson += '"';
          }
          
          // Close arrays
          const openBrackets = (fixedJson.match(/\[/g) || []).length;
          const closeBrackets = (fixedJson.match(/\]/g) || []).length;
          fixedJson += ']'.repeat(openBrackets - closeBrackets);
          
          // Close objects
          fixedJson += '}'.repeat(missingBraces);
          
          // Remove trailing commas before closing braces
          fixedJson = fixedJson.replace(/,(\s*[}\]])/g, '$1');
          
          try {
            comprehensiveAnalysis = JSON.parse(fixedJson);
            console.log('[NVIDIA] ✅ Fixed truncated JSON and parsed successfully');
          } catch (truncateError) {
            console.warn('[NVIDIA] ⚠️ Could not fix truncated JSON, will try other strategies');
          }
        }
      } else {
        // Normal case: we have both opening and closing braces
        let depth = 0;
        let foundFirstBrace = -1;
        for (let i = lastBrace; i >= 0; i--) {
          if (text[i] === '}') depth++;
          if (text[i] === '{') {
            depth--;
            if (depth === 0) {
              foundFirstBrace = i;
              break;
            }
          }
        }
        
        if (foundFirstBrace !== -1) {
           try {
             jsonText = text.substring(foundFirstBrace, lastBrace + 1);
             comprehensiveAnalysis = JSON.parse(jsonText);
             // Validate it's actually JSON data, not instructions
             if (comprehensiveAnalysis && typeof comprehensiveAnalysis === 'object' && 
                 !comprehensiveAnalysis.executiveSummary && !comprehensiveAnalysis.conversationAnalysis &&
                 !comprehensiveAnalysis.summary && Object.keys(comprehensiveAnalysis).length === 0) {
               comprehensiveAnalysis = null; // Reject empty or invalid objects
             }
           } catch {
             // Failed
           }
        }
      }
    }

    // Strategy 2: Strict regex extraction fallback (also handles truncated JSON)
    if (!comprehensiveAnalysis) {
        // Try to find JSON that might be truncated (starts with { but doesn't end with })
        const jsonStart = text.indexOf('{');
        if (jsonStart !== -1) {
          let jsonCandidate = text.substring(jsonStart);
          
          // Check if it's truncated (doesn't end with })
          const endsWithBrace = jsonCandidate.trim().endsWith('}');
          
          if (!endsWithBrace) {
            // JSON is truncated - try to fix it
            console.warn('[NVIDIA] ⚠️ JSON appears truncated in Strategy 2, attempting to fix...');
            
            // Count braces to see how many we need to close
            let openBraces = (jsonCandidate.match(/\{/g) || []).length;
            let closeBraces = (jsonCandidate.match(/\}/g) || []).length;
            const missingBraces = openBraces - closeBraces;
            
            if (missingBraces > 0) {
              // Find a safe place to close (after last complete value)
              let safeCloseIndex = jsonCandidate.length;
              
              // Remove any trailing incomplete content
              // Look for the last complete key-value pair
              const lastColon = jsonCandidate.lastIndexOf(':');
              if (lastColon > 0) {
                // Find the last complete value (ends with quote, number, true/false/null, or closing bracket/brace)
                for (let i = jsonCandidate.length - 1; i > lastColon; i--) {
                  const char = jsonCandidate[i];
                  if (char === '"' || char === ']' || char === '}' || 
                      /[0-9]/.test(char) || jsonCandidate.substring(i).match(/^(true|false|null)/)) {
                    safeCloseIndex = i + 1;
                    break;
                  }
                }
              }
              
              let fixedJson = jsonCandidate.substring(0, safeCloseIndex);
              
              // Close unterminated strings
              const quotes = [...fixedJson.matchAll(/(?<!\\)"/g)];
              if (quotes.length % 2 !== 0) {
                fixedJson += '"';
              }
              
              // Close arrays
              const openBrackets = (fixedJson.match(/\[/g) || []).length;
              const closeBrackets = (fixedJson.match(/\]/g) || []).length;
              fixedJson += ']'.repeat(openBrackets - closeBrackets);
              
              // Close objects
              fixedJson += '}'.repeat(missingBraces);
              
              // Remove trailing commas
              fixedJson = fixedJson.replace(/,(\s*[}\]])/g, '$1');
              
              try {
                comprehensiveAnalysis = JSON.parse(fixedJson);
                console.log('[NVIDIA] ✅ Fixed truncated JSON in Strategy 2 and parsed successfully');
              } catch (truncateError) {
                // Continue to try regex match
              }
            }
          } else {
            // Normal case: try regex match
            const jsonMatch = text.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                try {
                    jsonText = jsonMatch[0];
                    comprehensiveAnalysis = JSON.parse(jsonText);
                    // Validate it's actually JSON data
                    if (comprehensiveAnalysis && typeof comprehensiveAnalysis === 'object' && 
                        !comprehensiveAnalysis.executiveSummary && !comprehensiveAnalysis.conversationAnalysis &&
                        !comprehensiveAnalysis.summary && Object.keys(comprehensiveAnalysis).length === 0) {
                      comprehensiveAnalysis = null;
                    }
                } catch (parseError) {
                    console.error('[NVIDIA] Failed to parse JSON via regex match, trying to fix malformed JSON...');
                    
                    // Try to fix common JSON issues
                    try {
                      let fixedJson = jsonMatch[0];
                      
                      // Fix unterminated strings by finding and closing them
                      const quoteMatches = [...fixedJson.matchAll(/(?<!\\)"/g)];
                      if (quoteMatches.length % 2 !== 0) {
                        // Odd number of quotes - unterminated string
                        const lastQuoteIndex = fixedJson.lastIndexOf('"');
                        if (lastQuoteIndex > 0) {
                          // Find where to close the string (before next } or ,)
                          for (let i = lastQuoteIndex + 1; i < fixedJson.length; i++) {
                            if (fixedJson[i] === '}' || fixedJson[i] === ',' || fixedJson[i] === '\n') {
                              fixedJson = fixedJson.substring(0, i) + '"' + fixedJson.substring(i);
                              break;
                            }
                          }
                        }
                      }
                      
                      // Remove trailing commas
                      fixedJson = fixedJson.replace(/,(\s*[}\]])/g, '$1');
                      
                      // Try parsing again
                      comprehensiveAnalysis = JSON.parse(fixedJson);
                      console.log('[NVIDIA] ✅ Fixed malformed JSON and parsed successfully');
                    } catch (fixError) {
                      console.error('[NVIDIA] ❌ Could not fix malformed JSON:', fixError instanceof Error ? fixError.message : String(fixError));
                    }
                }
            }
          }
        }
    }
    
    // Strategy 3: Try to extract JSON from multiple potential locations (even if buried in instructions)
    if (!comprehensiveAnalysis) {
      // Look for ALL JSON blocks that might be embedded in instructions
      // Use a more aggressive regex that handles nested objects
      const jsonBlocks = text.match(/\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/g);
      if (jsonBlocks && jsonBlocks.length > 0) {
        console.log(`[NVIDIA] Found ${jsonBlocks.length} potential JSON blocks, trying to extract...`);
        // Try each block from last to first (usually the final output is last)
        for (let i = jsonBlocks.length - 1; i >= 0; i--) {
          try {
            let block = jsonBlocks[i];
            // Remove trailing commas
            let cleaned = block.replace(/,(\s*[}\]])/g, '$1');
            
            // Try to fix common issues
            // Fix unterminated strings
            const quoteMatches = [...cleaned.matchAll(/(?<!\\)"/g)];
            if (quoteMatches.length % 2 !== 0) {
              const lastQuoteIndex = cleaned.lastIndexOf('"');
              if (lastQuoteIndex > 0) {
                for (let j = lastQuoteIndex + 1; j < cleaned.length; j++) {
                  if (cleaned[j] === '}' || cleaned[j] === ',' || cleaned[j] === '\n') {
                    cleaned = cleaned.substring(0, j) + '"' + cleaned.substring(j);
                    break;
                  }
                }
              }
            }
            
            const parsed = JSON.parse(cleaned);
            if (parsed && typeof parsed === 'object') {
              // Check if it has the expected structure
              const hasExpectedKeys = parsed.executiveSummary || parsed.conversationAnalysis || 
                                     parsed.scoring || parsed.businessIntelligence || 
                                     parsed.customerInsights || parsed.pipelineRecommendation;
              
              if (hasExpectedKeys) {
                comprehensiveAnalysis = parsed;
                console.log(`[NVIDIA] ✅ Extracted valid JSON from block ${i + 1}/${jsonBlocks.length}`);
                break;
              }
            }
          } catch (parseError) {
            // Continue to next block
            continue;
          }
        }
      }
      
      // Strategy 4: If still no JSON, try to find the largest JSON-like structure
      if (!comprehensiveAnalysis) {
        // Find the largest block that starts with { and try to extract it
        const firstBrace = text.indexOf('{');
        const lastBrace = text.lastIndexOf('}');
        
        if (firstBrace >= 0 && lastBrace > firstBrace) {
          let candidate = text.substring(firstBrace, lastBrace + 1);
          
          // Try to fix it progressively
          try {
            // Remove trailing commas
            candidate = candidate.replace(/,(\s*[}\]])/g, '$1');
            
            // Try to close unterminated strings
            const quotes = [...candidate.matchAll(/(?<!\\)"/g)];
            if (quotes.length % 2 !== 0) {
              const lastQuote = candidate.lastIndexOf('"');
              if (lastQuote > 0) {
                for (let i = lastQuote + 1; i < candidate.length; i++) {
                  if (candidate[i] === '}' || candidate[i] === ',' || candidate[i] === '\n') {
                    candidate = candidate.substring(0, i) + '"' + candidate.substring(i);
                    break;
                  }
                }
              }
            }
            
            const parsed = JSON.parse(candidate);
            if (parsed && typeof parsed === 'object' && Object.keys(parsed).length > 0) {
              comprehensiveAnalysis = parsed;
              console.log('[NVIDIA] ✅ Extracted JSON using largest block strategy');
            }
          } catch {
            // Failed
          }
        }
      }
    }
    
    // Strategy 5: Final attempt - look for JSON at the very end of the response
    // Sometimes the AI puts instructions first, then JSON at the end
    if (!comprehensiveAnalysis) {
      // Find the last occurrence of a complete JSON object
      // Work backwards from the end to find where a valid JSON object might start
      const lines = text.split('\n');
      let jsonStartIndex = -1;
      let jsonEndIndex = -1;
      
      // Look for the last line that starts with {
      for (let i = lines.length - 1; i >= 0; i--) {
        const trimmed = lines[i].trim();
        if (trimmed.startsWith('{')) {
          jsonStartIndex = text.indexOf(lines[i]);
          // Try to find the matching closing brace
          let braceCount = 0;
          let foundEnd = false;
          for (let j = jsonStartIndex; j < text.length; j++) {
            if (text[j] === '{') braceCount++;
            if (text[j] === '}') {
              braceCount--;
              if (braceCount === 0) {
                jsonEndIndex = j;
                foundEnd = true;
                break;
              }
            }
          }
          
          if (foundEnd && jsonEndIndex > jsonStartIndex) {
            try {
              let candidate = text.substring(jsonStartIndex, jsonEndIndex + 1);
              // Clean it up
              candidate = candidate.replace(/,(\s*[}\]])/g, '$1');
              
              // Fix unterminated strings
              const quotes = [...candidate.matchAll(/(?<!\\)"/g)];
              if (quotes.length % 2 !== 0) {
                const lastQuote = candidate.lastIndexOf('"');
                if (lastQuote > 0) {
                  for (let k = lastQuote + 1; k < candidate.length; k++) {
                    if (candidate[k] === '}' || candidate[k] === ',' || candidate[k] === '\n') {
                      candidate = candidate.substring(0, k) + '"' + candidate.substring(k);
                      break;
                    }
                  }
                }
              }
              
              const parsed = JSON.parse(candidate);
              if (parsed && typeof parsed === 'object' && 
                  (parsed.executiveSummary || parsed.conversationAnalysis || parsed.scoring)) {
                comprehensiveAnalysis = parsed;
                console.log('[NVIDIA] ✅ Extracted JSON from end of response');
                break;
              }
            } catch {
              // Continue searching
            }
          }
        }
      }
    }
    
    // If we detected instructions and still no valid JSON, reject the response
    if (looksLikeInstructions && !comprehensiveAnalysis) {
      console.error('[NVIDIA] ❌ Response contains instructions but no valid JSON found. Rejecting response.');
      console.error('[NVIDIA] Response preview (first 1000 chars):', text.substring(0, 1000));
      console.error('[NVIDIA] Response preview (last 1000 chars):', text.substring(Math.max(0, text.length - 1000)));
      return null;
    }

    // Post-process comprehensiveAnalysis to ensure executiveSummary is always a plain string
    if (comprehensiveAnalysis && comprehensiveAnalysis.executiveSummary) {
      // CRITICAL: Ensure executiveSummary is a plain string, not a JSON string
      if (typeof comprehensiveAnalysis.executiveSummary === 'string') {
        const execSum = comprehensiveAnalysis.executiveSummary.trim();
        // Check if it's a JSON string (starts with { or [)
        if (execSum.startsWith('{') || execSum.startsWith('[')) {
          try {
            const parsed = JSON.parse(execSum);
            // If it parsed, extract the actual text
            if (parsed && typeof parsed === 'object') {
              // It's a JSON object - extract executiveSummary or summary from it
              comprehensiveAnalysis.executiveSummary = parsed.executiveSummary || parsed.summary || text.substring(0, 200);
              console.log('[NVIDIA] ✅ Fixed double-encoded executiveSummary (extracted from JSON string)');
            } else if (typeof parsed === 'string') {
              // It's a JSON string containing a string - use the parsed value
              comprehensiveAnalysis.executiveSummary = parsed;
              console.log('[NVIDIA] ✅ Fixed double-encoded executiveSummary (unwrapped JSON string)');
            }
          } catch {
            // Not valid JSON - might be truncated or malformed
            // Try to extract text if it looks like it contains "executiveSummary"
            if (execSum.includes('"executiveSummary"')) {
              const match = execSum.match(/"executiveSummary"\s*:\s*"((?:[^"\\]|\\.)*)"/);
              if (match && match[1]) {
                comprehensiveAnalysis.executiveSummary = match[1].replace(/\\"/g, '"').replace(/\\n/g, '\n');
                console.log('[NVIDIA] ✅ Extracted executiveSummary from malformed JSON string');
              }
            }
          }
        }
      }
    }
    
    // Extract executiveSummary from comprehensive format
    let summary: string;
    if (comprehensiveAnalysis && comprehensiveAnalysis.executiveSummary) {
      summary = comprehensiveAnalysis.executiveSummary;
      console.log(`[NVIDIA] ✅ Extracted executiveSummary from comprehensive format (${summary.length} chars)`);
    } else if (comprehensiveAnalysis && comprehensiveAnalysis.summary) {
      // Fallback to summary if executiveSummary not found
      summary = comprehensiveAnalysis.summary;
      console.log(`[NVIDIA] ✅ Extracted summary from comprehensive format (${summary.length} chars)`);
    } else {
      // Fallback to raw text if JSON parsing failed (backward compatibility)
      summary = text;
      console.warn(`[NVIDIA] ⚠️ Could not parse comprehensive format, using raw text (${summary.length} chars)`);
    }
    
    // Cache the result
    const { setCachedAnalysis, hashConversation } = await import('./conversation-cache');
    const hash = hashConversation(messages);
    await setCachedAnalysis(hash, {
      summary,
      recommendedStage: comprehensiveAnalysis?.pipelineRecommendation?.recommendedStage || 'New Lead',
      leadScore: comprehensiveAnalysis?.scoring?.leadScore ?? 50,
      leadStatus: comprehensiveAnalysis?.pipelineRecommendation?.leadStatus || 'NEW',
      confidence: comprehensiveAnalysis?.scoring?.confidence ?? 80,
      reasoning: comprehensiveAnalysis?.reasoning || 'Cached conversation analysis',
      // Include comprehensive fields if available
      executiveSummary: comprehensiveAnalysis?.executiveSummary,
      conversationAnalysis: comprehensiveAnalysis?.conversationAnalysis,
      customerInsights: comprehensiveAnalysis?.customerInsights,
      engagementMetrics: comprehensiveAnalysis?.engagementMetrics,
      businessIntelligence: comprehensiveAnalysis?.businessIntelligence,
      actionItems: comprehensiveAnalysis?.actionItems,
      greenFlags: comprehensiveAnalysis?.greenFlags,
      redFlags: comprehensiveAnalysis?.redFlags,
      upsellOpportunities: comprehensiveAnalysis?.upsellOpportunities,
      conversationTips: comprehensiveAnalysis?.conversationTips,
      objectionHandling: comprehensiveAnalysis?.objectionHandling,
    }).catch(() => {
      // Non-critical if caching fails
    });
    
    // Success will be recorded by caller with duration
    
    // Log success with rate tracking
    const elapsedMs = Date.now() - startTime;
    rateTracker.logRequestComplete({
      keyId,
      operation: 'analyzeConversation',
      elapsedMs,
      success: true,
      reqId: requestId,
    });
    
    console.log(`[NVIDIA] ✅ Generated comprehensive analysis summary (${summary.length} chars)`);
    
    // If returnComprehensive is true, return both summary and full comprehensive format
    if (returnComprehensive) {
      if (comprehensiveAnalysis) {
        // Validate that comprehensiveAnalysis has the expected structure
        const hasRequiredFields = !!(
          comprehensiveAnalysis.executiveSummary ||
          comprehensiveAnalysis.conversationAnalysis ||
          comprehensiveAnalysis.customerInsights ||
          comprehensiveAnalysis.engagementMetrics ||
          comprehensiveAnalysis.businessIntelligence ||
          comprehensiveAnalysis.scoring ||
          comprehensiveAnalysis.pipelineRecommendation ||
          comprehensiveAnalysis.actionItems ||
          Array.isArray(comprehensiveAnalysis.greenFlags) ||
          Array.isArray(comprehensiveAnalysis.redFlags) ||
          Array.isArray(comprehensiveAnalysis.upsellOpportunities) ||
          comprehensiveAnalysis.reasoning
        );
        
        if (hasRequiredFields) {
          console.log('[NVIDIA] ✅ Returning comprehensive format with all sections');
          return {
            summary: summary.trim(),
            comprehensiveAnalysis,
          };
        } else {
          console.warn('[NVIDIA] ⚠️ Comprehensive format parsed but missing required fields. Available keys:', Object.keys(comprehensiveAnalysis));
          // Still return it, but log a warning
          return {
            summary: summary.trim(),
            comprehensiveAnalysis: {
              executiveSummary: comprehensiveAnalysis.executiveSummary || summary.trim(),
              ...comprehensiveAnalysis, // Include whatever fields are available
            },
          };
        }
      } else {
        // If comprehensive analysis parsing failed, return summary wrapped in comprehensive format
        console.warn('[NVIDIA] ⚠️ Comprehensive format requested but parsing failed, returning summary in comprehensive structure');
        return {
          summary: summary.trim(),
          comprehensiveAnalysis: {
            executiveSummary: summary.trim(),
            summary: summary.trim(),
          },
        };
      }
    }
    
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
    
    // Log failure with rate tracking
    const elapsedMs = Date.now() - startTime;
    rateTracker.logRequestComplete({
      keyId,
      operation: 'analyzeConversation',
      elapsedMs,
      success: false,
      errorCode: errorStatus ? String(errorStatus) : undefined,
      retryCount: keyAttempts,
      reqId: requestId,
    });
    
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
        
        // Log backoff with rate tracking
        rateTracker.logBackoff({
          keyId,
          operation: 'analyzeConversation',
          delayMs: backoffDelay,
          attempt: attemptNumber,
          reqId: requestId,
        });
        
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

    const text = completion.choices[0]?.message?.content?.trim() || (completion.choices[0]?.message as any)?.reasoning_content?.trim();
    if (!text) {
      console.error('[NVIDIA] No response content received. Full response:', JSON.stringify(completion, null, 2));
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

// Comprehensive analysis structure (Format Option 5)
export interface ComprehensiveAnalysis {
  executiveSummary: string;     // 2-3 sentence brief executive summary
  conversationAnalysis: {
    mainTopic: string;
    keyTopics: string[];
    keyPoints: string[];
    decisionsMade: string[];
    questionsAsked: string[];
    informationProvided: string[];
  };
  customerInsights: {
    customerIntent: string;
    customerNeeds: string[];
    customerGoals: string[];
    painPoints: string[];
    preferences: string[];
    budgetIndicated: boolean;
    timelineIndicated: boolean;
    authorityLevel: string;
  };
  engagementMetrics: {
    engagementLevel: string;
    responseTime: string;
    messageFrequency: string;
    conversationDepth: string;
    sentiment: string;
    tone: string;
  };
  businessIntelligence: {
    buyingSignals: string[];
    objections: string[];
    competitorsMentioned: string[];
    priceSensitivity: string;
    productInterest: string[];
    conversionProbability: number;
    riskFactors: string[];
    opportunitySize: string;
  };
  scoring: {
    leadScore: number;
    confidence: number;
    fitScore: number;
    engagementScore: number;
    urgencyScore: number;
  };
  pipelineRecommendation: {
    recommendedStage: string;
    leadStatus: string;
    stageReason: string;
    nextStage: string;
    estimatedCloseDate: string | null;
  };
  actionItems: {
    immediateActions: string[];
    followUpActions: string[];
    nextBestAction: string;
    bestReply: string;
    followUpMessage: string;
    deadline: string | null;
  };
  greenFlags: string[];
  redFlags: string[];
  upsellOpportunities: string[];
  conversationTips: string[];
  objectionHandling: string[];
  reasoning: string;
}

// Structured analysis for pipeline stage recommendation (backward compatible)
export interface AIContactAnalysis {
  summary: string;              // Now uses executiveSummary from comprehensive format
  recommendedStage: string;     // Stage name recommendation
  leadScore: number;            // 0-100
  leadStatus: string;           // NEW, CONTACTED, QUALIFIED, etc.
  confidence: number;           // 0-100 confidence score
  reasoning: string;            // Why this stage was chosen
  // Optional comprehensive fields for enhanced analysis
  executiveSummary?: string;
  conversationAnalysis?: ComprehensiveAnalysis['conversationAnalysis'];
  customerInsights?: ComprehensiveAnalysis['customerInsights'];
  engagementMetrics?: ComprehensiveAnalysis['engagementMetrics'];
  businessIntelligence?: ComprehensiveAnalysis['businessIntelligence'];
  actionItems?: ComprehensiveAnalysis['actionItems'];
  greenFlags?: string[];
  redFlags?: string[];
  upsellOpportunities?: string[];
  conversationTips?: string[];
  objectionHandling?: string[];
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
  const requestId = `req-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const startTime = Date.now();
  
  // Log request start with rate tracking
  const keyId = apiKey.substring(0, 16);
  const estimatedTokens = Math.min(messages.length * 100 + pipelineStages.length * 50, 8000);
  rateTracker.logRequestStart({
    keyId,
    operation: 'analyzeConversationWithStageRecommendation',
    priority: 'NORMAL',
    tokens: estimatedTokens,
    reqId: requestId,
  });
  
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

    const prompt = `You are a business intelligence AI. Analyze this customer conversation and return ONLY a valid JSON object. Do NOT include any explanations, instructions, or text before or after the JSON.

Available Pipeline Stages:
${stageDescriptions}

Conversation:
${conversationText}

Return a JSON object with this exact structure. The executiveSummary must be 2-3 sentences (50-100 words):

{
  "executiveSummary": "2-3 sentence (50-100 word) brief executive summary covering: high-level opportunity overview, key buying signals or concerns, and immediate next step. Include only the most critical details like key names, numbers, or decisions. Keep it very short and focused.",
  "conversationAnalysis": {
    "mainTopic": "Primary subject of conversation",
    "keyTopics": ["Topic 1", "Topic 2", "Topic 3"],
    "keyPoints": ["Point 1", "Point 2", "Point 3"],
    "decisionsMade": ["Decision 1"],
    "questionsAsked": ["Question 1", "Question 2"],
    "informationProvided": ["Info 1", "Info 2"]
  },
  "customerInsights": {
    "customerIntent": "What they want (BROWSING|INQUIRING|EVALUATING|READY_TO_BUY|PURCHASING)",
    "customerNeeds": ["Need 1", "Need 2"],
    "customerGoals": ["Goal 1"],
    "painPoints": ["Pain 1", "Pain 2"],
    "preferences": ["Preference 1"],
    "budgetIndicated": true/false,
    "timelineIndicated": true/false,
    "authorityLevel": "DECISION_MAKER|INFLUENCER|END_USER|GATEKEEPER"
  },
  "engagementMetrics": {
    "engagementLevel": "LOW|MEDIUM|HIGH|VERY_HIGH",
    "responseTime": "FAST|NORMAL|SLOW",
    "messageFrequency": "LOW|MEDIUM|HIGH",
    "conversationDepth": "SURFACE|MODERATE|DEEP",
    "sentiment": "POSITIVE|NEUTRAL|NEGATIVE|MIXED",
    "tone": "FRIENDLY|PROFESSIONAL|CASUAL|FORMAL|FRUSTRATED"
  },
  "businessIntelligence": {
    "buyingSignals": ["Signal 1", "Signal 2"],
    "objections": ["Objection 1"],
    "competitorsMentioned": ["Competitor 1"],
    "priceSensitivity": "LOW|MEDIUM|HIGH",
    "productInterest": ["Product 1"],
    "conversionProbability": 0-100,
    "riskFactors": ["Risk 1"],
    "opportunitySize": "SMALL|MEDIUM|LARGE|ENTERPRISE"
  },
  "scoring": {
    "leadScore": 0-100,
    "confidence": 0-100,
    "fitScore": 0-100,
    "engagementScore": 0-100,
    "urgencyScore": 0-100
  },
  "pipelineRecommendation": {
    "recommendedStage": "exact stage name from list above",
    "leadStatus": "NEW|CONTACTED|QUALIFIED|PROPOSAL_SENT|NEGOTIATING|WON|LOST|UNRESPONSIVE",
    "stageReason": "Why this stage was chosen",
    "nextStage": "What comes next",
    "estimatedCloseDate": "YYYY-MM-DD or null"
  },
  "actionItems": {
    "immediateActions": ["Action 1", "Action 2"],
    "followUpActions": ["Action 1"],
    "nextBestAction": "Primary action to take",
    "bestReply": "Suggested response message",
    "followUpMessage": "Suggested follow-up",
    "deadline": "YYYY-MM-DD or null"
  },
  "greenFlags": ["Flag 1", "Flag 2"],
  "redFlags": ["Flag 1", "Flag 2"],
  "upsellOpportunities": ["Opportunity 1", "Opportunity 2"],
  "conversationTips": ["Tip 1", "Tip 2"],
  "objectionHandling": ["Rebuttal 1", "Rebuttal 2"],
  "reasoning": "Detailed explanation with specific conversation citations, behavioral patterns, and strategic insights explaining the scoring, stage recommendation, and overall assessment"
}

IMPORTANT: 
- Return ONLY the JSON object, nothing else
- Do NOT repeat these instructions
- Do NOT include markdown code blocks
- Do NOT add explanations before or after the JSON
- executiveSummary: 2-3 sentences (50-100 words), brief and focused
- All arrays must have at least 1-3 items (use [] if none)
- If customer AGREED TO BUY/CLOSED/SIGNED: leadStatus MUST be "WON" (score 85-100)
- If customer REJECTED/DECLINED/SAID NO: leadStatus MUST be "LOST" (score 0-20)
- Match leadScore to appropriate stage's score range when possible
- Fill all fields with actual data from the conversation`;

    const modelToUse = MODEL;
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
      max_tokens: 8000, // Increased to accommodate full comprehensive format JSON (was 5000, causing truncation)
      temperature: 0.3, 
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

    const text = completion.choices[0]?.message?.content?.trim() || (completion.choices[0]?.message as any)?.reasoning_content?.trim();
    if (!text) {
      console.error('[NVIDIA] No response content received. Full response:', JSON.stringify(completion, null, 2));
      return null;
    }
    
    // Check if response looks like instructions/prompt (common issue with reasoning models)
    const instructionIndicators = [
      'We need to parse',
      'We need to produce',
      'Now we need to',
      'Let\'s fill',
      'Now fill',
      'Now produce',
      'Now ensure',
      'Now check',
      'Now we need to ensure',
      'Now we need to produce',
      'Now we need to fill',
      'Now we need to craft',
      'Now we need to write',
      'Now we need to double-check',
      'Now we need to verify',
      'Interpretation:',
      'Conversation lines:',
      'Thus the conversation',
      'Now we need to produce JSON',
    ];
    
    const looksLikeInstructions = instructionIndicators.some(indicator => 
      text.toLowerCase().includes(indicator.toLowerCase())
    );
    
    if (looksLikeInstructions) {
      console.warn('[NVIDIA] ⚠️ Response appears to contain instructions instead of JSON. Attempting to extract JSON...');
    }
    
    // Parse JSON response with robust strategy
    let rawAnalysis: any = null;
    let jsonText = '';

    // Strategy 1: Find the LAST valid JSON object (handles reasoning chains)
    const lastBrace = text.lastIndexOf('}');
    if (lastBrace !== -1) {
      let depth = 0;
      let firstBrace = -1;
      for (let i = lastBrace; i >= 0; i--) {
        if (text[i] === '}') depth++;
        if (text[i] === '{') {
          depth--;
          if (depth === 0) {
            firstBrace = i;
            break;
          }
        }
      }
      
      if (firstBrace !== -1) {
         try {
           jsonText = text.substring(firstBrace, lastBrace + 1);
           rawAnalysis = JSON.parse(jsonText);
           // Validate it's actually JSON data, not instructions
           if (rawAnalysis && typeof rawAnalysis === 'object' && 
               !rawAnalysis.executiveSummary && !rawAnalysis.conversationAnalysis &&
               !rawAnalysis.summary && Object.keys(rawAnalysis).length === 0) {
             rawAnalysis = null; // Reject empty or invalid objects
           }
         } catch {
           // Failed
         }
      }
    }

    // Strategy 2: Strict regex extraction fallback
    if (!rawAnalysis) {
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            try {
                jsonText = jsonMatch[0];
                rawAnalysis = JSON.parse(jsonText);
                // Validate it's actually JSON data
                if (rawAnalysis && typeof rawAnalysis === 'object' && 
                    !rawAnalysis.executiveSummary && !rawAnalysis.conversationAnalysis &&
                    !rawAnalysis.summary && Object.keys(rawAnalysis).length === 0) {
                  rawAnalysis = null;
                }
            } catch {
                console.error('[NVIDIA] Failed to parse JSON via regex match');
            }
        }
    }
    
    // If we detected instructions and still no valid JSON, reject the response
    if (looksLikeInstructions && !rawAnalysis) {
      console.error('[NVIDIA] ❌ Response contains instructions but no valid JSON found. Rejecting response.');
      console.error('[NVIDIA] Response preview:', text.substring(0, 500));
      return null;
    }

    if (!rawAnalysis) {
      console.error('[NVIDIA] No valid JSON found in response. Raw text:', text.substring(0, 200));
      return null;
    }
    
    // Map comprehensive format to AIContactAnalysis interface (backward compatible)
    const analysis: AIContactAnalysis = {
      // Use executiveSummary as the main summary (longer and better)
      summary: rawAnalysis.executiveSummary || rawAnalysis.summary || '',
      recommendedStage: rawAnalysis.pipelineRecommendation?.recommendedStage || rawAnalysis.recommendedStage || 'New Lead',
      leadScore: rawAnalysis.scoring?.leadScore ?? rawAnalysis.leadScore ?? 50,
      leadStatus: rawAnalysis.pipelineRecommendation?.leadStatus || rawAnalysis.leadStatus || 'NEW',
      confidence: rawAnalysis.scoring?.confidence ?? rawAnalysis.confidence ?? 80,
      reasoning: rawAnalysis.reasoning || '',
      // Include comprehensive fields if available
      executiveSummary: rawAnalysis.executiveSummary,
      conversationAnalysis: rawAnalysis.conversationAnalysis,
      customerInsights: rawAnalysis.customerInsights,
      engagementMetrics: rawAnalysis.engagementMetrics,
      businessIntelligence: rawAnalysis.businessIntelligence,
      actionItems: rawAnalysis.actionItems,
      greenFlags: rawAnalysis.greenFlags,
      redFlags: rawAnalysis.redFlags,
      upsellOpportunities: rawAnalysis.upsellOpportunities,
      conversationTips: rawAnalysis.conversationTips,
      objectionHandling: rawAnalysis.objectionHandling,
    };
    
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
    
    // Log success with rate tracking
    const elapsedMs = Date.now() - startTime;
    rateTracker.logRequestComplete({
      keyId,
      operation: 'analyzeConversationWithStageRecommendation',
      elapsedMs,
      success: true,
      reqId: requestId,
    });
    
    console.log(`[NVIDIA] ✅ Stage recommendation: ${analysis.recommendedStage} (confidence: ${analysis.confidence}%, score: ${analysis.leadScore})`);
    if (analysis.executiveSummary) {
      console.log(`[NVIDIA] ✅ Executive summary length: ${analysis.executiveSummary.length} characters`);
    }
    
    return analysis;
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
    
    // Log failure with rate tracking
    const elapsedMs = Date.now() - startTime;
    rateTracker.logRequestComplete({
      keyId,
      operation: 'analyzeConversationWithStageRecommendation',
      elapsedMs,
      success: false,
      errorCode: errorStatus ? String(errorStatus) : undefined,
      retryCount: keyAttempts,
      reqId: requestId,
    });
    
    console.error('[NVIDIA] ❌ Stage recommendation failed:', errorMessage);
    console.error('[NVIDIA] Error details:', JSON.stringify(errorDetails, null, 2));
    
      // Check if it's a rate limit error (429)
    if (errorMessage?.includes('429') || errorMessage?.includes('quota') || errorMessage?.includes('rate limit')) {
      const attemptNumber = keyAttempts + 1;
      if (attemptNumber < MAX_ATTEMPTS) {
        const backoffDelay = calculateExponentialBackoff(keyAttempts);
        
        // Log backoff with rate tracking
        rateTracker.logBackoff({
          keyId,
          operation: 'analyzeConversationWithStageRecommendation',
          delayMs: backoffDelay,
          attempt: attemptNumber,
          reqId: requestId,
        });
        
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

      const personalizedMessage = completion.choices[0]?.message?.content?.trim() || (completion.choices[0]?.message as any)?.reasoning_content?.trim();
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