/**
 * Supabase Edge Function: Analyze Contact
 * 
 * Offloads AI analysis to a separate environment to:
 * - Reduce connection pool exhaustion on main server
 * - Avoid Vercel serverless timeout limits
 * - Provide dedicated resources for AI processing
 * 
 * This function runs in Supabase's edge runtime with its own connection pool.
 */

import "jsr:@supabase/functions-js/edge-runtime.d.ts";

declare global {
  const Deno: {
    env: {
      get(key: string): string | undefined;
    };
    serve(handler: (req: Request) => Promise<Response> | Response): void;
  };
}

interface Message {
  from: string;
  text: string;
  timestamp?: string;
}

interface PipelineStage {
  name: string;
  type: string;
  description?: string | null;
  leadScoreMin?: number;
  leadScoreMax?: number;
}

interface AnalysisRequest {
  messages: Message[];
  pipelineStages?: PipelineStage[];
  lastInteraction?: string;
  jobId?: string;
  useFastAnalysis?: boolean;
}

interface AnalysisResponse {
  success: boolean;
  analysis?: {
    summary: string;
    recommendedStage?: string;
    leadScore?: number;
    leadStatus?: string;
    confidence?: number;
    reasoning?: string;
    buyerIntent?: string;
    sentiment?: string;
    conversionProbability?: number;
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
  };
  usedFallback?: boolean;
  error?: string;
}

// Constants
const FAST_MODEL = 'openai/gpt-oss-120b';
const TIMEOUT_MS = 45000;
const MAX_MESSAGES = 20;
const MAX_MESSAGE_LENGTH = 200;

/**
 * Get API key from environment
 */
function getApiKey(): string | null {
  return Deno.env.get('NVIDIA_API_KEY') || Deno.env.get('GOOGLE_AI_API_KEY') || null;
}

/**
 * Calculate fallback score (simplified version)
 */
function calculateFallbackScore(messages: Message[], conversationAge?: Date): {
  leadScore: number;
  leadStatus: string;
  reasoning: string;
} {
  if (!messages || messages.length === 0) {
    return {
      leadScore: 15,
      leadStatus: 'NEW',
      reasoning: 'No conversation data available',
    };
  }

  let score = 20;
  const messageCount = messages.length;
  
  if (messageCount >= 20) score += 25;
  else if (messageCount >= 10) score += 15;
  else if (messageCount >= 5) score += 10;
  else score += 5;

  const avgLength = messages.reduce((sum, m) => sum + m.text.length, 0) / messages.length;
  if (avgLength > 100) score += 15;
  else if (avgLength > 50) score += 10;
  else score += 5;

  const text = messages.map(m => m.text.toLowerCase()).join(' ');
  const buyingKeywords = ['price', 'buy', 'purchase', 'order', 'available', 'interested'];
  const matches = buyingKeywords.filter(k => text.includes(k)).length;
  
  if (matches >= 3) score += 20;
  else if (matches >= 1) score += 6;

  score = Math.min(Math.max(score, 15), 80);

  let leadStatus = 'NEW';
  if (score >= 60) leadStatus = 'QUALIFIED';
  else if (score >= 40) leadStatus = 'CONTACTED';

  return {
    leadScore: score,
    leadStatus,
    reasoning: `Contact with ${messageCount} messages, ${matches} buying signals, score: ${score}`,
  };
}

/**
 * Perform fast AI analysis
 */
async function analyzeFast(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  conversationAge?: Date
): Promise<any | null> {
  const apiKey = getApiKey();
  if (!apiKey) {
    return null;
  }

  try {
    const recentMessages = messages.slice(-MAX_MESSAGES);
    const conversationText = recentMessages
      .map(msg => {
        const text = msg.text.length > MAX_MESSAGE_LENGTH 
          ? msg.text.substring(0, MAX_MESSAGE_LENGTH) + '...'
          : msg.text;
        return `${msg.from}: ${text}`;
      })
      .join('\n');

    const stageInfo = pipelineStages && pipelineStages.length > 0
      ? `\nStages: ${pipelineStages.slice(0, 10).map(s => `${s.name}(${s.leadScoreMin ?? 0}-${s.leadScoreMax ?? 100})`).join(' ')}`
      : '';

    const prompt = `You are an expert in deep conversation analysis. Analyze this conversation with maximum possible depth.

Your analysis must include:
1. High-Level Summary (3-7 sentences): purpose, main topics, decisions, tone
2. Expanded Detailed Chronological Summary: message-by-message reconstruction
3. Participant Analysis: goals, communication style, behavior patterns
4. Action Items & Follow-Up Tasks
5. Unresolved Questions/Gaps
6. Key Themes/Insights/Patterns
7. Metadata & Analytical Notes
8. Stage Assessment: recommended stage, lead score, lead status, confidence, detailed reasoning

IMPORTANT: All events in perfect chronological order. Extremely detailed (25-40+ sentences minimum).

JSON only:
{
  "summary": "Comprehensive 25-40+ sentence deep analysis covering all 8 sections...",
  "leadScore": 0-100,
  "recommendedStage": "stage name",
  "reasoning": "EXTREMELY DETAILED 6-10 sentence explanation..."
}

${conversationText}${stageInfo}`;

    // Call NVIDIA API
    const response = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: FAST_MODEL,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.6,
        max_tokens: 5000,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    
    if (!content) {
      return null;
    }

    // Parse JSON response
    let parsed: any;
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      const jsonText = jsonMatch ? jsonMatch[0] : content;
      parsed = JSON.parse(jsonText);
    } catch {
      const fallback = calculateFallbackScore(messages, conversationAge);
      return {
        summary: content.split('\n')[0] || content.substring(0, 200),
        recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
        leadScore: fallback.leadScore,
        leadStatus: fallback.leadStatus,
        confidence: 70,
        reasoning: 'AI analysis completed (parsed from text)',
      };
    }

    const fallback = calculateFallbackScore(messages, conversationAge);
    
    return {
      summary: parsed.summary || `Contact with ${messages.length} messages. ${fallback.reasoning}`,
      recommendedStage: parsed.recommendedStage || pipelineStages?.[0]?.name || 'New Lead',
      leadScore: typeof parsed.leadScore === 'number' 
        ? Math.max(0, Math.min(100, parsed.leadScore))
        : fallback.leadScore,
      leadStatus: fallback.leadStatus,
      confidence: 85,
      reasoning: parsed.reasoning || fallback.reasoning,
    };

  } catch (error) {
    console.warn('[Edge Function] Fast analysis failed:', error);
    return null;
  }
}

Deno.serve(async (req: Request) => {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  try {
    if (req.method !== 'POST') {
      return new Response(
        JSON.stringify({ success: false, error: 'Method not allowed' }),
        {
          status: 405,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      );
    }

    const requestData: AnalysisRequest = await req.json();

    if (!requestData.messages || !Array.isArray(requestData.messages) || requestData.messages.length === 0) {
      return new Response(
        JSON.stringify({ success: false, error: 'Messages array is required and must not be empty' }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      );
    }

    // Convert timestamp strings to Date objects
    const messages = requestData.messages.map(msg => ({
      from: msg.from,
      text: msg.text,
      timestamp: msg.timestamp ? new Date(msg.timestamp) : undefined,
    }));

    const pipelineStages = requestData.pipelineStages;
    const lastInteraction = requestData.lastInteraction ? new Date(requestData.lastInteraction) : undefined;
    const useFastAnalysis = requestData.useFastAnalysis !== false;

    // Perform AI analysis
    let analysisResult: any = null;
    let usedFallback = false;

    if (useFastAnalysis) {
      // Convert messages to match Message interface (timestamp as string)
      const convertedMessages: Message[] = messages.map(msg => ({
        from: msg.from,
        text: msg.text,
        timestamp: msg.timestamp ? (typeof msg.timestamp === 'string' ? msg.timestamp : msg.timestamp.toISOString()) : undefined
      }));
      analysisResult = await analyzeFast(convertedMessages, pipelineStages, lastInteraction);
      if (!analysisResult || !analysisResult.summary || analysisResult.summary.length <= 200) {
        usedFallback = true;
      }
    }

    // If fast analysis failed, use fallback scoring
    if (!analysisResult) {
      const fallback = calculateFallbackScore(convertedMessages, lastInteraction);
      analysisResult = {
        summary: `Contact analysis: ${fallback.reasoning}`,
        recommendedStage: pipelineStages?.[0]?.name || 'New Lead',
        leadScore: fallback.leadScore,
        leadStatus: fallback.leadStatus,
        confidence: 60,
        reasoning: fallback.reasoning,
      };
      usedFallback = true;
    }

    const response: AnalysisResponse = {
      success: true,
      usedFallback,
      analysis: {
        summary: analysisResult.summary || '',
        recommendedStage: analysisResult.recommendedStage,
        leadScore: analysisResult.leadScore,
        leadStatus: analysisResult.leadStatus,
        confidence: analysisResult.confidence,
        reasoning: analysisResult.reasoning,
      },
    };

    return new Response(
      JSON.stringify(response),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      }
    );

  } catch (error) {
    console.error('[Edge Function] Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    return new Response(
      JSON.stringify({
        success: false,
        error: `Analysis failed: ${errorMessage}`,
      }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      }
    );
  }
});
