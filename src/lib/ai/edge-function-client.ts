/**
 * Supabase Edge Function Client for AI Analysis
 * 
 * Provides a client interface to call the Supabase Edge Function for AI analysis.
 * This offloads AI processing to a separate environment, reducing connection pool
 * pressure on the main serverless function.
 */

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

interface EdgeFunctionRequestMessage {
  from: string;
  text: string;
  timestamp?: string;
}

interface EdgeFunctionRequest {
  messages: EdgeFunctionRequestMessage[];
  pipelineStages?: PipelineStage[];
  lastInteraction?: string;
  jobId?: string;
  useFastAnalysis?: boolean;
}

interface EdgeFunctionResponse {
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

/**
 * Calls the Supabase Edge Function for AI analysis
 * 
 * @param messages - Messages to analyze
 * @param pipelineStages - Optional pipeline stages
 * @param lastInteraction - Optional last interaction date
 * @param jobId - Optional job ID for logging
 * @param useFastAnalysis - Whether to use fast analysis (default: true)
 * @returns Analysis result or null if failed
 */
export async function analyzeContactViaEdgeFunction(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  lastInteraction?: Date,
  jobId?: string,
  useFastAnalysis: boolean = true
): Promise<{
  analysis: any;
  usedFallback: boolean;
} | null> {
  // Get Supabase URL and anon key from environment
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    if (jobId) {
      console.warn(`[Edge Function ${jobId}] ⚠️ Supabase credentials not configured, falling back to local analysis`);
    }
    return null; // Fall back to local analysis
  }

  // Check if edge function is enabled
  const useEdgeFunction = process.env.USE_EDGE_FUNCTION_FOR_AI === 'true';
  if (!useEdgeFunction) {
    return null; // Edge function disabled, use local analysis
  }

  try {
    // Prepare request payload
    const requestPayload: EdgeFunctionRequest = {
      messages: messages.map(msg => ({
        from: msg.from,
        text: msg.text,
        timestamp: msg.timestamp?.toISOString(),
      })),
      pipelineStages: pipelineStages?.map(stage => ({
        name: stage.name,
        type: stage.type,
        description: stage.description,
        leadScoreMin: stage.leadScoreMin,
        leadScoreMax: stage.leadScoreMax,
      })),
      lastInteraction: lastInteraction?.toISOString(),
      jobId,
      useFastAnalysis,
    };

    // Call edge function
    const edgeFunctionUrl = `${supabaseUrl}/functions/v1/analyze-contact`;
    
    const response = await fetch(edgeFunctionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${supabaseAnonKey}`,
      },
      body: JSON.stringify(requestPayload),
      // Timeout after 90 seconds (same as local analysis)
      signal: AbortSignal.timeout(90000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Edge function returned ${response.status}: ${errorText}`);
    }

    const result: EdgeFunctionResponse = await response.json();

    if (!result.success || !result.analysis) {
      if (jobId) {
        console.warn(`[Edge Function ${jobId}] ⚠️ Analysis failed: ${result.error || 'Unknown error'}`);
      }
      return null;
    }

    // Convert response to match local analysis format
    const analysis = {
      summary: result.analysis.summary,
      recommendedStage: result.analysis.recommendedStage || 'New Lead',
      leadScore: result.analysis.leadScore ?? 50,
      leadStatus: result.analysis.leadStatus || 'Warm',
      confidence: result.analysis.confidence ?? 85,
      reasoning: result.analysis.reasoning || result.analysis.summary,
      // Enhanced analysis fields
      buyerIntent: result.analysis.buyerIntent,
      sentiment: result.analysis.sentiment,
      conversionProbability: result.analysis.conversionProbability,
      productInterests: result.analysis.productInterests,
      intentSignals: result.analysis.intentSignals,
      nextBestAction: result.analysis.nextBestAction,
      agentSuggestions: result.analysis.agentSuggestions,
      conversionPath: result.analysis.conversionPath,
      similarLeadsInsight: result.analysis.similarLeadsInsight,
      botAccuracyScore: result.analysis.botAccuracyScore,
      conversationPatterns: result.analysis.conversationPatterns,
      indirectIntent: result.analysis.indirectIntent,
      buyerReliability: result.analysis.buyerReliability,
      buyerStyle: result.analysis.buyerStyle,
      leadRiskLevel: result.analysis.leadRiskLevel,
      leadRiskReasons: result.analysis.leadRiskReasons,
    };

    if (jobId) {
      console.log(`[Edge Function ${jobId}] ✅ Analysis successful via edge function (fallback: ${result.usedFallback})`);
    }

    return {
      analysis,
      usedFallback: result.usedFallback ?? false,
    };

  } catch (error) {
    // Log error but don't throw - fall back to local analysis
    if (jobId) {
      console.warn(`[Edge Function ${jobId}] ⚠️ Edge function call failed, falling back to local analysis:`, 
        error instanceof Error ? error.message : String(error));
    } else {
      console.warn(`[Edge Function] ⚠️ Edge function call failed:`, 
        error instanceof Error ? error.message : String(error));
    }
    
    return null; // Fall back to local analysis
  }
}

/**
 * Check if edge function is available and enabled
 */
export function isEdgeFunctionEnabled(): boolean {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const useEdgeFunction = process.env.USE_EDGE_FUNCTION_FOR_AI === 'true';
  
  return !!(supabaseUrl && supabaseAnonKey && useEdgeFunction);
}

