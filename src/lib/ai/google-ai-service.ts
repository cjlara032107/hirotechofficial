import { GoogleGenerativeAI } from '@google/generative-ai';

// API Key rotation manager
class GoogleAIKeyManager {
  private keys: string[];
  private currentIndex: number = 0;

  constructor() {
    this.keys = [
      process.env.GOOGLE_AI_API_KEY,
      process.env.GOOGLE_AI_API_KEY_2,
      process.env.GOOGLE_AI_API_KEY_3,
      process.env.GOOGLE_AI_API_KEY_4,
      process.env.GOOGLE_AI_API_KEY_5,
      process.env.GOOGLE_AI_API_KEY_6,
      process.env.GOOGLE_AI_API_KEY_7,
      process.env.GOOGLE_AI_API_KEY_8,
    ].filter((key): key is string => !!key);

    if (this.keys.length === 0) {
      console.warn('[Google AI] No API keys configured');
    }
  }

  getNextKey(): string | null {
    if (this.keys.length === 0) return null;
    const key = this.keys[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.keys.length;
    return key;
  }

  getKeyCount(): number {
    return this.keys.length;
  }
}

const keyManager = new GoogleAIKeyManager();

export async function analyzeConversation(
  messages: Array<{
    from: string;
    text: string;
    timestamp?: Date;
  }>,
  retries = 2
): Promise<string | null> {
  const apiKey = keyManager.getNextKey();
  if (!apiKey) {
    console.error('[Google AI] No API key available');
    return null;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });

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

    const result = await model.generateContent(prompt);
    const summary = result.response.text();
    
    console.log(`[Google AI] Generated summary (${summary.length} chars)`);
    return summary.trim();
  } catch (error: any) {
    // Check if it's a rate limit error (429)
    if (error.message?.includes('429') || error.message?.includes('quota')) {
      console.warn('[Google AI] Rate limit hit, trying next key...');
      
      // Try with next API key if we have retries left
      if (retries > 0) {
        // Wait a bit before retry
        await new Promise(resolve => setTimeout(resolve, 2000));
        return analyzeConversation(messages, retries - 1);
      }
      
      console.error('[Google AI] All API keys rate limited');
      return null;
    }
    
    console.error('[Google AI] Analysis failed:', error.message);
    return null;
  }
}

export function getAvailableKeyCount(): number {
  return keyManager.getKeyCount();
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
  pipelineStages: Array<{ name: string; type: string; description?: string | null }>,
  retries = 2
): Promise<AIContactAnalysis | null> {
  const apiKey = keyManager.getNextKey();
  if (!apiKey) {
    console.error('[Google AI] No API key available');
    return null;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });

    const conversationText = messages
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');

    const stageDescriptions = pipelineStages
      .map((s, i) => `${i + 1}. ${s.name} (${s.type})${s.description ? ': ' + s.description : ''}`)
      .join('\n');

    const prompt = `Analyze this customer conversation and assign them to the most appropriate sales/support stage.

Available Pipeline Stages:
${stageDescriptions}

Conversation:
${conversationText}

Analyze the conversation and determine:
1. Which stage best fits this contact's current position in the customer journey
2. Their engagement level and intent (lead score 0-100)
3. Their status (NEW, CONTACTED, QUALIFIED, PROPOSAL_SENT, NEGOTIATING, WON, LOST, UNRESPONSIVE)
4. Your confidence in this assessment (0-100)

Consider:
- Conversation maturity (new inquiry vs ongoing discussion)
- Customer intent (browsing vs ready to buy)
- Engagement level (responsive vs unresponsive)
- Specific requests or commitments made
- Timeline and urgency

Respond ONLY with valid JSON (no markdown, no explanation):
{
  "summary": "3-5 sentence summary of conversation",
  "recommendedStage": "exact stage name from list above",
  "leadScore": 0-100,
  "leadStatus": "NEW|CONTACTED|QUALIFIED|PROPOSAL_SENT|NEGOTIATING|WON|LOST|UNRESPONSIVE",
  "confidence": 0-100,
  "reasoning": "brief explanation of stage choice"
}`;

    const result = await model.generateContent(prompt);
    const text = result.response.text().trim();
    
    // Parse JSON response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.error('[Google AI] No JSON found in response');
      return null;
    }
    
    const analysis = JSON.parse(jsonMatch[0]) as AIContactAnalysis;
    console.log(`[Google AI] Stage recommendation: ${analysis.recommendedStage} (confidence: ${analysis.confidence}%)`);
    
    return analysis;
  } catch (error: any) {
    // Check if it's a rate limit error (429)
    if (error.message?.includes('429') || error.message?.includes('quota')) {
      console.warn('[Google AI] Rate limit hit, trying next key...');
      
      // Try with next API key if we have retries left
      if (retries > 0) {
        // Wait a bit before retry
        await new Promise(resolve => setTimeout(resolve, 2000));
        return analyzeConversationWithStageRecommendation(messages, pipelineStages, retries - 1);
      }
      
      console.error('[Google AI] All API keys rate limited');
      return null;
    }
    
    console.error('[Google AI] Analysis failed:', error.message);
    return null;
  }
}

