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
      process.env.GOOGLE_AI_API_KEY_9,
      process.env.GOOGLE_AI_API_KEY_10,
      process.env.GOOGLE_AI_API_KEY_11,
      process.env.GOOGLE_AI_API_KEY_12,
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
    // Using gemini-2.5-flash with v1 API - verified working!
    const model = genAI.getGenerativeModel({ 
      model: 'models/gemini-2.5-flash',
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 500,
      },
    });

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
  } catch (error: unknown) {
    // Check if it's a rate limit error (429)
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (errorMessage?.includes('429') || errorMessage?.includes('quota')) {
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
    
    console.error('[Google AI] Analysis failed:', errorMessage);
    return null;
  }
}

export function getAvailableKeyCount(): number {
  return keyManager.getKeyCount();
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
  const apiKey = keyManager.getNextKey();
  if (!apiKey) {
    console.error('[Google AI] No API key available');
    return null;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    // Using gemini-2.5-flash with v1 API - verified working!
    const model = genAI.getGenerativeModel({ 
      model: 'models/gemini-2.5-flash',
      generationConfig: {
        temperature: 0.8,
        maxOutputTokens: 1000,
      },
    });

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

    const result = await model.generateContent(prompt);
    const text = result.response.text().trim();
    
    // Parse JSON response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.error('[Google AI] No JSON found in response');
      return null;
    }
    
    const followUp = JSON.parse(jsonMatch[0]) as AIFollowUpResult;
    console.log(`[Google AI] Generated follow-up message for ${contactName}: "${followUp.message}"`);
    
    return followUp;
  } catch (error: unknown) {
    // Check if it's a rate limit error (429)
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (errorMessage?.includes('429') || errorMessage?.includes('quota')) {
      console.warn('[Google AI] Rate limit hit, trying next key...');
      
      // Try with next API key if we have retries left
      if (retries > 0) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        return generateFollowUpMessage(contactName, conversationHistory, customPrompt, languageStyle, retries - 1);
      }
      
      console.error('[Google AI] All API keys rate limited');
      return null;
    }
    
    console.error('[Google AI] Follow-up generation failed:', errorMessage);
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
  retries = 2
): Promise<AIContactAnalysis | null> {
  const apiKey = keyManager.getNextKey();
  if (!apiKey) {
    console.error('[Google AI] No API key available');
    return null;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    // Using gemini-2.5-flash with v1 API - verified working!
    const model = genAI.getGenerativeModel({ 
      model: 'models/gemini-2.5-flash',
      generationConfig: {
        temperature: 0.8,
        maxOutputTokens: 2000,
      },
    });

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
  } catch (error: unknown) {
    // Check if it's a rate limit error (429)
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (errorMessage?.includes('429') || errorMessage?.includes('quota')) {
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
    
    console.error('[Google AI] Analysis failed:', errorMessage);
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
  private keyManager: GoogleAIKeyManager;

  constructor() {
    this.keyManager = keyManager;
  }

  async generatePersonalizedMessage(
    context: PersonalizedMessageContext,
    retries = 2
  ): Promise<string> {
    const apiKey = this.keyManager.getNextKey();
    if (!apiKey) {
      console.error('[Google AI] No API key available');
      // Fallback to template
      return context.templateMessage
        .replace(/\{firstName\}/g, context.contactName)
        .replace(/\{name\}/g, context.contactName);
    }

    try {
      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });

      const historyText = context.conversationHistory.length > 0
        ? context.conversationHistory
            .map((msg) => `${msg.from}: ${msg.message}`)
            .join('\n')
        : 'No previous conversation';

      const customInstructions = context.customInstructions
        ? `\n\nCustom Instructions: ${context.customInstructions}`
        : '';

      const prompt = `Generate a personalized follow-up message for ${context.contactName}.

Template Message: ${context.templateMessage}

Previous Conversation History:
${historyText}${customInstructions}

Create a natural, personalized version of the template message that:
1. References specific points from the conversation history (if available)
2. Feels personal and tailored to ${context.contactName}
3. Maintains the intent and key information from the template
4. Uses a conversational, friendly tone
5. Is concise and engaging (2-4 sentences)

Respond with ONLY the personalized message text (no JSON, no markdown, no explanation).`;

      const result = await model.generateContent(prompt);
      const personalizedMessage = result.response.text().trim();

      console.log(`[Google AI] Generated personalized message for ${context.contactName}`);
      return personalizedMessage;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage?.includes('429') || errorMessage?.includes('quota')) {
        console.warn('[Google AI] Rate limit hit, trying next key...');

        if (retries > 0) {
          await new Promise((resolve) => setTimeout(resolve, 2000));
          return this.generatePersonalizedMessage(context, retries - 1);
        }

        console.error('[Google AI] All API keys rate limited');
      } else {
        console.error('[Google AI] Personalization failed:', errorMessage);
      }

      // Fallback to template
      return context.templateMessage
        .replace(/\{firstName\}/g, context.contactName)
        .replace(/\{name\}/g, context.contactName);
    }
  }
}

