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

export async function analyzeConversation(messages: Array<{
  from: string;
  text: string;
  timestamp?: Date;
}>): Promise<string | null> {
  const apiKey = keyManager.getNextKey();
  if (!apiKey) {
    console.error('[Google AI] No API key available');
    return null;
  }

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

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
    console.error('[Google AI] Analysis failed:', error.message);
    return null;
  }
}

export function getAvailableKeyCount(): number {
  return keyManager.getKeyCount();
}

