import OpenAI from 'openai';

// Initialize OpenAI client
let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI | null {
  if (!process.env.OPENAI_API_KEY) {
    return null;
  }
  
  if (!openaiClient) {
    openaiClient = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });
  }
  
  return openaiClient;
}

export interface AIFollowUpResult {
  message: string;
  reasoning: string;
}

export async function generateFollowUpMessage(
  contactName: string,
  conversationHistory: Array<{ from: string; text: string; timestamp?: Date }>,
  customPrompt?: string | null,
  languageStyle?: string | null
): Promise<AIFollowUpResult | null> {
  const client = getOpenAIClient();
  
  if (!client) {
    console.error('[OpenAI] No API key configured');
    return null;
  }
  
  try {
    // Format conversation history
    const historyText = conversationHistory
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');
    
    // Build prompt
    const styleInstruction = languageStyle 
      ? `\n\nLanguage Style: ${languageStyle}`
      : '\n\nUse a friendly, professional tone that feels natural and conversational.';
    
    const customInstruction = customPrompt
      ? `\n\nCustom Instructions: ${customPrompt}`
      : '';
    
    const systemPrompt = `You are a helpful business assistant generating follow-up messages for customers.${styleInstruction}${customInstruction}`;
    
    const userPrompt = `Generate a natural, engaging follow-up message for ${contactName} based on this previous conversation:

${historyText}

The follow-up should:
1. Reference the previous conversation context
2. Provide value or continue the conversation naturally
3. Encourage further engagement
4. Feel personalized and human (not robotic)
5. Be concise (2-4 sentences)

Respond ONLY with valid JSON (no markdown, no explanation):
{
  "message": "the follow-up message text here",
  "reasoning": "brief explanation of why this message was chosen"
}`;
    
    const response = await client.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.8,
      max_tokens: 500,
    });
    
    const text = response.choices[0]?.message?.content?.trim();
    
    if (!text) {
      console.error('[OpenAI] No response text');
      return null;
    }
    
    // Parse JSON response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.error('[OpenAI] No JSON found in response');
      return null;
    }
    
    const followUp = JSON.parse(jsonMatch[0]) as AIFollowUpResult;
    console.log(`[OpenAI] Generated follow-up for ${contactName}: "${followUp.message}"`);
    
    return followUp;
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error('[OpenAI] Follow-up generation failed:', errorMessage);
    return null;
  }
}

export async function analyzeConversation(
  messages: Array<{ from: string; text: string; timestamp?: Date }>
): Promise<string | null> {
  const client = getOpenAIClient();
  
  if (!client) {
    return null;
  }
  
  try {
    const conversationText = messages
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');
    
    const response = await client.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'user',
          content: `Analyze this conversation and provide a concise 3-5 sentence summary covering:
- The main topic or purpose
- Key points discussed
- Customer intent or needs
- Any action items

Conversation:
${conversationText}

Summary:`,
        },
      ],
      temperature: 0.7,
      max_tokens: 300,
    });
    
    return response.choices[0]?.message?.content?.trim() || null;
  } catch (error: unknown) {
    console.error('[OpenAI] Analysis failed:', error);
    return null;
  }
}

