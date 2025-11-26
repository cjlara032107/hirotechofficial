import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';

const MODEL = 'google/gemini-2.0-flash-exp:free';

// Helper function to create OpenAI client configured for NVIDIA API
function createNvidiaClient(apiKey: string): OpenAI {
  return new OpenAI({
    baseURL: 'https://integrate.api.nvidia.com/v1',
    apiKey: apiKey,
  });
}

interface ContactInfo {
  age?: number | null;
  phoneNumbers?: string[]; // Array of phone numbers
  emails?: string[]; // Array of email addresses
  businessNames?: string[]; // Array of business/company names
  pageLinks?: string[]; // Array of page links (Facebook pages, websites, etc.)
  socialMedia?: {
    facebook?: string[] | string | null; // Can be array or single value
    instagram?: string[] | string | null;
    twitter?: string[] | string | null;
    linkedin?: string[] | string | null;
    tiktok?: string[] | string | null;
    youtube?: string[] | string | null;
    [key: string]: string[] | string | null | undefined;
  };
  facebookPages?: string[]; // Array of Facebook pages
  locations?: string[]; // Array of locations
  occupations?: string[]; // Array of job titles/occupations
  companies?: string[]; // Array of companies
  websites?: string[]; // Array of websites/URLs
  // Legacy single-value fields for backward compatibility
  phoneNumber?: string | null;
  email?: string | null;
  facebookPage?: string | null;
  location?: string | null;
  occupation?: string | null;
  company?: string | null;
  website?: string | null;
  otherInfo?: Record<string, any>;
}

/**
 * Extracts comprehensive contact information from conversation messages
 */
export async function extractContactInfo(
  messages: Array<{ from: string; text: string; timestamp?: Date }>,
  retries = 2
): Promise<ContactInfo | null> {
  try {
    const apiKey = await apiKeyManager.getNextKey();
    if (!apiKey) {
      console.warn('[Contact Info Extraction] No API key available');
      return null;
    }

    const openai = createNvidiaClient(apiKey);

    const conversationText = messages
      .map(msg => `${msg.from}: ${msg.text}`)
      .join('\n');

    const prompt = `Analyze this conversation and extract ALL available contact information about the customer/contact.

Conversation:
${conversationText}

Extract and return ALL information you can find about the contact. IMPORTANT: Extract MULTIPLE entries when multiple values are mentioned.

Extract:
- Age (if mentioned or can be inferred) - single number
- Phone numbers (ANY format: mobile, landline, WhatsApp, business phone, etc.) - ARRAY of all phone numbers found
- Email addresses - ARRAY of all email addresses found
- Business/Company names - ARRAY of all business names mentioned
- Page links (Facebook pages, websites, social media pages they own/manage) - ARRAY of all page links
- Social media profiles (Facebook, Instagram, Twitter/X, LinkedIn, TikTok, YouTube, etc.) - ARRAY for each platform
- Locations (city, country, address, etc.) - ARRAY of all locations mentioned
- Occupations/Job titles - ARRAY of all job titles mentioned
- Companies/Organizations - ARRAY of all companies mentioned
- Websites/URLs - ARRAY of all websites/URLs mentioned
- Any other relevant information (interests, hobbies, preferences, etc.)

CRITICAL RULES:
1. Extract MULTIPLE entries - if the conversation mentions 3 phone numbers, extract all 3 in an array
2. Only extract information that is EXPLICITLY mentioned or can be CLEARLY inferred
3. If no information is found for a field, use null or empty array []
4. Be thorough - extract EVERY instance mentioned (e.g., if they mention 2 emails, include both)
5. For phone numbers, include country codes if mentioned
6. For locations, be as specific as possible
7. For social media, extract handles/usernames, not just mentions
8. For page links, include full URLs when available

Respond ONLY with valid JSON (no markdown, no explanation):
{
  "age": number or null,
  "phoneNumbers": ["string1", "string2", ...] or [],
  "emails": ["email1@example.com", "email2@example.com", ...] or [],
  "businessNames": ["Business 1", "Business 2", ...] or [],
  "pageLinks": ["https://facebook.com/page1", "https://website.com", ...] or [],
  "socialMedia": {
    "facebook": ["handle1", "handle2", ...] or "single_handle" or null,
    "instagram": ["handle1", "handle2", ...] or "single_handle" or null,
    "twitter": ["handle1", "handle2", ...] or "single_handle" or null,
    "linkedin": ["profile1", "profile2", ...] or "single_profile" or null,
    "tiktok": ["handle1", "handle2", ...] or "single_handle" or null,
    "youtube": ["channel1", "channel2", ...] or "single_channel" or null
  },
  "facebookPages": ["page1", "page2", ...] or [],
  "locations": ["Location 1", "Location 2", ...] or [],
  "occupations": ["Job Title 1", "Job Title 2", ...] or [],
  "companies": ["Company 1", "Company 2", ...] or [],
  "websites": ["https://website1.com", "https://website2.com", ...] or [],
  "otherInfo": {}
}`;

    const completion = await openai.chat.completions.create({
      model: MODEL,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3, // Lower temperature for more accurate extraction
      max_tokens: 1000, // Limit tokens for faster response
    });

    if (!completion.choices || completion.choices.length === 0) {
      console.error('[Contact Info Extraction] No choices in response');
      return null;
    }

    const content = completion.choices[0]?.message?.content;
    if (!content) {
      console.error('[Contact Info Extraction] No content in response');
      return null;
    }

    // Parse JSON response
    try {
      // Remove markdown code blocks if present
      const jsonContent = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      const contactInfo = JSON.parse(jsonContent) as ContactInfo;
      
      console.log('[Contact Info Extraction] Successfully extracted contact information');
      return contactInfo;
    } catch (parseError) {
      console.error('[Contact Info Extraction] Failed to parse JSON response:', parseError);
      console.error('[Contact Info Extraction] Response content:', content);
      return null;
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('[Contact Info Extraction] Error:', errorMessage);
    
    if (retries > 0) {
      console.log(`[Contact Info Extraction] Retrying... (${retries} attempts left)`);
      await new Promise(resolve => setTimeout(resolve, 500)); // Reduced from 1000ms to 500ms
      return extractContactInfo(messages, retries - 1);
    }
    
    return null;
  }
}

