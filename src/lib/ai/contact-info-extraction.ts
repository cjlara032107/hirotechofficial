import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';

// Use the same model as the main AI service for consistency and availability
const MODEL = process.env.AI_PRIMARY_MODEL || 'openai/gpt-oss-120b';

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
  retries = 2,
  context?: { contactId?: string }
): Promise<ContactInfo | null> {
  const startTime = Date.now();
  try {
    const apiKey = await apiKeyManager.getNextKey({ 
      operation: 'extractContactInfo',
      contactId: context?.contactId 
    });
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
      
      // CRITICAL: Validate that the extracted object has meaningful data
      // An empty object {} would pass truthy checks but has no actual data
      const hasData = (info: ContactInfo): boolean => {
        // Check age
        if (info.age !== null && info.age !== undefined && typeof info.age === 'number') {
          return true;
        }
        
        // Check arrays (phoneNumbers, emails, etc.)
        const arrayFields: (keyof ContactInfo)[] = [
          'phoneNumbers', 'emails', 'businessNames', 'pageLinks', 
          'facebookPages', 'locations', 'occupations', 'companies', 'websites'
        ];
        for (const field of arrayFields) {
          const value = info[field];
          if (Array.isArray(value) && value.length > 0) {
            return true;
          }
        }
        
        // Check legacy single-value fields
        const singleFields: (keyof ContactInfo)[] = [
          'phoneNumber', 'email', 'facebookPage', 'location', 'occupation', 'company', 'website'
        ];
        for (const field of singleFields) {
          const value = info[field];
          if (value !== null && value !== undefined && value !== '') {
            return true;
          }
        }
        
        // Check socialMedia object
        if (info.socialMedia && typeof info.socialMedia === 'object') {
          const socialValues = Object.values(info.socialMedia);
          if (socialValues.some(v => v !== null && v !== undefined && v !== '' && 
            (Array.isArray(v) ? v.length > 0 : true))) {
            return true;
          }
        }
        
        // Check otherInfo object
        if (info.otherInfo && typeof info.otherInfo === 'object' && 
            Object.keys(info.otherInfo).length > 0) {
          return true;
        }
        
        return false;
      };
      
      if (hasData(contactInfo)) {
        console.log('[Contact Info Extraction] ✅ Successfully extracted contact information with data');
        const extractedFields = Object.keys(contactInfo).filter(key => {
          const value = contactInfo[key as keyof ContactInfo];
          if (Array.isArray(value)) return value.length > 0;
          if (typeof value === 'object' && value !== null) {
            if (key === 'socialMedia') {
              return Object.values(value).some(v => v !== null && v !== undefined && v !== '');
            }
            return Object.keys(value).length > 0;
          }
          return value !== null && value !== undefined && value !== '';
        });
        if (extractedFields.length > 0) {
          console.log('[Contact Info Extraction] Extracted fields:', extractedFields.join(', '));
        }
        return contactInfo;
      } else {
        console.log('[Contact Info Extraction] ⚠️ Extracted object has no meaningful data, returning null');
        return null;
      }
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

