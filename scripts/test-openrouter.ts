/**
 * Test script for OpenRouter integration
 * Run with: npx tsx scripts/test-openrouter.ts
 */

import { config } from 'dotenv';
import { resolve } from 'path';

// Load environment variables
config({ path: resolve(process.cwd(), '.env.local') });

import OpenAI from 'openai';

async function testOpenRouter() {
  console.log('\n🧪 Testing OpenRouter Integration\n');
  console.log('=' .repeat(60));

  // Check environment variables
  console.log('\n📋 Environment Check:');
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  const siteUrl = process.env.OPENROUTER_SITE_URL || process.env.NEXT_PUBLIC_APP_URL || 'https://hiro.app';
  const siteName = process.env.OPENROUTER_SITE_NAME || 'Hiro';

  if (!apiKey) {
    console.error('❌ GOOGLE_AI_API_KEY not found in environment variables');
    console.log('\n💡 Make sure you have .env.local file with:');
    console.log('   GOOGLE_AI_API_KEY=sk-or-v1-xxxxxxxxxxxxx');
    process.exit(1);
  }

  console.log(`✅ API Key found: ${apiKey.substring(0, 12)}...${apiKey.substring(apiKey.length - 4)} (${apiKey.length} chars)`);
  console.log(`✅ Site URL: ${siteUrl}`);
  console.log(`✅ Site Name: ${siteName}`);

  // Check API key format
  if (!apiKey.startsWith('sk-or-v1-')) {
    console.warn('⚠️  Warning: API key should start with "sk-or-v1-" for OpenRouter');
    console.warn('   Current format might be incorrect');
  } else {
    console.log('✅ API key format looks correct (starts with sk-or-v1-)');
  }

  // Create OpenAI client
  console.log('\n🔧 Creating OpenRouter client...');
  const openai = new OpenAI({
    baseURL: 'https://openrouter.ai/api/v1',
    apiKey: apiKey,
    defaultHeaders: {
      'HTTP-Referer': siteUrl,
      'X-Title': siteName,
    },
  });

  // Test API call
  console.log('\n🚀 Testing API call...');
  try {
    const testMessages = [
      { from: 'Customer', text: 'Hello, I am interested in your product.' },
      { from: 'Support', text: 'Great! What would you like to know?' },
      { from: 'Customer', text: 'What are your pricing options?' },
    ];

    const prompt = `Analyze this conversation and provide a concise 3-5 sentence summary covering:
- The main topic or purpose of the conversation
- Key points discussed
- Customer intent or needs
- Any action items or requests

Conversation:
${testMessages.map(msg => `${msg.from}: ${msg.text}`).join('\n')}

Summary:`;

    console.log('📤 Sending request to OpenRouter...');
    console.log(`   Model: google/gemini-2.0-flash-exp:free`);
    console.log(`   Messages: ${testMessages.length}`);

    const startTime = Date.now();
    const completion = await openai.chat.completions.create({
      model: 'google/gemini-2.0-flash-exp:free',
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });
    const duration = Date.now() - startTime;

    console.log(`\n✅ Request successful! (${duration}ms)`);
    console.log(`📊 Response details:`);
    console.log(`   - Choices: ${completion.choices?.length || 0}`);
    console.log(`   - Usage: ${JSON.stringify(completion.usage || {}, null, 2)}`);

    const summary = completion.choices[0]?.message?.content;
    if (summary) {
      console.log(`\n📝 Generated Summary:`);
      console.log(`   ${summary.trim()}`);
      console.log(`\n✅ OpenRouter integration is working correctly!`);
    } else {
      console.error('\n❌ No content in response');
      console.error('Full response:', JSON.stringify(completion, null, 2));
      process.exit(1);
    }
  } catch (error: unknown) {
    console.error('\n❌ Test failed!');
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Try to extract more details from the error
    let errorDetails: any = {};
    if (error instanceof Error) {
      errorDetails = {
        name: error.name,
        message: error.message,
        stack: error.stack?.split('\n').slice(0, 5).join('\n'),
      };
      
      // Check if it's an OpenAI API error with more details
      if ('status' in error) {
        errorDetails.status = (error as any).status;
      }
      if ('statusText' in error) {
        errorDetails.statusText = (error as any).statusText;
      }
      if ('response' in error) {
        try {
          const response = (error as any).response;
          errorDetails.response = {
            status: response?.status,
            statusText: response?.statusText,
            data: response?.data,
          };
        } catch {
          // Ignore
        }
      }
    } else {
      errorDetails = { raw: String(error) };
    }

    console.error('\nError details:');
    console.error(JSON.stringify(errorDetails, null, 2));

    if (errorMessage?.includes('401') || errorMessage?.includes('No auth') || errorMessage?.includes('Unauthorized')) {
      console.error('\n🔐 Authentication Error:');
      console.error('   - Check that your API key is correct');
      console.error('   - Make sure it starts with "sk-or-v1-"');
      console.error('   - Verify the key is active in OpenRouter dashboard');
    } else if (errorMessage?.includes('429') || errorMessage?.includes('rate limit')) {
      console.error('\n⏱️  Rate Limit Error:');
      console.error('   - You have hit the rate limit');
      console.error('   - Wait a few minutes and try again');
    } else if (errorMessage?.includes('model')) {
      console.error('\n🤖 Model Error:');
      console.error('   - The model "google/gemini-2.0-flash-exp:free" might not be available');
      console.error('   - Check OpenRouter model list');
    }

    process.exit(1);
  }

  console.log('\n' + '='.repeat(60));
  console.log('✨ All tests passed!\n');
}

// Run the test
testOpenRouter().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

