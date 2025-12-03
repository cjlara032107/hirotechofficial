/**
 * Verify Key #4 to see if it actually works with openai/gpt-oss-120b
 */

// Load env vars first
require('dotenv').config({ path: require('path').join(process.cwd(), '.env.local') });

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL not found');
  process.exit(1);
}

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const OpenAI = require('openai');

// Import decryptKey using dynamic import
let decryptKey: (encrypted: string) => string;

async function verifyKey4() {
  console.log('\n🔍 Verifying Key #4...\n');

  // Import decryptKey
  try {
    const encryptionModule = await import('../src/lib/crypto/encryption');
    decryptKey = encryptionModule.decryptKey;
  } catch (error) {
    console.error('❌ Failed to import decryptKey:', error);
    process.exit(1);
  }

  try {
    // Find the key with ID starting with cmina3jir000
    const key = await prisma.apiKey.findFirst({
      where: {
        id: { startsWith: 'cmina3jir000' },
        status: 'ACTIVE',
      },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
        totalRequests: true,
        failedRequests: true,
        lastSuccessAt: true,
        metadata: true,
      },
    });

    if (!key) {
      console.log('❌ Key #4 not found');
      await prisma.$disconnect();
      return;
    }

    console.log(`Found key: ${key.name || 'Unnamed'}`);
    console.log(`ID: ${key.id}`);
    console.log(`Total Requests: ${key.totalRequests}`);
    console.log(`Failed Requests: ${key.failedRequests}`);
    console.log(`Last Success: ${key.lastSuccessAt ? new Date(key.lastSuccessAt).toLocaleString() : 'Never'}`);
    console.log('\n' + '='.repeat(80));
    console.log('\n🧪 Testing key with primary model (openai/gpt-oss-120b)...\n');

    // Decrypt the key
    const decryptedKey = decryptKey(key.encryptedKey);
    const keyPrefix = decryptedKey.substring(0, 20) + '...';
    console.log(`Key: ${keyPrefix}\n`);

    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: decryptedKey,
    });

    // Test 1: Can list models?
    console.log('📋 Test 1: Can list models?');
    try {
      const models = await client.models.list();
      console.log(`  ✅ Yes! Found ${models.data.length} available models`);
      
      // Check if primary model is in the list
      const hasPrimaryModel = models.data.some(m => m.id === 'openai/gpt-oss-120b');
      if (hasPrimaryModel) {
        console.log(`  ✅ Primary model (openai/gpt-oss-120b) is in the list!`);
      } else {
        console.log(`  ❌ Primary model (openai/gpt-oss-120b) is NOT in the list`);
        console.log(`  📋 Available models (first 10):`);
        models.data.slice(0, 10).forEach((m: any) => {
          console.log(`     - ${m.id}`);
        });
      }
    } catch (error: any) {
      console.log(`  ❌ No - ${error?.message || String(error)}`);
      await prisma.$disconnect();
      return;
    }

    // Test 2: Can make API call with primary model?
    console.log('\n🧪 Test 2: Can make API call with openai/gpt-oss-120b?');
    const primaryModel = 'openai/gpt-oss-120b';
    
    try {
      const startTime = Date.now();
      const response = await Promise.race([
        client.chat.completions.create({
          model: primaryModel,
          messages: [{ role: 'user', content: 'Say "verified" only.' }],
          max_tokens: 10,
        }),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Timeout after 30 seconds')), 30000)
        ),
      ]);

      const duration = Date.now() - startTime;
      
      // Check response structure
      console.log(`  📊 Response structure:`, JSON.stringify({
        hasChoices: !!response.choices,
        choicesLength: response.choices?.length || 0,
        firstChoice: response.choices?.[0] ? {
          hasMessage: !!response.choices[0].message,
          hasContent: !!response.choices[0].message?.content,
          contentLength: response.choices[0].message?.content?.length || 0,
          finishReason: response.choices[0].finish_reason,
        } : null,
        model: response.model,
        usage: response.usage,
      }, null, 2));

      if (response.choices?.[0]?.message?.content) {
        const content = response.choices[0].message.content.trim();
        console.log(`  ✅ YES! Successfully made API call`);
        console.log(`  ⏱️  Response time: ${duration}ms`);
        console.log(`  📝 Response: "${content}"`);
        console.log(`  ✅ Key #4 is FULLY WORKING with openai/gpt-oss-120b!`);
        
        // Update metadata to reflect this
        await prisma.apiKey.update({
          where: { id: key.id },
          data: {
            metadata: {
              ...(key.metadata as any || {}),
              hasPrimaryModelAccess: true,
              canMakeApiCalls: true,
              verifiedAt: new Date().toISOString(),
              note: 'Verified - Full access to openai/gpt-oss-120b',
            },
          },
        });
        console.log(`  ✅ Updated database metadata to reflect verified status`);
      } else {
        console.log(`  ⚠️  API call succeeded but content field is empty`);
        console.log(`  📊 Checking for alternative response formats...`);
        
        // Check if content is in reasoning_content or other fields
        const fullResponse = JSON.stringify(response, null, 2);
        if (fullResponse.includes('reasoning') || fullResponse.includes('reasoning_content')) {
          console.log(`  💡 Response may contain reasoning content in a different field`);
        }
        
        // Even if content is empty, if we got a 200 response, the key has access
        if (response.choices && response.choices.length > 0) {
          console.log(`  ✅ Key has access to ${primaryModel} (got valid response structure)`);
          console.log(`  ⚠️  However, content field is empty - this may be a model response format issue`);
          
          // Update metadata to indicate partial access
          await prisma.apiKey.update({
            where: { id: key.id },
            data: {
              metadata: {
                ...(key.metadata as any || {}),
                hasPrimaryModelAccess: true, // Has access, even if response format is unusual
                canMakeApiCalls: true,
                verifiedAt: new Date().toISOString(),
                note: 'Verified - Has access to openai/gpt-oss-120b (response format may vary)',
              },
            },
          });
          console.log(`  ✅ Updated database metadata`);
        }
      }
    } catch (error: any) {
      const statusCode = error?.status || error?.response?.status;
      const errorMsg = error?.message || String(error);
      
      console.log(`  ❌ No - API call failed`);
      console.log(`  📊 Status Code: ${statusCode || 'N/A'}`);
      console.log(`  📝 Error: ${errorMsg}`);
      
      if (statusCode === 403) {
        console.log(`  ⚠️  403 Forbidden - Key does not have access to ${primaryModel}`);
      } else if (statusCode === 429) {
        console.log(`  ⚠️  429 Rate Limited - Key is valid but rate limited`);
      } else if (statusCode === 401) {
        console.log(`  ⚠️  401 Unauthorized - Key authentication failed`);
      }
    }

    // Test 3: Check what models it can actually use
    console.log('\n🔍 Test 3: Testing alternative models to see what works...');
    try {
      const models = await client.models.list();
      const testModels = models.data
        .filter((m: any) => m.id.includes('gpt') || m.id.includes('llama') || m.id.includes('mistral'))
        .slice(0, 5)
        .map((m: any) => m.id);

      let workingModels: string[] = [];
      
      for (const model of testModels) {
        try {
          const response = await Promise.race([
            client.chat.completions.create({
              model: model,
              messages: [{ role: 'user', content: 'test' }],
              max_tokens: 5,
            }),
            new Promise<never>((_, reject) => 
              setTimeout(() => reject(new Error('Timeout')), 10000)
            ),
          ]);

          if (response.choices?.[0]?.message?.content) {
            workingModels.push(model);
            console.log(`  ✅ ${model} - Works!`);
          }
        } catch {
          console.log(`  ❌ ${model} - Failed`);
        }
      }

      if (workingModels.length > 0) {
        console.log(`\n  📋 Working models: ${workingModels.join(', ')}`);
      }
    } catch (error) {
      console.log(`  ⚠️  Could not test alternative models`);
    }

    console.log('\n' + '='.repeat(80));
    console.log('\n📊 Final Status:\n');
    
    const metadata = key.metadata as any || {};
    console.log(`  Key Name: ${key.name || 'Unnamed'}`);
    console.log(`  Total Requests: ${key.totalRequests}`);
    console.log(`  Success Rate: ${key.totalRequests > 0 ? ((key.totalRequests - key.failedRequests) / key.totalRequests * 100).toFixed(1) : 0}%`);
    console.log(`  Has Primary Model Access: ${metadata.hasPrimaryModelAccess ? '✅ Yes' : '❌ No (or not verified)'}`);
    console.log(`  Can Make API Calls: ${metadata.canMakeApiCalls !== false ? '✅ Yes' : '❌ No'}`);
    
    console.log('\n');

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

verifyKey4().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

