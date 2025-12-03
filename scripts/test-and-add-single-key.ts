import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), '.env.local') });

import OpenAI from 'openai';

const NEW_KEY = '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';

async function listAvailableModels(key: string): Promise<string[]> {
  try {
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: key,
    });

    const models = await client.models.list();
    return models.data.map(m => m.id);
  } catch (error: any) {
    console.log(`  ⚠️  Could not list models: ${error?.message || String(error)}`);
    return [];
  }
}

async function testApiKey(key: string, modelName: string): Promise<{ valid: boolean; error?: string; model?: string }> {
  try {
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: key,
    });

    // Test with a simple, fast request
    const response = await Promise.race([
      client.chat.completions.create({
        model: modelName,
        messages: [{ role: 'user', content: 'Say "test" only.' }],
        max_tokens: 10,
      }),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000)
      ),
    ]);

    if (response.choices?.[0]?.message?.content) {
      return { valid: true, model: modelName };
    } else {
      return { valid: false, error: 'Empty response from API', model: modelName };
    }
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    const statusCode = error?.status || error?.response?.status;
    
    // 403 means invalid key or no access
    if (statusCode === 403) {
      return { valid: false, error: '403 Forbidden - Invalid key or no access', model: modelName };
    }
    // 429 means rate limited but key is valid
    if (statusCode === 429) {
      return { valid: true, error: 'Rate limited (key is valid)', model: modelName };
    }
    // 401 means authentication failed
    if (statusCode === 401) {
      return { valid: false, error: '401 Unauthorized - Invalid API key', model: modelName };
    }
    
    return { valid: false, error: errorMsg, model: modelName };
  }
}

async function testAndAddKey() {
  console.log('\n🔍 Testing API key...\n');
  
  const prefix = NEW_KEY.substring(0, 20) + '...';
  console.log(`Testing: ${prefix}\n`);
  
  // First, try to list available models to see if key is valid
  console.log('📋 Checking available models for this key...');
  const availableModels = await listAvailableModels(NEW_KEY);
  
  if (availableModels.length > 0) {
    console.log(`  ✅ Key is valid! Found ${availableModels.length} available models:`);
    availableModels.slice(0, 10).forEach(model => {
      console.log(`     - ${model}`);
    });
    if (availableModels.length > 10) {
      console.log(`     ... and ${availableModels.length - 10} more`);
    }
    console.log('');
  } else {
    console.log('  ⚠️  Could not list models (key may be invalid or have no model access)\n');
  }
  
  // Try the primary model we use
  const primaryModel = 'openai/gpt-oss-120b';
  console.log(`🧪 Testing with primary model: ${primaryModel}...`);
  const testResult = await testApiKey(NEW_KEY, primaryModel);
  
    if (!testResult.valid) {
      // If primary model fails, try to test with any available model to confirm key works
      if (availableModels.length > 0) {
        console.log(`\n🔄 Primary model (${primaryModel}) not available, testing with an alternative model...\n`);
        
        // Try a few common models that might be available
        const modelsToTest = availableModels
          .filter(m => m.includes('llama') || m.includes('gpt') || m.includes('mistral') || m.includes('claude'))
          .slice(0, 3);
        
        if (modelsToTest.length === 0) {
          // If no common models, just try the first available
          modelsToTest.push(availableModels[0]);
        }
        
        let keyWorks = false;
        for (const model of modelsToTest) {
          console.log(`  Testing: ${model}...`);
          const result = await testApiKey(NEW_KEY, model);
          
          if (result.valid) {
            console.log(`  ✅ Key works with ${model}${result.error ? ` (${result.error})` : ''}\n`);
            keyWorks = true;
            break;
          } else {
            console.log(`  ❌ Failed: ${result.error}\n`);
          }
        }
        
        if (keyWorks) {
          console.log(`\n✅ Key is valid and functional!`);
          console.log(`\n⚠️  IMPORTANT: This key does NOT have access to ${primaryModel} (the model our system uses).`);
          console.log(`   The key has access to ${availableModels.length} other models.`);
          console.log(`   You have two options:`);
          console.log(`   1. Get a new key with access to ${primaryModel}`);
          console.log(`   2. Update the system to use a different model that this key can access`);
          console.log(`\n💾 Adding key to database anyway (marked as limited access)...\n`);
        } else {
          console.log(`\n⚠️  Key can authenticate (can list models) but cannot make API calls.`);
          console.log(`   This may indicate:`);
          console.log(`   - Read-only access (can list but not use models)`);
          console.log(`   - Additional permissions needed`);
          console.log(`   - Rate limiting or restrictions`);
          console.log(`\n💾 Adding key to database with warning (may not be usable for API calls)...\n`);
          // Continue to add the key anyway since it can authenticate
        }
      } else {
        console.log(`\n❌ Key test failed with primary model: ${primaryModel}`);
        console.log(`   Error: ${testResult.error}`);
        console.log('\n⚠️  Key is not valid or does not have access to any models.');
        process.exit(1);
      }
    } else {
      console.log(`  ✅ Success! Key works with ${primaryModel}${testResult.error ? ` (${testResult.error})` : ''}\n`);
      console.log(`\n✅ Key is valid and working with model: ${primaryModel}!`);
      console.log('\n💾 Adding key to database...\n');
    }
  
  // Import database modules only when needed
  const { prisma } = await import('@/lib/db');
  const { encryptKey } = await import('@/lib/crypto/encryption');
  const { ApiKeyStatus } = await import('@prisma/client');
  
  // Connect to database
  try {
    await prisma.$connect();
    console.log('✅ Connected to database\n');
  } catch (error) {
    console.error('❌ Failed to connect to database:', error instanceof Error ? error.message : String(error));
    console.error('⚠️  Key was tested successfully but could not be added to database.');
    process.exit(1);
  }
  
  try {
    const encryptedKey = encryptKey(NEW_KEY);
    
    // Check if key already exists
    const existing = await prisma.apiKey.findFirst({
      where: { encryptedKey },
    });

    if (existing) {
      console.log(`⏭️  Key already exists in database (ID: ${existing.id.substring(0, 8)}...)`);
      console.log(`   Status: ${existing.status}`);
      console.log(`   Name: ${existing.name || 'Unnamed'}`);
      
      // If it's disabled, offer to reactivate
      if (existing.status !== ApiKeyStatus.ACTIVE) {
        console.log(`\n💡 Key exists but is ${existing.status}. Would you like to reactivate it?`);
      }
      
      await prisma.$disconnect();
      process.exit(0);
    }

    // Check if key has access to primary model
    const hasPrimaryModel = testResult?.valid === true;
    const canMakeApiCalls = hasPrimaryModel || (availableModels.length > 0 && testResult !== null);
    
    // Create new API key
    const apiKey = await prisma.apiKey.create({
      data: {
        name: `NVIDIA Key ${NEW_KEY.substring(0, 12)}`,
        encryptedKey,
        status: canMakeApiCalls ? ApiKeyStatus.ACTIVE : ApiKeyStatus.ACTIVE, // Still active, but note in metadata
        metadata: {
          prefix: NEW_KEY.substring(0, 12),
          length: NEW_KEY.length,
          addedAt: new Date().toISOString(),
          addedBy: 'test-script',
          hasPrimaryModelAccess: hasPrimaryModel,
          availableModelsCount: availableModels.length,
          canListModels: availableModels.length > 0,
          canMakeApiCalls: canMakeApiCalls,
          note: hasPrimaryModel 
            ? 'Full access to primary model' 
            : availableModels.length > 0
            ? 'Can list models but may have limited API call access - does not have access to openai/gpt-oss-120b'
            : 'Key authenticated but API call access uncertain',
        },
      },
    });

    console.log(`✅ Successfully added key to database!`);
    console.log(`   ID: ${apiKey.id.substring(0, 8)}...`);
    console.log(`   Name: ${apiKey.name}`);
    console.log(`   Status: ${apiKey.status}`);
    
    // Show total active keys
    const totalActive = await prisma.apiKey.count({
      where: { status: ApiKeyStatus.ACTIVE },
    });
    console.log(`\n📦 Total active keys in database: ${totalActive}`);
    console.log('\n✅ Done!\n');
    
    await prisma.$disconnect();
  } catch (error) {
    console.error(`❌ Error adding key:`, error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

testAndAddKey().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

