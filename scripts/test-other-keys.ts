/**
 * Test Keys #1, #2, #3 to see why they're not working
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

async function testKey(decryptedKey: string, keyId: string, keyName: string | null, keyNumber: number) {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`\n🔍 Testing Key #${keyNumber}: ${keyName || 'Unnamed'}`);
  console.log(`   ID: ${keyId.substring(0, 12)}...`);
  console.log(`   Key: ${decryptedKey.substring(0, 20)}...`);
  console.log(`\n${'-'.repeat(80)}\n`);

  const client = new OpenAI({
    baseURL: 'https://integrate.api.nvidia.com/v1',
    apiKey: decryptedKey,
  });

  const results = {
    canListModels: false,
    canMakeCalls: false,
    hasPrimaryModel: false,
    errors: [] as string[],
    availableModels: 0,
  };

  // Test 1: Can list models?
  console.log('📋 Test 1: Can list models?');
  try {
    const models = await client.models.list();
    results.canListModels = true;
    results.availableModels = models.data.length;
    console.log(`  ✅ Yes! Found ${models.data.length} available models`);
    
    // Check if primary model is in the list
    const hasPrimaryModel = models.data.some((m: any) => m.id === 'openai/gpt-oss-120b');
    if (hasPrimaryModel) {
      console.log(`  ✅ Primary model (openai/gpt-oss-120b) is in the list`);
    } else {
      console.log(`  ❌ Primary model (openai/gpt-oss-120b) is NOT in the list`);
      results.errors.push('Primary model not available');
    }
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    const statusCode = error?.status || error?.response?.status;
    console.log(`  ❌ No - Cannot list models`);
    console.log(`     Status: ${statusCode || 'N/A'}`);
    console.log(`     Error: ${errorMsg}`);
    results.errors.push(`Cannot list models: ${errorMsg} (${statusCode || 'N/A'})`);
    return results; // Can't proceed if we can't list models
  }

  // Test 2: Can make API call with primary model?
  console.log(`\n🧪 Test 2: Can make API call with openai/gpt-oss-120b?`);
  const primaryModel = 'openai/gpt-oss-120b';
  
  try {
    const response = await Promise.race([
      client.chat.completions.create({
        model: primaryModel,
        messages: [{ role: 'user', content: 'Say "test" only.' }],
        max_tokens: 10,
      }),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('Timeout after 30 seconds')), 30000)
      ),
    ]);

    if (response.choices?.[0]?.message?.content) {
      results.canMakeCalls = true;
      results.hasPrimaryModel = true;
      console.log(`  ✅ YES! Successfully made API call`);
      console.log(`  📝 Response: "${response.choices[0].message.content.trim()}"`);
    } else {
      // Check if we got a valid response structure even without content
      if (response.choices && response.choices.length > 0) {
        results.canMakeCalls = true;
        results.hasPrimaryModel = true;
        console.log(`  ✅ API call succeeded (got response structure)`);
        console.log(`  ⚠️  Content field is empty (may be in different field)`);
        console.log(`  📊 Tokens used: ${response.usage?.completion_tokens || 0}`);
      } else {
        console.log(`  ❌ API call returned invalid structure`);
        results.errors.push('Invalid response structure');
      }
    }
  } catch (error: any) {
    const statusCode = error?.status || error?.response?.status;
    const errorMsg = error?.message || String(error);
    
    console.log(`  ❌ No - API call failed`);
    console.log(`     Status Code: ${statusCode || 'N/A'}`);
    console.log(`     Error: ${errorMsg}`);
    
    if (statusCode === 403) {
      console.log(`     💡 403 Forbidden typically means:`);
      console.log(`        - Key does not have access to this model`);
      console.log(`        - Key has read-only permissions`);
      console.log(`        - Model requires special access/permissions`);
      results.errors.push(`403 Forbidden - No access to ${primaryModel}`);
    } else if (statusCode === 429) {
      console.log(`     💡 429 Rate Limited - Key is valid but rate limited`);
      results.canMakeCalls = true; // Key works, just rate limited
      results.errors.push('Rate limited (key is valid)');
    } else if (statusCode === 401) {
      console.log(`     💡 401 Unauthorized - Key authentication failed`);
      results.errors.push('401 Unauthorized - Invalid key');
    } else {
      results.errors.push(`API call failed: ${errorMsg} (${statusCode || 'N/A'})`);
    }
  }

  // Test 3: Try alternative models to see if key can make ANY calls
  if (!results.canMakeCalls) {
    console.log(`\n🔍 Test 3: Testing alternative models to see if key can make ANY API calls...`);
    try {
      const models = await client.models.list();
      const testModels = models.data
        .filter((m: any) => m.id.includes('llama') || m.id.includes('gpt') || m.id.includes('mistral'))
        .slice(0, 3)
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
            results.canMakeCalls = true;
          }
        } catch (error: any) {
          const statusCode = error?.status || error?.response?.status;
          console.log(`  ❌ ${model} - Failed (${statusCode || 'N/A'})`);
        }
      }

      if (workingModels.length > 0) {
        console.log(`\n  📋 Key CAN make API calls to: ${workingModels.join(', ')}`);
        console.log(`  ⚠️  But NOT to openai/gpt-oss-120b`);
        results.errors.push(`Can make calls to other models but not primary model`);
      } else {
        console.log(`\n  ❌ Key cannot make API calls to ANY tested models`);
        results.errors.push('Cannot make API calls to any models (read-only access)');
      }
    } catch (error) {
      console.log(`  ⚠️  Could not test alternative models`);
    }
  }

  return results;
}

async function testOtherKeys() {
  console.log('\n🔍 Testing Keys #1, #2, #3 to diagnose why they\'re not working...\n');

  try {
    // Find the 3 keys that are not working (excluding key #4)
    const allKeys = await prisma.apiKey.findMany({
      where: { status: 'ACTIVE' },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
        totalRequests: true,
        metadata: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    // Exclude key #4 (the working one)
    const otherKeys = allKeys.filter(k => !k.id.startsWith('cmina3jir000'));

    if (otherKeys.length === 0) {
      console.log('⚠️  No other keys found to test.\n');
      await prisma.$disconnect();
      return;
    }

    console.log(`Found ${otherKeys.length} other key(s) to test:\n`);

    // Import decryptKey
    const encryptionModule = await import('../src/lib/crypto/encryption');
    const decryptKey = encryptionModule.decryptKey;

    const allResults: Array<{
      keyId: string;
      keyName: string | null;
      results: any;
      recommendation: string;
    }> = [];

    for (let i = 0; i < otherKeys.length; i++) {
      const key = otherKeys[i];
      const decryptedKey = decryptKey(key.encryptedKey);
      const results = await testKey(decryptedKey, key.id, key.name, i + 1);
      
      let recommendation = '';
      if (results.hasPrimaryModel) {
        recommendation = '✅ FULLY WORKING - Ready to use';
      } else if (results.canMakeCalls) {
        recommendation = '⚠️  PARTIALLY WORKING - Can make calls but not to primary model';
      } else if (results.canListModels) {
        recommendation = '❌ READ-ONLY - Can authenticate but cannot make API calls';
      } else {
        recommendation = '❌ INVALID - Cannot authenticate';
      }

      allResults.push({
        keyId: key.id,
        keyName: key.name,
        results,
        recommendation,
      });

      // Small delay between tests
      if (i < otherKeys.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    console.log(`\n${'='.repeat(80)}`);
    console.log('\n📊 SUMMARY OF ISSUES:\n');

    for (let i = 0; i < allResults.length; i++) {
      const { keyName, results, recommendation } = allResults[i];
      console.log(`\nKey #${i + 1}: ${keyName || 'Unnamed'}`);
      console.log(`  Status: ${recommendation}`);
      console.log(`  Can list models: ${results.canListModels ? '✅' : '❌'}`);
      console.log(`  Can make API calls: ${results.canMakeCalls ? '✅' : '❌'}`);
      console.log(`  Has primary model access: ${results.hasPrimaryModel ? '✅' : '❌'}`);
      if (results.errors.length > 0) {
        console.log(`  Errors:`);
        results.errors.forEach((err: string) => {
          console.log(`    - ${err}`);
        });
      }
    }

    console.log(`\n${'='.repeat(80)}`);
    console.log('\n💡 DIAGNOSIS:\n');

    const readOnlyKeys = allResults.filter(r => r.results.canListModels && !r.results.canMakeCalls);
    const noPrimaryModelKeys = allResults.filter(r => r.results.canMakeCalls && !r.results.hasPrimaryModel);
    const invalidKeys = allResults.filter(r => !r.results.canListModels);

    if (readOnlyKeys.length > 0) {
      console.log(`📖 Read-Only Keys (${readOnlyKeys.length}):`);
      console.log(`   These keys can authenticate and list models, but cannot make API calls.`);
      console.log(`   Possible causes:`);
      console.log(`   - Keys have read-only permissions in NVIDIA account`);
      console.log(`   - Keys need additional API call permissions enabled`);
      console.log(`   - Keys may be restricted to certain operations`);
      console.log(`   Solution: Check NVIDIA account settings and enable API call permissions\n`);
    }

    if (noPrimaryModelKeys.length > 0) {
      console.log(`⚠️  Keys Without Primary Model Access (${noPrimaryModelKeys.length}):`);
      console.log(`   These keys can make API calls but not to openai/gpt-oss-120b.`);
      console.log(`   Possible causes:`);
      console.log(`   - Model requires special access/permissions`);
      console.log(`   - Model may not be available for this key tier`);
      console.log(`   - Key may need to request access to this specific model`);
      console.log(`   Solution: Request access to openai/gpt-oss-120b in NVIDIA account\n`);
    }

    if (invalidKeys.length > 0) {
      console.log(`❌ Invalid Keys (${invalidKeys.length}):`);
      console.log(`   These keys cannot even authenticate.`);
      console.log(`   Possible causes:`);
      console.log(`   - Keys are expired or revoked`);
      console.log(`   - Keys are invalid or malformed`);
      console.log(`   Solution: Generate new keys from NVIDIA account\n`);
    }

    console.log('\n');

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

testOtherKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});




