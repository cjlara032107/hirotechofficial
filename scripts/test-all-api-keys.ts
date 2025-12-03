// Load environment variables FIRST before any imports
import dotenv from 'dotenv';
import path from 'path';

const envPath = path.join(process.cwd(), '.env.local');
const result = dotenv.config({ path: envPath });

if (result.error) {
  console.warn(`⚠️  Could not load .env.local from ${envPath}`);
  dotenv.config(); // Try default .env
}

// Verify DATABASE_URL is loaded
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL not found in environment variables');
  console.error('💡 Make sure .env.local exists and contains DATABASE_URL');
  process.exit(1);
}

// Now import modules that depend on environment variables
import OpenAI from 'openai';
import { prisma } from '@/lib/db';
import { decryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

async function testApiKey(key: string, keyId: string, keyName: string | null): Promise<{ 
  valid: boolean; 
  canListModels: boolean;
  canMakeCalls: boolean;
  hasPrimaryModel: boolean;
  error?: string;
  availableModels?: number;
}> {
  const result = {
    valid: false,
    canListModels: false,
    canMakeCalls: false,
    hasPrimaryModel: false,
    availableModels: 0,
  };

  try {
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: key,
    });

    // Test 1: Can list models?
    try {
      const models = await client.models.list();
      result.canListModels = true;
      result.availableModels = models.data.length;
      result.valid = true; // Key is valid if it can list models
    } catch (error: any) {
      result.error = `Cannot list models: ${error?.message || String(error)}`;
      return result;
    }

    // Test 2: Can make API calls with primary model?
    const primaryModel = 'openai/gpt-oss-120b';
    try {
      const response = await Promise.race([
        client.chat.completions.create({
          model: primaryModel,
          messages: [{ role: 'user', content: 'Say "test" only.' }],
          max_tokens: 10,
        }),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000)
        ),
      ]);

      if (response.choices?.[0]?.message?.content) {
        result.canMakeCalls = true;
        result.hasPrimaryModel = true;
        return result;
      }
    } catch (error: any) {
      const statusCode = error?.status || error?.response?.status;
      if (statusCode === 403) {
        // Try alternative models to see if key can make calls at all
        result.error = `No access to ${primaryModel}`;
      } else if (statusCode === 429) {
        result.canMakeCalls = true; // Rate limited but key works
        result.error = `Rate limited (key is valid)`;
        return result;
      } else {
        result.error = `API call failed: ${error?.message || String(error)}`;
      }
    }

    // Test 3: Try alternative models to see if key can make any calls
    if (!result.canMakeCalls) {
      try {
        const models = await client.models.list();
        const testModels = models.data
          .filter(m => m.id.includes('llama') || m.id.includes('gpt') || m.id.includes('mistral'))
          .slice(0, 3)
          .map(m => m.id);

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
              result.canMakeCalls = true;
              result.error = `Can make calls but not to ${primaryModel}`;
              break;
            }
          } catch {
            // Continue to next model
          }
        }
      } catch {
        // Ignore errors in alternative model testing
      }
    }

    return result;
  } catch (error: any) {
    result.error = error?.message || String(error);
    return result;
  }
}

async function testAllKeys() {
  console.log('\n🔍 Testing all active API keys in database...\n');

  try {
    // Use connectPrisma if available, otherwise use direct connection
    try {
      const { connectPrisma } = await import('@/lib/db');
      await connectPrisma();
    } catch {
      await prisma.$connect();
    }
    console.log('✅ Connected to database\n');
  } catch (error) {
    console.error('❌ Failed to connect to database:', error instanceof Error ? error.message : String(error));
    console.error('💡 Make sure DATABASE_URL is set in .env.local');
    process.exit(1);
  }

  try {
    const keys = await prisma.apiKey.findMany({
      where: { status: ApiKeyStatus.ACTIVE },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
        status: true,
        metadata: true,
      },
    });

    if (keys.length === 0) {
      console.log('⚠️  No active keys found in database.\n');
      await prisma.$disconnect();
      return;
    }

    console.log(`Found ${keys.length} active key(s) to test:\n`);
    console.log('='.repeat(80));

    const results: Array<{
      id: string;
      name: string | null;
      valid: boolean;
      canListModels: boolean;
      canMakeCalls: boolean;
      hasPrimaryModel: boolean;
      availableModels: number;
      error?: string;
      recommendation: string;
    }> = [];

    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const keyPrefix = key.id.substring(0, 8);
      const keyName = key.name || 'Unnamed';
      
      console.log(`\n[${i + 1}/${keys.length}] Testing: ${keyName} (${keyPrefix}...)`);
      console.log('-'.repeat(80));

      try {
        const decryptedKey = decryptKey(key.encryptedKey);
        const testResult = await testApiKey(decryptedKey, key.id, key.name);

        const recommendation = testResult.hasPrimaryModel
          ? '✅ FULLY WORKING - Ready to use'
          : testResult.canMakeCalls
          ? '⚠️  PARTIALLY WORKING - Can make calls but not to primary model'
          : testResult.canListModels
          ? '❌ READ-ONLY - Can authenticate but cannot make API calls'
          : '❌ INVALID - Cannot authenticate';

        results.push({
          id: key.id,
          name: key.name,
          ...testResult,
          recommendation,
        });

        console.log(`  Authentication: ${testResult.valid ? '✅ Valid' : '❌ Invalid'}`);
        console.log(`  Can list models: ${testResult.canListModels ? `✅ Yes (${testResult.availableModels} models)` : '❌ No'}`);
        console.log(`  Can make API calls: ${testResult.canMakeCalls ? '✅ Yes' : '❌ No'}`);
        console.log(`  Has primary model access: ${testResult.hasPrimaryModel ? '✅ Yes (openai/gpt-oss-120b)' : '❌ No'}`);
        if (testResult.error) {
          console.log(`  Error: ${testResult.error}`);
        }
        console.log(`  Status: ${recommendation}`);

        // Small delay between tests
        if (i < keys.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        console.error(`  ❌ Error testing key:`, error instanceof Error ? error.message : String(error));
        results.push({
          id: key.id,
          name: key.name,
          valid: false,
          canListModels: false,
          canMakeCalls: false,
          hasPrimaryModel: false,
          availableModels: 0,
          error: error instanceof Error ? error.message : String(error),
          recommendation: '❌ ERROR - Failed to test',
        });
      }
    }

    console.log('\n' + '='.repeat(80));
    console.log('\n📊 SUMMARY:\n');

    const fullyWorking = results.filter(r => r.hasPrimaryModel);
    const partiallyWorking = results.filter(r => r.canMakeCalls && !r.hasPrimaryModel);
    const readOnly = results.filter(r => r.canListModels && !r.canMakeCalls);
    const invalid = results.filter(r => !r.valid);

    console.log(`✅ Fully Working (can use primary model): ${fullyWorking.length}`);
    fullyWorking.forEach(r => {
      console.log(`   - ${r.name || 'Unnamed'} (${r.id.substring(0, 8)}...)`);
    });

    console.log(`\n⚠️  Partially Working (can make calls but not to primary model): ${partiallyWorking.length}`);
    partiallyWorking.forEach(r => {
      console.log(`   - ${r.name || 'Unnamed'} (${r.id.substring(0, 8)}...) - ${r.error || 'No primary model access'}`);
    });

    console.log(`\n📖 Read-Only (can authenticate but cannot make calls): ${readOnly.length}`);
    readOnly.forEach(r => {
      console.log(`   - ${r.name || 'Unnamed'} (${r.id.substring(0, 8)}...) - ${r.error || 'Read-only access'}`);
    });

    console.log(`\n❌ Invalid (cannot authenticate): ${invalid.length}`);
    invalid.forEach(r => {
      console.log(`   - ${r.name || 'Unnamed'} (${r.id.substring(0, 8)}...) - ${r.error || 'Invalid key'}`);
    });

    console.log(`\n📦 Total Keys: ${results.length}`);
    console.log(`✅ Usable Keys: ${fullyWorking.length + partiallyWorking.length}`);
    console.log(`❌ Unusable Keys: ${readOnly.length + invalid.length}`);

    if (fullyWorking.length === 0) {
      console.log('\n⚠️  WARNING: No fully working keys found!');
      console.log('   You need at least one key with access to openai/gpt-oss-120b for the system to work.');
    } else {
      console.log(`\n✅ You have ${fullyWorking.length} fully working key(s) ready to use!`);
    }

    console.log('\n');

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

testAllKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

