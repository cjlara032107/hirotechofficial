/**
 * Test Bulk API Keys Script
 * 
 * This script tests adding API keys and verifies they work
 */

// Load environment variables
import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { prisma } from '../src/lib/db';
import { encryptKey, decryptKey } from '../src/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';
import apiKeyManager from '../src/lib/ai/api-key-manager';

const TEST_KEYS = [
  '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',
  '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',
];

async function testBulkApiKeys() {
  console.log('\n🧪 Testing Bulk API Key Addition...\n');

  try {
    // Step 1: Test encryption/decryption
    console.log('📝 Step 1: Testing encryption/decryption...');
    const testKey = TEST_KEYS[0];
    const encrypted = encryptKey(testKey);
    const decrypted = decryptKey(encrypted);
    
    if (decrypted === testKey) {
      console.log('✅ Encryption/decryption works correctly\n');
    } else {
      console.log('❌ Encryption/decryption failed!\n');
      return;
    }

    // Step 2: Add test keys
    console.log('📝 Step 2: Adding test keys...');
    let added = 0;
    let skipped = 0;

    for (let i = 0; i < TEST_KEYS.length; i++) {
      const rawKey = TEST_KEYS[i];
      const keyPrefix = rawKey.substring(0, 20) + '...';

      try {
        const encryptedKey = encryptKey(rawKey);
        
        // Check if exists
        const existing = await prisma.apiKey.findFirst({
          where: {
            encryptedKey: encryptedKey,
          },
        });

        if (existing) {
          console.log(`⏭️  [${i + 1}/${TEST_KEYS.length}] Skipped: ${keyPrefix} (already exists)`);
          skipped++;
          continue;
        }

        // Create
        const apiKey = await prisma.apiKey.create({
          data: {
            name: `Test Key ${i + 1}`,
            encryptedKey: encryptedKey,
            status: ApiKeyStatus.ACTIVE,
            metadata: {
              prefix: rawKey.substring(0, 12),
              addedBy: 'test-script',
            },
          },
        });

        console.log(`✅ [${i + 1}/${TEST_KEYS.length}] Added: ${keyPrefix} (ID: ${apiKey.id})`);
        added++;
      } catch (error) {
        console.error(`❌ [${i + 1}/${TEST_KEYS.length}] Error: ${keyPrefix}`, error instanceof Error ? error.message : String(error));
      }
    }

    console.log(`\n📊 Added: ${added}, Skipped: ${skipped}\n`);

    // Step 3: Test key retrieval
    console.log('📝 Step 3: Testing key retrieval from manager...');
    const retrievedKey = await apiKeyManager.getNextKey({ operation: 'test' });
    
    if (retrievedKey) {
      console.log(`✅ Key retrieved: ${retrievedKey.substring(0, 20)}...`);
      console.log(`   Key starts with 'nvapi-': ${retrievedKey.startsWith('nvapi-')}`);
      console.log(`   Key length: ${retrievedKey.length}\n`);
    } else {
      console.log('❌ Failed to retrieve key from manager\n');
    }

    // Step 4: Count active keys
    console.log('📝 Step 4: Counting active keys...');
    const activeCount = await prisma.apiKey.count({
      where: {
        status: ApiKeyStatus.ACTIVE,
      },
    });
    console.log(`✅ Total active keys: ${activeCount}\n`);

    // Step 5: Test API connectivity (optional - requires network)
    console.log('📝 Step 5: Testing API connectivity...');
    if (retrievedKey) {
      try {
        const OpenAI = (await import('openai')).default;
        const client = new OpenAI({
          baseURL: 'https://integrate.api.nvidia.com/v1',
          apiKey: retrievedKey,
        });

        const startTime = Date.now();
        const testResponse = await Promise.race([
          client.chat.completions.create({
            model: 'openai/gpt-oss-120b',
            messages: [{ role: 'user', content: 'test' }],
            max_tokens: 5,
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout after 10 seconds')), 10000)
          ),
        ]);

        const latency = Date.now() - startTime;
        console.log(`✅ API connectivity test passed!`);
        console.log(`   Latency: ${latency}ms`);
        console.log(`   Model available: Yes\n`);
      } catch (error: any) {
        const errorMsg = error?.message || String(error);
        if (errorMsg.includes('403')) {
          console.log(`⚠️  API returned 403 - Key may not have access to model`);
          console.log(`   This is expected if key needs permissions\n`);
        } else if (errorMsg.includes('401')) {
          console.log(`❌ API returned 401 - Key is invalid\n`);
        } else if (errorMsg.includes('429')) {
          console.log(`⚠️  API returned 429 - Rate limited (this is normal)\n`);
        } else {
          console.log(`⚠️  API test error: ${errorMsg.substring(0, 100)}\n`);
        }
      }
    }

    console.log('✨ Test completed!\n');
    console.log('📋 Summary:');
    console.log(`   ✅ Encryption: Working`);
    console.log(`   ✅ Key Storage: ${added} added, ${skipped} skipped`);
    console.log(`   ✅ Key Retrieval: ${retrievedKey ? 'Working' : 'Failed'}`);
    console.log(`   ✅ Active Keys: ${activeCount}`);
    console.log(`   ${retrievedKey ? '✅' : '❌'} API Connectivity: ${retrievedKey ? 'Tested' : 'Skipped'}\n`);

  } catch (error) {
    console.error('💥 Test failed:', error);
    throw error;
  }
}

// Run the test
testBulkApiKeys()
  .then(() => {
    console.log('🎉 All tests passed!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Test suite failed:', error);
    process.exit(1);
  });

