/**
 * Add Working API Keys Script
 * 
 * Adds the 2 working keys that have access to gpt-oss-120b
 */

// Load environment variables
import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { prisma } from '../src/lib/db';
import { encryptKey } from '../src/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

const WORKING_KEYS = [
  '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',
  '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',
];

async function addWorkingKeys() {
  console.log('\n🚀 Adding Working API Keys...\n');
  console.log(`📋 Adding ${WORKING_KEYS.length} keys that work with gpt-oss-120b\n`);

  let added = 0;
  let skipped = 0;
  let errors = 0;

  for (let i = 0; i < WORKING_KEYS.length; i++) {
    const rawKey = WORKING_KEYS[i];
    const keyPrefix = rawKey.substring(0, 20) + '...';

    try {
      // Encrypt the key
      const encryptedKey = encryptKey(rawKey);
      
      // Check if key already exists
      const existing = await prisma.apiKey.findFirst({
        where: {
          encryptedKey: encryptedKey,
        },
      });

      if (existing) {
        console.log(`⏭️  [${i + 1}/${WORKING_KEYS.length}] Skipped: ${keyPrefix} (already exists)`);
        skipped++;
        continue;
      }

      // Create new API key
      const apiKey = await prisma.apiKey.create({
        data: {
          name: `NVIDIA API Key ${i + 1} (gpt-oss-120b)`,
          encryptedKey: encryptedKey,
          status: ApiKeyStatus.ACTIVE,
          metadata: {
            prefix: rawKey.substring(0, 12),
            model: 'openai/gpt-oss-120b',
            addedBy: 'working-keys-script',
            addedAt: new Date().toISOString(),
            tested: true,
            working: true,
          },
        },
      });

      console.log(`✅ [${i + 1}/${WORKING_KEYS.length}] Added: ${keyPrefix} (ID: ${apiKey.id})`);
      added++;

      // Small delay
      await new Promise(resolve => setTimeout(resolve, 200));
    } catch (error) {
      console.error(`❌ [${i + 1}/${WORKING_KEYS.length}] Error adding ${keyPrefix}:`, error instanceof Error ? error.message : String(error));
      errors++;
    }
  }

  console.log(`\n📊 Summary:`);
  console.log(`   ✅ Added: ${added}`);
  console.log(`   ⏭️  Skipped: ${skipped}`);
  console.log(`   ❌ Errors: ${errors}`);
  console.log(`   📦 Total: ${WORKING_KEYS.length}\n`);

  // Show final count
  const totalKeys = await prisma.apiKey.count({
    where: {
      status: ApiKeyStatus.ACTIVE,
    },
  });

  console.log(`🎉 Total active API keys in database: ${totalKeys}\n`);

  // Verify keys are accessible
  console.log('🔍 Verifying keys are accessible...\n');
  try {
    const { default: apiKeyManager } = await import('../src/lib/ai/api-key-manager');
    const testKey = await apiKeyManager.getNextKey({ operation: 'verification' });
    
    if (testKey) {
      console.log(`✅ Key retrieval works: ${testKey.substring(0, 20)}...`);
      console.log(`   Key starts with 'nvapi-': ${testKey.startsWith('nvapi-')}`);
      console.log(`   Key length: ${testKey.length}\n`);
    } else {
      console.log('⚠️  Could not retrieve key (may need to refresh cache)\n');
    }
  } catch (error) {
    console.log('⚠️  Could not verify key retrieval:', error instanceof Error ? error.message : String(error));
  }

  return { added, skipped, errors, totalKeys };
}

// Run the script
addWorkingKeys()
  .then(({ added, totalKeys }) => {
    console.log('✨ Keys added successfully!');
    console.log(`\n📋 Next steps:`);
    console.log(`   1. Test AI analysis on a contact`);
    console.log(`   2. Check logs for "[Fast AI] ✅ Analysis successful"`);
    console.log(`   3. Verify detailed analysis output (not fallback scoring)\n`);
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Failed to add keys:', error);
    process.exit(1);
  });








