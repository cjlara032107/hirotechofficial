/**
 * Add 4 Working API Keys Script
 * 
 * Adds 4 additional working NVIDIA API keys
 * Update the WORKING_KEYS array with your actual keys
 */

// Load environment variables
import { config } from 'dotenv';
import { resolve } from 'path';
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { prisma } from '../src/lib/db';
import { encryptKey } from '../src/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

// TODO: Replace these with your actual 4 working API keys
const WORKING_KEYS = [
  // Add your 4 working API keys here
  // Example format:
  // 'nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  // 'nvapi-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy',
  // 'nvapi-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
  // 'nvapi-wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww',
];

async function addWorkingKeys() {
  if (WORKING_KEYS.length === 0) {
    console.log('\n⚠️  No API keys provided in WORKING_KEYS array');
    console.log('📝 Please update scripts/add-4-working-api-keys.ts with your 4 working keys\n');
    process.exit(1);
  }

  console.log('\n🚀 Adding 4 Working API Keys...\n');
  console.log(`📋 Adding ${WORKING_KEYS.length} keys\n`);

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
          name: `NVIDIA API Key ${i + 1} (Working)`,
          encryptedKey: encryptedKey,
          status: ApiKeyStatus.ACTIVE,
          metadata: {
            prefix: rawKey.substring(0, 12),
            addedBy: 'add-4-working-keys-script',
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

  return { added, skipped, errors, totalKeys };
}

// Run the script
addWorkingKeys()
  .then(({ added, totalKeys }) => {
    console.log('✨ Keys added successfully!');
    console.log(`\n📋 Next steps:`);
    console.log(`   1. Test AI analysis on a contact`);
    console.log(`   2. Check logs for successful API key usage`);
    console.log(`   3. Verify all ${totalKeys} keys are working\n`);
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Failed to add keys:', error);
    process.exit(1);
  });




