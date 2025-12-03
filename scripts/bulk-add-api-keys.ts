/**
 * Bulk Add API Keys Script
 * 
 * This script adds multiple NVIDIA API keys to the database.
 * Run with: npx tsx scripts/bulk-add-api-keys.ts
 */

import { prisma } from '../src/lib/db';
import { encryptKey } from '../src/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

const API_KEYS = [
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
  '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',
];

async function bulkAddApiKeys() {
  console.log(`\n🚀 Starting bulk API key import...\n`);
  console.log(`📋 Total keys to import: ${API_KEYS.length}\n`);

  let added = 0;
  let skipped = 0;
  let errors = 0;

  for (let i = 0; i < API_KEYS.length; i++) {
    const rawKey = API_KEYS[i];
    const keyPrefix = rawKey.substring(0, 20) + '...';

    try {
      // Check if key already exists (by checking encrypted key)
      const encryptedKey = encryptKey(rawKey);
      
      // Check if this encrypted key already exists
      const existing = await prisma.apiKey.findFirst({
        where: {
          encryptedKey: encryptedKey,
        },
      });

      if (existing) {
        console.log(`⏭️  [${i + 1}/${API_KEYS.length}] Skipped: ${keyPrefix} (already exists)`);
        skipped++;
        continue;
      }

      // Create new API key
      const apiKey = await prisma.apiKey.create({
        data: {
          name: `NVIDIA API Key ${i + 1}`,
          encryptedKey: encryptedKey,
          status: ApiKeyStatus.ACTIVE,
          metadata: {
            prefix: rawKey.substring(0, 12),
            addedBy: 'bulk-import-script',
            addedAt: new Date().toISOString(),
          },
        },
      });

      console.log(`✅ [${i + 1}/${API_KEYS.length}] Added: ${keyPrefix} (ID: ${apiKey.id})`);
      added++;

      // Small delay to avoid overwhelming the database
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      console.error(`❌ [${i + 1}/${API_KEYS.length}] Error adding ${keyPrefix}:`, error instanceof Error ? error.message : String(error));
      errors++;
    }
  }

  console.log(`\n📊 Summary:`);
  console.log(`   ✅ Added: ${added}`);
  console.log(`   ⏭️  Skipped: ${skipped}`);
  console.log(`   ❌ Errors: ${errors}`);
  console.log(`   📦 Total: ${API_KEYS.length}\n`);

  // Show final count
  const totalKeys = await prisma.apiKey.count({
    where: {
      status: ApiKeyStatus.ACTIVE,
    },
  });

  console.log(`🎉 Total active API keys in database: ${totalKeys}\n`);
}

// Run the script
bulkAddApiKeys()
  .then(() => {
    console.log('✨ Bulk import completed!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Fatal error:', error);
    process.exit(1);
  });








