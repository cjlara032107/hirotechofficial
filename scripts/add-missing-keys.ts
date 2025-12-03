/**
 * Add Missing API Keys
 * Adds only the keys that are missing from the database
 */

import { PrismaClient } from '@prisma/client';
import { config } from 'dotenv';
import { resolve } from 'path';
import { encryptKey, decryptKey } from '../src/lib/crypto/encryption';

// Load environment variables
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

const prisma = new PrismaClient();

// The 20 keys you provided
const PROVIDED_KEYS = [
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

async function addMissingKeys() {
  try {
    console.log('🔍 Checking for missing keys...\n');

    // Get all existing keys from database
    const dbKeys = await prisma.apiKey.findMany({
      select: {
        id: true,
        encryptedKey: true,
      },
    });

    // Decrypt all database keys and create a set
    const existingKeys = new Set<string>();
    
    for (const dbKey of dbKeys) {
      try {
        const decrypted = decryptKey(dbKey.encryptedKey);
        existingKeys.add(decrypted);
      } catch {
        // Skip invalid keys
      }
    }

    // Find missing keys
    const missingKeys = PROVIDED_KEYS.filter(key => !existingKeys.has(key));

    if (missingKeys.length === 0) {
      console.log('✅ All keys are already in the database!');
      return;
    }

    console.log(`📋 Found ${missingKeys.length} missing keys to add:\n`);

    let added = 0;
    let skipped = 0;
    let failed = 0;

    for (let i = 0; i < missingKeys.length; i++) {
      const key = missingKeys[i];
      const keyNumber = PROVIDED_KEYS.indexOf(key) + 1;
      const keyName = `NVIDIA Key #${keyNumber}`;
      const prefix = key.substring(0, 12);

      try {
        // Encrypt the key
        const encryptedKey = encryptKey(key);

        // Create database record
        await prisma.apiKey.create({
          data: {
            name: keyName,
            encryptedKey,
            status: 'ACTIVE',
            metadata: {
              prefix: key.substring(0, 8),
              length: key.length,
              provider: 'nvidia',
            },
          },
        });

        console.log(`   ✅ Added: Key #${keyNumber} (${prefix}...)`);
        added++;
      } catch (error) {
        if (error instanceof Error && error.message.includes('Unique constraint')) {
          console.log(`   ⏭️  Skipped: Key #${keyNumber} (${prefix}...) - Already exists`);
          skipped++;
        } else {
          console.error(`   ❌ Failed: Key #${keyNumber} (${prefix}...):`, error instanceof Error ? error.message : String(error));
          failed++;
        }
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log('📊 Results:');
    console.log(`   ✅ Added: ${added}`);
    console.log(`   ⏭️  Skipped: ${skipped}`);
    console.log(`   ❌ Failed: ${failed}`);
    console.log('='.repeat(60));

    // Get final count
    const finalCount = await prisma.apiKey.count({
      where: { status: 'ACTIVE' },
    });

    console.log(`\n🎉 Total Active Keys in Database: ${finalCount}`);

  } catch (error) {
    console.error('❌ Error adding missing keys:', error);
  } finally {
    await prisma.$disconnect();
  }
}

addMissingKeys();





