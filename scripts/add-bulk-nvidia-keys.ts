/**
 * Script to add multiple NVIDIA API keys to database in bulk
 * Usage: npx tsx scripts/add-bulk-nvidia-keys.ts
 */

// Load environment variables
import { config } from 'dotenv';
import { resolve } from 'path';

// Load .env.local first, then .env
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { prisma } from '../src/lib/db';
import { encryptKey, decryptKey } from '../src/lib/crypto/encryption';

// Your 20 NVIDIA API keys
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
];

async function addBulkNvidiaKeys() {
  try {
    console.log('🚀 Adding 20 NVIDIA API keys to database...\n');
    console.log('='.repeat(60));

    // Check encryption key
    if (!process.env.ENCRYPTION_KEY) {
      console.error('❌ ENCRYPTION_KEY not found in environment variables');
      console.log('\n💡 Generate an encryption key:');
      console.log('   node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
      console.log('\n   Then add to .env.local:');
      console.log('   ENCRYPTION_KEY=<generated_key>');
      process.exit(1);
    }

    console.log('✅ Encryption key found\n');

    // Get existing keys to check for duplicates
    console.log('🔍 Checking for existing keys...');
    const existingKeys = await prisma.apiKey.findMany({
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
    });

    console.log(`   Found ${existingKeys.length} existing key(s) in database\n`);

    // Track results
    const results = {
      added: 0,
      skipped: 0,
      failed: 0,
    };

    // Add each key
    console.log('📝 Processing keys...\n');
    for (let i = 0; i < API_KEYS.length; i++) {
      const apiKey = API_KEYS[i];
      const keyNumber = i + 1;
      const keyName = `NVIDIA Key #${keyNumber}`;
      const keyPrefix = apiKey.substring(0, 12);

      try {
        // Check for duplicates
        let duplicate = false;
        for (const existingKey of existingKeys) {
          try {
            const decrypted = decryptKey(existingKey.encryptedKey);
            if (decrypted === apiKey) {
              duplicate = true;
              console.log(`⏭️  Key #${keyNumber} (${keyPrefix}...): Already exists, skipping`);
              results.skipped++;
              break;
            }
          } catch {
            // Decryption failed, not a duplicate
          }
        }

        if (duplicate) {
          continue;
        }

        // Encrypt the key
        const encryptedKey = encryptKey(apiKey);

        // Create database record
        const apiKeyRecord = await prisma.apiKey.create({
          data: {
            name: keyName,
            encryptedKey,
            status: 'ACTIVE',
            metadata: {
              prefix: apiKey.substring(0, 8),
              length: apiKey.length,
              provider: 'nvidia',
            },
          },
        });

        console.log(`✅ Key #${keyNumber} (${keyPrefix}...): Added successfully`);
        results.added++;
      } catch (error) {
        console.error(`❌ Key #${keyNumber} (${keyPrefix}...): Failed to add`);
        if (error instanceof Error) {
          console.error(`   Error: ${error.message}`);
        }
        results.failed++;
      }
    }

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 Summary:');
    console.log(`   ✅ Added: ${results.added}`);
    console.log(`   ⏭️  Skipped (duplicates): ${results.skipped}`);
    console.log(`   ❌ Failed: ${results.failed}`);
    console.log(`   📦 Total: ${API_KEYS.length}`);

    // Get final count
    const finalCount = await prisma.apiKey.count({
      where: {
        status: 'ACTIVE',
      },
    });

    console.log(`\n🎉 Success! You now have ${finalCount} active API key(s) in the database.`);
    console.log('\n💡 The system will automatically rotate through these keys for:');
    console.log('   - Faster AI processing (parallel requests)');
    console.log('   - Better rate limit handling');
    console.log('   - Automatic failover if a key gets rate-limited\n');
  } catch (error) {
    console.error('\n❌ Fatal error:');
    if (error instanceof Error) {
      console.error(`   ${error.message}`);
      
      if (error.message.includes('ENCRYPTION_KEY')) {
        console.error('\n💡 Tip: Make sure ENCRYPTION_KEY is set in your .env.local file');
        console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
      }
    } else {
      console.error('   Unknown error:', error);
    }
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Run the script
addBulkNvidiaKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

