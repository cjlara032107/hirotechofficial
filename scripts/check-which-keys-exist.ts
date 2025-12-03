/**
 * Check Which API Keys Exist
 * Compares provided keys with database to see which are already stored
 */

import { PrismaClient } from '@prisma/client';
import { config } from 'dotenv';
import { resolve } from 'path';
import { decryptKey } from '../src/lib/crypto/encryption';

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

async function checkWhichKeysExist() {
  try {
    console.log('🔍 Checking which keys exist in database...\n');
    console.log(`📋 Provided keys: ${PROVIDED_KEYS.length}\n`);

    // Get all keys from database
    const dbKeys = await prisma.apiKey.findMany({
      select: {
        id: true,
        name: true,
        encryptedKey: true,
        status: true,
      },
    });

    console.log(`💾 Database keys: ${dbKeys.length}\n`);

    // Decrypt all database keys and create a map
    const dbKeyMap = new Map<string, { id: string; name: string | null; status: string }>();
    
    for (const dbKey of dbKeys) {
      try {
        const decrypted = decryptKey(dbKey.encryptedKey);
        dbKeyMap.set(decrypted, {
          id: dbKey.id,
          name: dbKey.name,
          status: dbKey.status,
        });
      } catch (error) {
        console.warn(`⚠️  Failed to decrypt key ${dbKey.id}:`, error);
      }
    }

    // Check each provided key
    const existing: Array<{ key: string; prefix: string; dbInfo: { id: string; name: string | null; status: string } }> = [];
    const missing: Array<{ key: string; prefix: string }> = [];

    for (const providedKey of PROVIDED_KEYS) {
      const prefix = providedKey.substring(0, 12);
      const dbInfo = dbKeyMap.get(providedKey);
      
      if (dbInfo) {
        existing.push({
          key: providedKey,
          prefix,
          dbInfo,
        });
      } else {
        missing.push({
          key: providedKey,
          prefix,
        });
      }
    }

    // Display results
    console.log('='.repeat(80));
    console.log('✅ EXISTING KEYS (Already in database):');
    console.log('='.repeat(80));
    
    if (existing.length === 0) {
      console.log('   None found');
    } else {
      existing.forEach((item, index) => {
        const statusIcon = item.dbInfo.status === 'ACTIVE' ? '✅' : 
                          item.dbInfo.status === 'RATE_LIMITED' ? '⏸️' : 
                          item.dbInfo.status === 'DISABLED' ? '❌' : '❓';
        console.log(`   ${index + 1}. ${statusIcon} ${item.prefix}... (${item.dbInfo.status}) - ${item.dbInfo.name || 'unnamed'}`);
      });
    }

    console.log('\n' + '='.repeat(80));
    console.log('❌ MISSING KEYS (Not in database):');
    console.log('='.repeat(80));
    
    if (missing.length === 0) {
      console.log('   None - All keys are in database!');
    } else {
      missing.forEach((item, index) => {
        console.log(`   ${index + 1}. ${item.prefix}...`);
      });
    }

    console.log('\n' + '='.repeat(80));
    console.log('📊 SUMMARY:');
    console.log('='.repeat(80));
    console.log(`   Total provided: ${PROVIDED_KEYS.length}`);
    console.log(`   ✅ Existing: ${existing.length}`);
    console.log(`   ❌ Missing: ${missing.length}`);
    console.log('='.repeat(80));

    // Show status breakdown of existing keys
    if (existing.length > 0) {
      const statusCounts = {
        ACTIVE: existing.filter(e => e.dbInfo.status === 'ACTIVE').length,
        RATE_LIMITED: existing.filter(e => e.dbInfo.status === 'RATE_LIMITED').length,
        DISABLED: existing.filter(e => e.dbInfo.status === 'DISABLED').length,
      };
      
      console.log('\n📈 Status of existing keys:');
      console.log(`   ✅ ACTIVE: ${statusCounts.ACTIVE}`);
      console.log(`   ⏸️  RATE_LIMITED: ${statusCounts.RATE_LIMITED}`);
      console.log(`   ❌ DISABLED: ${statusCounts.DISABLED}`);
    }

    // Offer to add missing keys
    if (missing.length > 0) {
      console.log('\n💡 To add missing keys, run:');
      console.log('   npm run add-missing-keys');
    }

  } catch (error) {
    console.error('❌ Error checking keys:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkWhichKeysExist();













