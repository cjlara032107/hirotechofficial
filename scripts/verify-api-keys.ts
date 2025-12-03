/**
 * Verify API Keys Script
 * 
 * Verifies that API keys are in the database and can be retrieved
 */

// Load environment variables FIRST before any imports
import { config } from 'dotenv';
import { resolve } from 'path';

// Load .env.local first (highest priority), then .env
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

import { PrismaClient } from '@prisma/client';
import { ApiKeyStatus } from '@prisma/client';
import apiKeyManager from '../src/lib/ai/api-key-manager';
import { decryptKey } from '../src/lib/crypto/encryption';

// Debug: Show what env vars are loaded (without showing values)
console.log(`[Verify Script] Environment check:`);
console.log(`   DATABASE_URL: ${process.env.DATABASE_URL ? '✅ Set (' + process.env.DATABASE_URL.substring(0, 20) + '...)' : '❌ Not set'}`);
console.log(`   ENCRYPTION_KEY: ${process.env.ENCRYPTION_KEY ? '✅ Set' : '❌ Not set'}`);
console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'not set'}\n`);

// Check if DATABASE_URL is set
if (!process.env.DATABASE_URL) {
  console.error('\n❌ DATABASE_URL environment variable is not set!');
  console.error('   Please set DATABASE_URL in .env.local or .env file');
  console.error('   Or set it as an environment variable before running the script');
  console.error('\n   Example:');
  console.error('   DATABASE_URL="postgresql://user:password@host:5432/database"\n');
  process.exit(1);
}

// Check if ENCRYPTION_KEY is set
if (!process.env.ENCRYPTION_KEY) {
  console.warn('\n⚠️  ENCRYPTION_KEY environment variable is not set!');
  console.warn('   API key decryption will fail\n');
}

// Create Prisma client directly with DATABASE_URL
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});

async function verifyApiKeys() {
  console.log('\n🔍 Verifying API Keys in Database...\n');
  
  // Ensure Prisma is connected
  try {
    await prisma.$connect();
    console.log('[Verify Script] ✅ Connected to database\n');
  } catch (error) {
    console.error('❌ Failed to connect to database:', error);
    console.error('\n💡 Make sure DATABASE_URL is set correctly in .env.local or .env file');
    throw error;
  }

  try {
    // Step 1: Count keys
    const allKeys = await prisma.apiKey.findMany({
      select: {
        id: true,
        name: true,
        status: true,
        rateLimitedAt: true,
        totalRequests: true,
        failedRequests: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    console.log(`📊 Total keys in database: ${allKeys.length}`);
    console.log(`   Active: ${allKeys.filter(k => k.status === ApiKeyStatus.ACTIVE && !k.rateLimitedAt).length}`);
    console.log(`   Rate Limited: ${allKeys.filter(k => k.status === ApiKeyStatus.RATE_LIMITED || k.rateLimitedAt).length}`);
    console.log(`   Disabled: ${allKeys.filter(k => k.status === ApiKeyStatus.DISABLED).length}\n`);

    if (allKeys.length === 0) {
      console.log('❌ No API keys found in database!\n');
      console.log('💡 Add API keys using:');
      console.log('   - Browser console: fetch(\'/api/api-keys/bulk\', {...})');
      console.log('   - Or add manually in Settings → API Keys\n');
      return;
    }

    // Step 2: Get active keys list
    const activeKeys = allKeys.filter(k => k.status === ApiKeyStatus.ACTIVE && !k.rateLimitedAt);
    
    // Step 3: Test key retrieval (using direct Prisma query since apiKeyManager uses different instance)
    console.log('🔑 Testing key retrieval...\n');
    
    // Get first active key directly
    const firstActiveKey = activeKeys[0];
    if (firstActiveKey) {
      try {
        const keyRecord = await prisma.apiKey.findUnique({
          where: { id: firstActiveKey.id },
          select: { encryptedKey: true, name: true },
        });
        
        if (keyRecord && keyRecord.encryptedKey) {
          try {
            const decrypted = decryptKey(keyRecord.encryptedKey);
            if (decrypted) {
              console.log(`✅ Key retrieval works!`);
              console.log(`   Key: ${keyRecord.name || firstActiveKey.id}`);
              console.log(`   Key length: ${decrypted.length}`);
              console.log(`   Key prefix: ${decrypted.substring(0, 12)}...`);
              console.log(`   Starts with 'nvapi-': ${decrypted.startsWith('nvapi-')}\n`);
            } else {
              console.log('❌ Key decryption returned empty\n');
            }
          } catch (decryptError) {
            console.log(`❌ Key decryption failed: ${decryptError instanceof Error ? decryptError.message : String(decryptError)}\n`);
          }
        } else {
          console.log('❌ Key record not found or encryptedKey is empty\n');
        }
      } catch (error) {
        console.log(`❌ Error retrieving key: ${error instanceof Error ? error.message : String(error)}\n`);
      }
    } else {
      console.log('❌ No active keys to test\n');
    }

    // Step 4: Test decryption
    console.log('🔐 Testing key decryption...\n');
    let decryptionSuccess = 0;
    let decryptionFailures = 0;

    // Get full key records with encryptedKey
    const keysWithEncryption = await prisma.apiKey.findMany({
      where: {
        id: { in: allKeys.slice(0, 5).map(k => k.id) },
      },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
    });

    for (const keyRecord of keysWithEncryption) {
      try {
        if (!keyRecord.encryptedKey || keyRecord.encryptedKey.trim().length === 0) {
          decryptionFailures++;
          console.log(`   ❌ ${keyRecord.name || keyRecord.id}: Encrypted key is empty in database`);
          continue;
        }
        
        const decrypted = decryptKey(keyRecord.encryptedKey);
        if (decrypted && decrypted.length > 0) {
          decryptionSuccess++;
          console.log(`   ✅ ${keyRecord.name || keyRecord.id}: Decryption works (${decrypted.length} chars, prefix: ${decrypted.substring(0, 12)}...)`);
        } else {
          decryptionFailures++;
          console.log(`   ❌ ${keyRecord.name || keyRecord.id}: Decryption returned empty`);
        }
      } catch (error) {
        decryptionFailures++;
        const errorMsg = error instanceof Error ? error.message : String(error);
        console.log(`   ❌ ${keyRecord.name || keyRecord.id}: Decryption failed: ${errorMsg}`);
      }
    }

    console.log(`\n📊 Decryption test: ${decryptionSuccess} success, ${decryptionFailures} failures\n`);

    // Step 5: Display active keys
    console.log(`✅ Active keys: ${activeKeys.length}`);
    if (activeKeys.length > 0) {
      activeKeys.forEach((key, i) => {
        console.log(`   ${i + 1}. ${key.name || key.id} (requests: ${key.totalRequests}, failures: ${key.failedRequests})`);
      });
    }
    console.log('');

    // Step 6: Validate key format
    console.log('🔍 Validating key format...\n');
    let formatValid = 0;
    let formatInvalid = 0;
    
    // Get full key records with encryptedKey for format validation
    const activeKeysWithEncryption = await prisma.apiKey.findMany({
      where: {
        id: { in: activeKeys.slice(0, 5).map(k => k.id) },
      },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
    });
    
    for (const keyRecord of activeKeysWithEncryption) {
      try {
        if (!keyRecord.encryptedKey || keyRecord.encryptedKey.trim().length === 0) {
          formatInvalid++;
          console.log(`   ❌ ${keyRecord.name || keyRecord.id}: Encrypted key is empty - cannot validate format`);
          continue;
        }
        
        const decrypted = decryptKey(keyRecord.encryptedKey);
        if (decrypted) {
          if (decrypted.startsWith('nvapi-')) {
            formatValid++;
            console.log(`   ✅ ${keyRecord.name || keyRecord.id}: Valid format (starts with 'nvapi-', ${decrypted.length} chars)`);
          } else {
            formatInvalid++;
            console.log(`   ⚠️  ${keyRecord.name || keyRecord.id}: Invalid format (does not start with 'nvapi-', starts with: '${decrypted.substring(0, 10)}...')`);
          }
          
          if (decrypted.length < 30) {
            console.log(`   ⚠️  ${keyRecord.name || keyRecord.id}: Key is unusually short (${decrypted.length} chars)`);
          }
        } else {
          formatInvalid++;
          console.log(`   ❌ ${keyRecord.name || keyRecord.id}: Decryption returned empty - cannot validate format`);
        }
      } catch (error) {
        formatInvalid++;
        const errorMsg = error instanceof Error ? error.message : String(error);
        console.log(`   ❌ ${keyRecord.name || keyRecord.id}: Format validation failed: ${errorMsg}`);
      }
    }
    
    console.log(`\n📊 Format validation: ${formatValid} valid, ${formatInvalid} invalid\n`);

    // Step 7: Check encryption key
    console.log('🔐 Checking encryption configuration...\n');
    if (process.env.ENCRYPTION_KEY) {
      console.log('   ✅ ENCRYPTION_KEY environment variable is set');
      console.log(`   Key length: ${process.env.ENCRYPTION_KEY.length} chars\n`);
    } else {
      console.log('   ❌ ENCRYPTION_KEY environment variable is NOT set');
      console.log('   ⚠️  API key encryption/decryption will fail!\n');
    }

    // Step 8: Summary
    console.log('='.repeat(60));
    console.log('📋 Verification Summary\n');
    console.log(`   Total Keys: ${allKeys.length}`);
    console.log(`   Active Keys: ${activeKeys.length}`);
    console.log(`   Key Retrieval: ${firstActiveKey ? '✅ Works' : '❌ Failed'}`);
    console.log(`   Decryption: ${decryptionSuccess}/${decryptionSuccess + decryptionFailures} success`);
    console.log(`   Format Validation: ${formatValid} valid, ${formatInvalid} invalid`);
    console.log(`   Encryption Key: ${process.env.ENCRYPTION_KEY ? '✅ Set' : '❌ Missing'}\n`);

    if (activeKeys.length === 0) {
      console.log('⚠️  WARNING: No active keys found!');
      console.log('   Add API keys to enable AI analysis.\n');
    } else if (activeKeys.length < 3) {
      console.log('⚠️  WARNING: Only a few active keys.');
      console.log('   Consider adding more keys for better rate limit handling.\n');
    } else {
      console.log('✅ API keys are properly configured!\n');
    }
    
    if (!process.env.ENCRYPTION_KEY) {
      console.log('🚨 CRITICAL: ENCRYPTION_KEY is not set!');
      console.log('   API key encryption/decryption will fail.');
      console.log('   Set ENCRYPTION_KEY environment variable.\n');
    }

  } catch (error) {
    console.error('💥 Verification failed:', error);
    throw error;
  }
}

// Run verification
verifyApiKeys()
  .then(async () => {
    console.log('✨ Verification completed!');
    await prisma.$disconnect();
    process.exit(0);
  })
  .catch(async (error) => {
    console.error('💥 Verification failed:', error);
    await prisma.$disconnect().catch(() => {});
    process.exit(1);
  });

