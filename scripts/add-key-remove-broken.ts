/**
 * Script to add new working API key and remove 3 broken ones
 * 
 * Usage: npx tsx scripts/add-key-remove-broken.ts
 * 
 * Requires:
 * - DATABASE_URL in environment
 * - ENCRYPTION_KEY in environment
 */

import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
const envPaths = [
  path.join(process.cwd(), '.env.local'),
  path.join(process.cwd(), '.env'),
];

for (const envPath of envPaths) {
  try {
    dotenv.config({ path: envPath });
  } catch {
    // Ignore if file doesn't exist
  }
}

// Check required environment variables
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is required!');
  console.error('   Please set DATABASE_URL in your .env.local file.');
  process.exit(1);
}

if (!process.env.ENCRYPTION_KEY) {
  console.error('❌ ENCRYPTION_KEY environment variable is required!');
  console.error('   Please set ENCRYPTION_KEY in your .env.local file.');
  process.exit(1);
}

import OpenAI from 'openai';
import { prisma } from '@/lib/db';
import { encryptKey, decryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

const NEW_KEY = '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';

async function testApiKey(key: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: key,
    });

    const response = await Promise.race([
      client.chat.completions.create({
        model: 'meta/llama-3.1-8b-instruct',
        messages: [{ role: 'user', content: 'Say "test" only.' }],
        max_tokens: 10,
      }),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('Timeout after 10 seconds')), 10000)
      ),
    ]);

    const content = response.choices?.[0]?.message?.content;
    return { valid: content && content.trim().length > 0 };
  } catch (error: any) {
    const statusCode = error?.status || error?.response?.status;
    if (statusCode === 401 || statusCode === 403) {
      return { valid: false, error: `Invalid key (${statusCode})` };
    }
    if (statusCode === 429) {
      return { valid: true, error: 'Rate limited (key is valid)' };
    }
    return { valid: false, error: error?.message || String(error) };
  }
}

async function main() {
  console.log('='.repeat(70));
  console.log('🔧 Add New Key & Remove Broken Keys');
  console.log('='.repeat(70));
  console.log('');

  try {
    await prisma.$connect();
    console.log('✅ Connected to database\n');

    // Step 1: Get all active keys
    console.log('📋 Step 1: Fetching active API keys...');
    const activeKeys = await prisma.apiKey.findMany({
      where: { status: ApiKeyStatus.ACTIVE },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    console.log(`   Found ${activeKeys.length} active key(s)\n`);

    // Step 2: Test all existing keys
    const invalidKeys: Array<{ id: string; name: string | null }> = [];
    
    if (activeKeys.length > 0) {
      console.log('🧪 Step 2: Testing existing API keys...\n');
      
      for (let i = 0; i < activeKeys.length; i++) {
        const key = activeKeys[i];
        const keyName = key.name || key.id.substring(0, 12);
        
        process.stdout.write(`   [${i + 1}/${activeKeys.length}] Testing ${keyName}... `);
        
        try {
          const decryptedKey = decryptKey(key.encryptedKey);
          const testResult = await testApiKey(decryptedKey);
          
          if (testResult.valid) {
            console.log('✅ Valid');
          } else {
            console.log(`❌ Invalid (${testResult.error || 'Test failed'})`);
            invalidKeys.push({ id: key.id, name: key.name });
          }
        } catch (error: any) {
          console.log(`❌ Error: ${error.message}`);
          invalidKeys.push({ id: key.id, name: key.name });
        }
        
        if (i < activeKeys.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      }
      console.log('');
    }

    // Step 3: Remove up to 3 invalid keys
    if (invalidKeys.length > 0) {
      const keysToRemove = invalidKeys.slice(0, 3);
      console.log(`🗑️  Step 3: Removing ${keysToRemove.length} invalid key(s)...\n`);
      
      for (const key of keysToRemove) {
        try {
          await prisma.apiKey.delete({
            where: { id: key.id },
          });
          console.log(`   ✅ Removed: ${key.name || key.id.substring(0, 12)}`);
        } catch (error: any) {
          console.log(`   ❌ Failed to remove ${key.name || key.id}: ${error.message}`);
        }
      }
      console.log('');
    } else {
      console.log('⚠️  No invalid keys found to remove.\n');
    }

    // Step 4: Add new key
    console.log('➕ Step 4: Adding new API key...');
    
    // Check if key already exists
    const encryptedNewKey = encryptKey(NEW_KEY);
    const existing = await prisma.apiKey.findFirst({
      where: { encryptedKey: encryptedNewKey },
    });

    if (existing) {
      console.log(`   ⏭️  Key already exists (ID: ${existing.id.substring(0, 12)}...)\n`);
    } else {
      // Test the new key first
      console.log('   Testing new key...');
      const testResult = await testApiKey(NEW_KEY);
      
      if (!testResult.valid) {
        console.log(`   ❌ New key test failed: ${testResult.error}`);
        console.log('   ⚠️  Not adding invalid key to database\n');
      } else {
        console.log('   ✅ New key is valid');
        
        const apiKey = await prisma.apiKey.create({
          data: {
            name: 'NVIDIA API Key (Working)',
            encryptedKey: encryptedNewKey,
            status: ApiKeyStatus.ACTIVE,
            metadata: {
              prefix: NEW_KEY.substring(0, 12),
              length: NEW_KEY.length,
              addedAt: new Date().toISOString(),
              addedBy: 'add-key-remove-broken-script',
            },
          },
        });

        console.log(`   ✅ Added new key (ID: ${apiKey.id.substring(0, 12)}...)\n`);
      }
    }

    // Final summary
    const finalCount = await prisma.apiKey.count({
      where: { status: ApiKeyStatus.ACTIVE },
    });

    console.log('='.repeat(70));
    console.log('📊 Summary');
    console.log('='.repeat(70));
    console.log(`Total active keys: ${finalCount}`);
    console.log('='.repeat(70));
    console.log('');

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});




