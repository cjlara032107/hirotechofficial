import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from multiple possible locations
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

// Also load from process.env (for Vercel/production)
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is required!');
  console.error('   Please set DATABASE_URL in your .env.local file or environment variables.');
  process.exit(1);
}

import OpenAI from 'openai';
import { prisma } from '@/lib/db';
import { encryptKey, decryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

const NEW_KEY = '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';

async function testApiKey(key: string): Promise<{ valid: boolean; error?: string; responseTime?: number }> {
  const startTime = Date.now();
  
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

    const responseTime = Date.now() - startTime;
    const content = response.choices?.[0]?.message?.content;
    
    if (content && content.trim().length > 0) {
      return { valid: true, responseTime };
    } else {
      return { valid: false, error: 'Empty response', responseTime };
    }
  } catch (error: any) {
    const responseTime = Date.now() - startTime;
    const statusCode = error?.status || error?.response?.status;
    const errorMsg = error?.message || String(error);
    
    if (statusCode === 401 || statusCode === 403) {
      return { valid: false, error: `Invalid key (${statusCode})`, responseTime };
    }
    if (statusCode === 429) {
      return { valid: true, error: 'Rate limited (key is valid)', responseTime };
    }
    
    return { valid: false, error: errorMsg.substring(0, 100), responseTime };
  }
}

async function manageApiKeys() {
  console.log('='.repeat(70));
  console.log('🔧 API Key Management');
  console.log('='.repeat(70));
  console.log('');

  try {
    // Connect to database
    await prisma.$connect();
    console.log('✅ Connected to database\n');

    // Step 1: Get all active API keys
    console.log('📋 Step 1: Fetching all active API keys...');
    const allKeys = await prisma.apiKey.findMany({
      where: {
        status: ApiKeyStatus.ACTIVE,
      },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    console.log(`   Found ${allKeys.length} active key(s)\n`);

    if (allKeys.length === 0) {
      console.log('⚠️  No active keys found. Adding new key only.\n');
    } else {
      // Step 2: Test all existing keys
      console.log('🧪 Step 2: Testing existing API keys...\n');
      const testResults: Array<{ key: typeof allKeys[0]; valid: boolean; error?: string }> = [];

      for (let i = 0; i < allKeys.length; i++) {
        const key = allKeys[i];
        const keyPrefix = key.name || key.id.substring(0, 12);
        
        process.stdout.write(`   [${i + 1}/${allKeys.length}] Testing ${keyPrefix}... `);
        
        try {
          const decryptedKey = decryptKey(key.encryptedKey);
          const testResult = await testApiKey(decryptedKey);
          testResults.push({ key, valid: testResult.valid, error: testResult.error });
          
          if (testResult.valid) {
            console.log(`✅ (${testResult.responseTime}ms)`);
          } else {
            console.log(`❌ (${testResult.error})`);
          }
        } catch (error: any) {
          console.log(`❌ (Decryption error: ${error.message})`);
          testResults.push({ key, valid: false, error: `Decryption failed: ${error.message}` });
        }
        
        // Small delay to avoid rate limits
        if (i < allKeys.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      }

      // Step 3: Identify invalid keys
      const invalidKeys = testResults.filter(r => !r.valid);
      console.log(`\n   Found ${invalidKeys.length} invalid key(s)\n`);

      // Step 4: Remove 3 invalid keys (or all if less than 3)
      if (invalidKeys.length > 0) {
        const keysToRemove = invalidKeys.slice(0, 3);
        console.log(`🗑️  Step 3: Removing ${keysToRemove.length} invalid key(s)...\n`);
        
        for (const { key } of keysToRemove) {
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
    }

    // Step 5: Add new key
    console.log('➕ Step 4: Adding new API key...');
    
    // Check if new key already exists
    const encryptedNewKey = encryptKey(NEW_KEY);
    const existing = await prisma.apiKey.findFirst({
      where: {
        encryptedKey: encryptedNewKey,
      },
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
        console.log(`   ✅ New key is valid (${testResult.responseTime}ms)`);
        
        // Add the new key
        const apiKey = await prisma.apiKey.create({
          data: {
            name: 'NVIDIA API Key (Working)',
            encryptedKey: encryptedNewKey,
            status: ApiKeyStatus.ACTIVE,
            metadata: {
              prefix: NEW_KEY.substring(0, 12),
              length: NEW_KEY.length,
              addedAt: new Date().toISOString(),
              addedBy: 'manage-api-keys-script',
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
    console.log('📊 Final Summary');
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

manageApiKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

