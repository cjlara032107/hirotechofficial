/**
 * Script to test all active API keys in the database
 */

import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), '.env.local') });
dotenv.config({ path: path.join(process.cwd(), '.env') });

// Use encryption key from docs if not set
if (!process.env.ENCRYPTION_KEY) {
  process.env.ENCRYPTION_KEY = 'f902ad293f5f9af42c98b007dfdc0eede8614ac2be7a985c23347e051f3bcf81';
}

// Check DATABASE_URL
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL is required!');
  process.exit(1);
}

import OpenAI from 'openai';
import { PrismaClient } from '@prisma/client';
import { decryptKey } from '@/lib/crypto/encryption';

// Create Prisma client with explicit DATABASE_URL
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
    },
  },
});

async function testApiKey(key: string, keyId: string, keyName: string | null): Promise<{
  valid: boolean;
  responseTime?: number;
  error?: string;
}> {
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
        temperature: 0.1,
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
      return { valid: false, responseTime, error: 'Empty response' };
    }
  } catch (error: any) {
    const responseTime = Date.now() - startTime;
    const statusCode = error?.status || error?.response?.status;
    const errorMsg = error?.message || String(error);
    
    if (statusCode === 401 || statusCode === 403) {
      return { valid: false, responseTime, error: `Invalid key (${statusCode})` };
    }
    if (statusCode === 429) {
      return { valid: true, responseTime, error: 'Rate limited (key is valid)' };
    }
    
    return { valid: false, responseTime, error: errorMsg.substring(0, 100) };
  }
}

async function main() {
  try {
    console.log('='.repeat(70));
    console.log('🧪 Testing All Active API Keys');
    console.log('='.repeat(70));
    console.log('');

    await prisma.$connect();
    console.log('✅ Connected to database\n');

    // Get all active keys
    console.log('📋 Fetching all active API keys...');
    const activeKeys = await prisma.apiKey.findMany({
      where: { status: 'ACTIVE' },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    console.log(`   Found ${activeKeys.length} active key(s)\n`);

    if (activeKeys.length === 0) {
      console.log('⚠️  No active keys found to test.');
      await prisma.$disconnect();
      return;
    }

    // Test all keys in parallel
    console.log('🧪 Testing all API keys in parallel...\n');
    const overallStartTime = Date.now();
    
    const testPromises = activeKeys.map(async (key) => {
      const keyName = key.name || key.id.substring(0, 12);
      try {
        const decryptedKey = decryptKey(key.encryptedKey);
        const testResult = await testApiKey(decryptedKey, key.id, key.name);
        return {
          keyId: key.id,
          keyName: key.name,
          valid: testResult.valid,
          responseTime: testResult.responseTime,
          error: testResult.error,
        };
      } catch (error: any) {
        return {
          keyId: key.id,
          keyName: key.name,
          valid: false,
          error: `Decryption failed: ${error.message}`,
        };
      }
    });

    // Wait for all tests to complete in parallel
    const results = await Promise.all(testPromises);
    const overallTime = Date.now() - overallStartTime;
    
    // Display results
    results.forEach((result, i) => {
      const keyName = result.keyName || result.keyId.substring(0, 12);
      if (result.valid) {
        console.log(`   [${i + 1}/${activeKeys.length}] ${keyName}: ✅ Valid (${result.responseTime}ms)`);
      } else {
        console.log(`   [${i + 1}/${activeKeys.length}] ${keyName}: ❌ Invalid (${result.error || 'Test failed'})`);
      }
    });
    
    console.log(`\n   ⏱️  Total parallel test time: ${overallTime}ms`);

    // Summary
    console.log('');
    console.log('='.repeat(70));
    console.log('📊 Test Results Summary');
    console.log('='.repeat(70));
    
    const validKeys = results.filter(r => r.valid);
    const invalidKeys = results.filter(r => !r.valid);
    
    console.log(`Total Keys Tested: ${results.length}`);
    console.log(`✅ Valid: ${validKeys.length}`);
    console.log(`❌ Invalid: ${invalidKeys.length}`);
    console.log('');

    if (validKeys.length > 0) {
      console.log('✅ Valid Keys:');
      validKeys.forEach((r, i) => {
        console.log(`   ${i + 1}. ${r.keyName || r.keyId.substring(0, 12)}`);
        console.log(`      Response Time: ${r.responseTime}ms`);
        if (r.error) {
          console.log(`      Note: ${r.error}`);
        }
      });
      console.log('');
    }

    if (invalidKeys.length > 0) {
      console.log('❌ Invalid Keys:');
      invalidKeys.forEach((r, i) => {
        console.log(`   ${i + 1}. ${r.keyName || r.keyId.substring(0, 12)}`);
        console.log(`      Error: ${r.error || 'Test failed'}`);
      });
      console.log('');
    }

    console.log('='.repeat(70));

    await prisma.$disconnect();
    console.log('\n✅ Testing complete!');
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : String(error));
    if (error instanceof Error && error.stack) {
      console.error('\nStack trace:');
      console.error(error.stack);
    }
    await prisma.$disconnect();
    process.exit(1);
  }
}

main();

