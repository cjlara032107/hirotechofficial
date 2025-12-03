/**
 * Test NVIDIA API Keys
 * Tests all active NVIDIA API keys to verify they're working
 */

import { PrismaClient, ApiKeyStatus } from '@prisma/client';
import { config } from 'dotenv';
import { resolve } from 'path';
import { decryptKey } from '../src/lib/crypto/encryption';
import OpenAI from 'openai';

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

interface TestResult {
  keyNumber: number;
  prefix: string;
  status: 'success' | 'error' | 'timeout';
  responseTime: number;
  error?: string;
  response?: string;
}

async function testKey(apiKey: string, keyNumber: number, prefix: string): Promise<TestResult> {
  const startTime = Date.now();
  
  try {
    const openai = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: apiKey,
    });

    // Simple test request - try multiple models to see which one works
    // Try the model used in fast-detailed-analysis first
    let completion;
    let modelUsed = 'meta/llama-3.1-8b-instruct';
    
    try {
      completion = await Promise.race([
        openai.chat.completions.create({
          model: 'meta/llama-3.1-8b-instruct',
          messages: [
            {
              role: 'user',
              content: 'Say "OK" if you can read this.',
            },
          ],
          max_tokens: 10,
          temperature: 0.1,
        }),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Timeout after 10 seconds')), 10000)
        )
      ]);
    } catch (firstError) {
      // If first model fails, try the model from google-ai-service
      try {
        modelUsed = 'openai/gpt-oss-20b';
        completion = await Promise.race([
          openai.chat.completions.create({
            model: 'openai/gpt-oss-20b',
            messages: [
              {
                role: 'user',
                content: 'Say "OK" if you can read this.',
              },
            ],
            max_tokens: 10,
            temperature: 0.1,
          }),
          new Promise<never>((_, reject) => 
            setTimeout(() => reject(new Error('Timeout after 10 seconds')), 10000)
          )
        ]);
      } catch {
        throw firstError; // Throw original error
      }
    }

    const responseTime = Date.now() - startTime;
    const response = completion.choices[0]?.message?.content || 'No response';

    return {
      keyNumber,
      prefix,
      status: 'success',
      responseTime,
      response: `${modelUsed}: ${response.substring(0, 50)}`, // Include model used
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Check for specific error types
    let status: 'error' | 'timeout' = 'error';
    if (errorMessage.includes('timeout') || errorMessage.includes('Timeout')) {
      status = 'timeout';
    }

    return {
      keyNumber,
      prefix,
      status,
      responseTime,
      error: errorMessage.substring(0, 100), // Truncate for display
    };
  }
}

async function testNvidiaKeys() {
  try {
    console.log('🧪 Testing NVIDIA API Keys...\n');
    console.log(`📋 Testing ${PROVIDED_KEYS.length} keys\n`);

    // Get all keys from database
    const dbKeys = await prisma.apiKey.findMany({
      where: {
        status: ApiKeyStatus.ACTIVE,
      },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
    });

    // Create a map of decrypted keys to database info
    const keyMap = new Map<string, { id: string; name: string | null }>();
    
    for (const dbKey of dbKeys) {
      try {
        const decrypted = decryptKey(dbKey.encryptedKey);
        keyMap.set(decrypted, {
          id: dbKey.id,
          name: dbKey.name,
        });
      } catch {
        // Skip invalid keys
      }
    }

    // Test each provided key
    const results: TestResult[] = [];
    const testPromises: Promise<TestResult>[] = [];

    console.log('⏳ Testing keys (this may take a minute)...\n');

    for (let i = 0; i < PROVIDED_KEYS.length; i++) {
      const key = PROVIDED_KEYS[i];
      const keyNumber = i + 1;
      const prefix = key.substring(0, 12);
      keyMap.get(key);

      // Test with a small delay to avoid rate limits
      const promise = new Promise<TestResult>((resolve) => {
        setTimeout(async () => {
          const result = await testKey(key, keyNumber, prefix);
          resolve(result);
        }, i * 200); // 200ms delay between each test
      });

      testPromises.push(promise);
    }

    // Wait for all tests to complete
    const testResults = await Promise.all(testPromises);
    results.push(...testResults);

    // Display results
    console.log('='.repeat(80));
    console.log('📊 TEST RESULTS:');
    console.log('='.repeat(80));

    const successful: TestResult[] = [];
    const failed: TestResult[] = [];
    const timedOut: TestResult[] = [];

    results.forEach((result) => {
      if (result.status === 'success') {
        successful.push(result);
      } else if (result.status === 'timeout') {
        timedOut.push(result);
      } else {
        failed.push(result);
      }
    });

    // Show successful tests
    if (successful.length > 0) {
      console.log('\n✅ SUCCESSFUL KEYS:');
      successful.forEach((result) => {
        const dbInfo = keyMap.get(PROVIDED_KEYS[result.keyNumber - 1]);
        const name = dbInfo?.name || 'unnamed';
        console.log(`   ${result.keyNumber}. ${result.prefix}... (${result.responseTime}ms) - ${name}`);
        if (result.response) {
          console.log(`      Response: "${result.response}"`);
        }
      });
    }

    // Show failed tests
    if (failed.length > 0) {
      console.log('\n❌ FAILED KEYS:');
      failed.forEach((result) => {
        const dbInfo = keyMap.get(PROVIDED_KEYS[result.keyNumber - 1]);
        const name = dbInfo?.name || 'unnamed';
        console.log(`   ${result.keyNumber}. ${result.prefix}... (${result.responseTime}ms) - ${name}`);
        if (result.error) {
          console.log(`      Error: ${result.error}`);
        }
      });
    }

    // Show timed out tests
    if (timedOut.length > 0) {
      console.log('\n⏱️  TIMED OUT KEYS:');
      timedOut.forEach((result) => {
        const dbInfo = keyMap.get(PROVIDED_KEYS[result.keyNumber - 1]);
        const name = dbInfo?.name || 'unnamed';
        console.log(`   ${result.keyNumber}. ${result.prefix}... (${result.responseTime}ms) - ${name}`);
      });
    }

    // Summary
    console.log('\n' + '='.repeat(80));
    console.log('📈 SUMMARY:');
    console.log('='.repeat(80));
    console.log(`   Total tested: ${results.length}`);
    console.log(`   ✅ Successful: ${successful.length}`);
    console.log(`   ❌ Failed: ${failed.length}`);
    console.log(`   ⏱️  Timed out: ${timedOut.length}`);
    
    const avgResponseTime = successful.length > 0
      ? Math.round(successful.reduce((sum, r) => sum + r.responseTime, 0) / successful.length)
      : 0;
    
    if (avgResponseTime > 0) {
      console.log(`   ⚡ Average response time: ${avgResponseTime}ms`);
    }
    
    console.log('='.repeat(80));

    // Update database with test results
    if (failed.length > 0 || timedOut.length > 0) {
      console.log('\n💡 Note: Failed/timed out keys may need to be checked manually.');
      console.log('   They may be rate-limited or invalid.');
    }

  } catch (error) {
    console.error('❌ Error testing keys:', error);
  } finally {
    await prisma.$disconnect();
  }
}

testNvidiaKeys();

