/**
 * Test API Keys Validity Script
 * 
 * Tests each API key against NVIDIA API to see which ones work with gpt-oss-120b
 * Run with: npx tsx scripts/test-api-keys-validity.ts
 */

import OpenAI from 'openai';

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

const MODEL = 'openai/gpt-oss-120b';
const BASE_URL = 'https://integrate.api.nvidia.com/v1';
const TEST_TIMEOUT = 15000; // 15 seconds per key

interface TestResult {
  key: string;
  keyIndex: number;
  status: 'working' | 'invalid' | 'no-access' | 'rate-limited' | 'timeout' | 'error';
  error?: string;
  latency?: number;
  response?: string;
}

async function testApiKey(key: string, index: number): Promise<TestResult> {
  const keyPrefix = key.substring(0, 20) + '...';
  const startTime = Date.now();

  try {
    const client = new OpenAI({
      baseURL: BASE_URL,
      apiKey: key,
    });

    // Test with a minimal request
    const testPromise = client.chat.completions.create({
      model: MODEL,
      messages: [
        {
          role: 'user',
          content: 'Say "test"',
        },
      ],
      max_tokens: 5,
    });

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Timeout')), TEST_TIMEOUT)
    );

    const response = await Promise.race([testPromise, timeoutPromise]);
    const latency = Date.now() - startTime;

    // Check if we got a valid response
    if (response.choices && response.choices.length > 0) {
      const content = response.choices[0]?.message?.content || '';
      return {
        key,
        keyIndex: index + 1,
        status: 'working',
        latency,
        response: content.substring(0, 50),
      };
    } else {
      return {
        key,
        keyIndex: index + 1,
        status: 'error',
        error: 'No response content',
        latency,
      };
    }
  } catch (error: any) {
    const latency = Date.now() - startTime;
    const errorMessage = error?.message || String(error);
    const statusCode = error?.status || error?.response?.status || 
                      (errorMessage.match(/(\d{3})/)?.[1]);

    let status: TestResult['status'] = 'error';
    let errorMsg = errorMessage;

    if (errorMessage.includes('Timeout')) {
      status = 'timeout';
      errorMsg = 'Request timed out';
    } else if (statusCode === '401' || statusCode === 401) {
      status = 'invalid';
      errorMsg = 'Invalid API key (401 Unauthorized)';
    } else if (statusCode === '403' || statusCode === 403) {
      status = 'no-access';
      errorMsg = 'No access to model (403 Forbidden)';
    } else if (statusCode === '429' || statusCode === 429 || errorMessage.includes('rate limit')) {
      status = 'rate-limited';
      errorMsg = 'Rate limited (429 Too Many Requests)';
    } else if (statusCode === '404' || statusCode === 404) {
      status = 'no-access';
      errorMsg = 'Model not found (404)';
    }

    return {
      key,
      keyIndex: index + 1,
      status,
      error: errorMsg,
      latency,
    };
  }
}

async function testAllKeys() {
  console.log('\n🧪 Testing API Keys for GPT-OS-120B Model\n');
  console.log(`📋 Testing ${API_KEYS.length} keys against: ${MODEL}\n`);
  console.log('⏳ This may take a few minutes...\n');

  const results: TestResult[] = [];
  const workingKeys: string[] = [];
  const failedKeys: Array<{ key: string; reason: string }> = [];

  // Test keys sequentially to avoid overwhelming the API
  for (let i = 0; i < API_KEYS.length; i++) {
    const key = API_KEYS[i];
    const keyPrefix = key.substring(0, 20) + '...';
    
    process.stdout.write(`[${i + 1}/${API_KEYS.length}] Testing ${keyPrefix}... `);
    
    const result = await testApiKey(key, i);
    results.push(result);

    if (result.status === 'working') {
      console.log(`✅ WORKING (${result.latency}ms)`);
      workingKeys.push(key);
    } else {
      const statusEmoji = {
        'invalid': '❌',
        'no-access': '🚫',
        'rate-limited': '⏸️',
        'timeout': '⏱️',
        'error': '⚠️',
      }[result.status] || '❓';
      
      console.log(`${statusEmoji} ${result.status.toUpperCase()}: ${result.error}`);
      failedKeys.push({ key, reason: `${result.status}: ${result.error}` });
    }

    // Small delay between requests to avoid rate limiting
    if (i < API_KEYS.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 TEST SUMMARY\n');
  console.log(`✅ Working Keys: ${workingKeys.length}/${API_KEYS.length}`);
  console.log(`❌ Failed Keys: ${failedKeys.length}/${API_KEYS.length}\n`);

  if (workingKeys.length > 0) {
    console.log('✅ WORKING KEYS:');
    workingKeys.forEach((key, i) => {
      const result = results.find(r => r.key === key);
      console.log(`   ${i + 1}. ${key.substring(0, 30)}... (${result?.latency}ms)`);
    });
    console.log('');
  }

  if (failedKeys.length > 0) {
    console.log('❌ FAILED KEYS:');
    failedKeys.forEach((failed, i) => {
      console.log(`   ${i + 1}. ${failed.key.substring(0, 30)}... - ${failed.reason}`);
    });
    console.log('');
  }

  // Generate code to add only working keys
  if (workingKeys.length > 0) {
    console.log('📋 CODE TO ADD WORKING KEYS:\n');
    console.log('```javascript');
    console.log('fetch(\'/api/api-keys/bulk\', {');
    console.log('  method: \'POST\',');
    console.log('  headers: { \'Content-Type\': \'application/json\' },');
    console.log('  body: JSON.stringify({');
    console.log('    keys: [');
    workingKeys.forEach(key => {
      console.log(`      '${key}',`);
    });
    console.log('    ]');
    console.log('  })');
    console.log('})');
    console.log('.then(r => r.json())');
    console.log('.then(console.log);');
    console.log('```\n');
  }

  // Save results to file
  const fs = await import('fs/promises');
  const resultsJson = {
    testedAt: new Date().toISOString(),
    model: MODEL,
    total: API_KEYS.length,
    working: workingKeys.length,
    failed: failedKeys.length,
    workingKeys: workingKeys.map(key => ({
      key: key.substring(0, 30) + '...',
      fullKey: key,
    })),
    failedKeys: failedKeys,
    allResults: results.map(r => ({
      index: r.keyIndex,
      status: r.status,
      latency: r.latency,
      error: r.error,
      keyPrefix: r.key.substring(0, 30) + '...',
    })),
  };

  await fs.writeFile(
    'api-keys-test-results.json',
    JSON.stringify(resultsJson, null, 2)
  );

  console.log('💾 Results saved to: api-keys-test-results.json\n');

  return {
    working: workingKeys,
    failed: failedKeys,
    results,
  };
}

// Run the test
testAllKeys()
  .then(({ working, failed }) => {
    console.log('✨ Testing completed!\n');
    console.log(`✅ ${working.length} working keys found`);
    console.log(`❌ ${failed.length} failed keys\n`);
    
    if (working.length === 0) {
      console.log('⚠️  WARNING: No working keys found!');
      console.log('   - Check if keys are valid');
      console.log('   - Check if keys have access to gpt-oss-120b model');
      console.log('   - Check NVIDIA API status\n');
      process.exit(1);
    } else {
      process.exit(0);
    }
  })
  .catch((error) => {
    console.error('💥 Test suite failed:', error);
    process.exit(1);
  });








