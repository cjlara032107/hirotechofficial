/**
 * Retest Failed API Keys Script
 * 
 * Retests the 19 keys that failed previously
 */

import OpenAI from 'openai';

const FAILED_KEYS = [
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
const TEST_TIMEOUT = 20000; // 20 seconds per key (increased timeout)

interface TestResult {
  key: string;
  keyIndex: number;
  status: 'working' | 'invalid' | 'no-access' | 'rate-limited' | 'timeout' | 'error';
  error?: string;
  latency?: number;
  response?: string;
  retryAttempt: number;
}

async function testApiKey(key: string, index: number, retryAttempt: number = 1): Promise<TestResult> {
  const keyPrefix = key.substring(0, 20) + '...';
  const startTime = Date.now();

  try {
    const client = new OpenAI({
      baseURL: BASE_URL,
      apiKey: key,
      timeout: TEST_TIMEOUT,
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
      temperature: 0.1,
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
        retryAttempt,
      };
    } else {
      return {
        key,
        keyIndex: index + 1,
        status: 'error',
        error: 'No response content',
        latency,
        retryAttempt,
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
      retryAttempt,
    };
  }
}

async function retestFailedKeys() {
  console.log('\n🔄 Retesting Failed API Keys for GPT-OS-120B\n');
  console.log(`📋 Retesting ${FAILED_KEYS.length} keys against: ${MODEL}\n`);
  console.log('⏳ This may take a few minutes...\n');

  const results: TestResult[] = [];
  const workingKeys: string[] = [];
  const stillFailedKeys: Array<{ key: string; reason: string; status: string }> = [];

  // Test keys sequentially with longer delays to avoid rate limiting
  for (let i = 0; i < FAILED_KEYS.length; i++) {
    const key = FAILED_KEYS[i];
    const keyPrefix = key.substring(0, 20) + '...';
    
    process.stdout.write(`[${i + 1}/${FAILED_KEYS.length}] Retesting ${keyPrefix}... `);
    
    // Try up to 2 times per key
    let result: TestResult | null = null;
    for (let attempt = 1; attempt <= 2; attempt++) {
      result = await testApiKey(key, i, attempt);
      
      if (result.status === 'working') {
        break; // Success, no need to retry
      }
      
      // If rate limited, wait longer before retry
      if (result.status === 'rate-limited' && attempt < 2) {
        console.log(`⏸️  Rate limited, waiting 5s before retry...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
      } else if (attempt < 2 && result.status !== 'working') {
        // Wait 2 seconds before retry for other errors
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    if (result) {
      results.push(result);

      if (result.status === 'working') {
        console.log(`✅ NOW WORKING! (${result.latency}ms, attempt ${result.retryAttempt})`);
        workingKeys.push(key);
      } else {
        const statusEmoji = {
          'invalid': '❌',
          'no-access': '🚫',
          'rate-limited': '⏸️',
          'timeout': '⏱️',
          'error': '⚠️',
        }[result.status] || '❓';
        
        console.log(`${statusEmoji} Still ${result.status.toUpperCase()}: ${result.error}`);
        stillFailedKeys.push({ 
          key, 
          reason: result.error || 'Unknown error',
          status: result.status,
        });
      }
    }

    // Longer delay between keys to avoid rate limiting
    if (i < FAILED_KEYS.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('📊 RETEST SUMMARY\n');
  console.log(`✅ Now Working: ${workingKeys.length}/${FAILED_KEYS.length}`);
  console.log(`❌ Still Failed: ${stillFailedKeys.length}/${FAILED_KEYS.length}\n`);

  if (workingKeys.length > 0) {
    console.log('✅ KEYS THAT NOW WORK:');
    workingKeys.forEach((key, i) => {
      const result = results.find(r => r.key === key);
      console.log(`   ${i + 1}. ${key.substring(0, 30)}... (${result?.latency}ms)`);
    });
    console.log('');
  }

  if (stillFailedKeys.length > 0) {
    console.log('❌ KEYS STILL FAILING:');
    stillFailedKeys.forEach((failed, i) => {
      console.log(`   ${i + 1}. ${failed.key.substring(0, 30)}... - ${failed.status}: ${failed.reason}`);
    });
    console.log('');
  }

  // Generate code to add newly working keys
  if (workingKeys.length > 0) {
    console.log('📋 CODE TO ADD NEWLY WORKING KEYS:\n');
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

  // Save results
  const fs = await import('fs/promises');
  const resultsJson = {
    retestedAt: new Date().toISOString(),
    model: MODEL,
    totalRetested: FAILED_KEYS.length,
    nowWorking: workingKeys.length,
    stillFailed: stillFailedKeys.length,
    newlyWorkingKeys: workingKeys.map(key => ({
      key: key.substring(0, 30) + '...',
      fullKey: key,
    })),
    stillFailedKeys: stillFailedKeys,
    allResults: results.map(r => ({
      index: r.keyIndex,
      status: r.status,
      latency: r.latency,
      error: r.error,
      retryAttempt: r.retryAttempt,
      keyPrefix: r.key.substring(0, 30) + '...',
    })),
  };

  await fs.writeFile(
    'api-keys-retest-results.json',
    JSON.stringify(resultsJson, null, 2)
  );

  console.log('💾 Results saved to: api-keys-retest-results.json\n');

  return {
    working: workingKeys,
    failed: stillFailedKeys,
    results,
  };
}

// Run the retest
retestFailedKeys()
  .then(({ working, failed }) => {
    console.log('✨ Retest completed!\n');
    console.log(`✅ ${working.length} keys now working`);
    console.log(`❌ ${failed.length} keys still failing\n`);
    
    if (working.length > 0) {
      console.log('🎉 Great! Some keys are now working!');
      console.log('   Add them using the code above.\n');
    } else {
      console.log('⚠️  No keys are working yet.');
      console.log('   These keys may need access granted in your NVIDIA developer account.\n');
    }
    
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Retest failed:', error);
    process.exit(1);
  });








