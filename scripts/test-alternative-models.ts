/**
 * Test Alternative Models Script
 * 
 * Tests the 19 failed keys with alternative large models that are as smart as gpt-oss-120b
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

// Alternative large models comparable to gpt-oss-120b (120B parameters)
// Testing with models that are 70B+ parameters for similar intelligence
const ALTERNATIVE_MODELS = [
  'meta/llama-3.1-70b-instruct',      // 70B - Large, very capable
  'meta/llama-3.3-70b-instruct',     // 70B - Latest version
  'meta/llama-3.1-405b-instruct',    // 405B - Even larger than 120B!
  'meta/llama-3-70b-instruct',        // 70B - Previous version
  'mistralai/mixtral-8x22b-instruct', // 176B total (8x22B) - Very large
  'mistralai/mixtral-8x7b-instruct',  // 56B total (8x7B) - Large
];

const BASE_URL = 'https://integrate.api.nvidia.com/v1';
const TEST_TIMEOUT = 20000; // 20 seconds per test

interface ModelTestResult {
  model: string;
  key: string;
  keyIndex: number;
  status: 'working' | 'invalid' | 'no-access' | 'rate-limited' | 'timeout' | 'error';
  error?: string;
  latency?: number;
  response?: string;
}

async function testKeyWithModel(key: string, model: string, keyIndex: number): Promise<ModelTestResult> {
  const startTime = Date.now();

  try {
    const client = new OpenAI({
      baseURL: BASE_URL,
      apiKey: key,
      timeout: TEST_TIMEOUT,
    });

    const testPromise = client.chat.completions.create({
      model: model,
      messages: [
        {
          role: 'user',
          content: 'Analyze this conversation: "Customer: Hi, I need help with pricing. Sales: Sure, what product are you interested in? Customer: The premium package, how much does it cost?" Provide a brief analysis.',
        },
      ],
      max_tokens: 100,
      temperature: 0.3,
    });

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Timeout')), TEST_TIMEOUT)
    );

    const response = await Promise.race([testPromise, timeoutPromise]);
    const latency = Date.now() - startTime;

    if (response.choices && response.choices.length > 0) {
      const content = response.choices[0]?.message?.content || '';
      return {
        model,
        key,
        keyIndex,
        status: 'working',
        latency,
        response: content.substring(0, 100),
      };
    } else {
      return {
        model,
        key,
        keyIndex,
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

    let status: ModelTestResult['status'] = 'error';
    let errorMsg = errorMessage;

    if (errorMessage.includes('Timeout')) {
      status = 'timeout';
      errorMsg = 'Request timed out';
    } else if (statusCode === '401' || statusCode === 401) {
      status = 'invalid';
      errorMsg = 'Invalid API key (401)';
    } else if (statusCode === '403' || statusCode === 403) {
      status = 'no-access';
      errorMsg = 'No access to model (403)';
    } else if (statusCode === '429' || statusCode === 429 || errorMessage.includes('rate limit')) {
      status = 'rate-limited';
      errorMsg = 'Rate limited (429)';
    } else if (statusCode === '404' || statusCode === 404) {
      status = 'no-access';
      errorMsg = 'Model not found (404)';
    }

    return {
      model,
      key,
      keyIndex,
      status,
      error: errorMsg,
      latency,
    };
  }
}

async function testAlternativeModels() {
  console.log('\n🧪 Testing Failed Keys with Alternative Large Models\n');
  console.log(`📋 Testing ${FAILED_KEYS.length} keys with ${ALTERNATIVE_MODELS.length} alternative models\n`);
  console.log('🎯 Looking for models as smart as gpt-oss-120b (120B parameters)\n');
  console.log('⏳ This will take several minutes...\n');

  const results: ModelTestResult[] = [];
  const workingCombinations: Array<{ key: string; model: string; latency: number }> = [];

  // Test each key with each model
  for (let keyIndex = 0; keyIndex < FAILED_KEYS.length; keyIndex++) {
    const key = FAILED_KEYS[keyIndex];
    const keyPrefix = key.substring(0, 20) + '...';

    console.log(`\n🔑 Key ${keyIndex + 1}/${FAILED_KEYS.length}: ${keyPrefix}`);

    for (let modelIndex = 0; modelIndex < ALTERNATIVE_MODELS.length; modelIndex++) {
      const model = ALTERNATIVE_MODELS[modelIndex];
      process.stdout.write(`   [${modelIndex + 1}/${ALTERNATIVE_MODELS.length}] Testing ${model}... `);

      const result = await testKeyWithModel(key, model, keyIndex + 1);
      results.push(result);

      if (result.status === 'working') {
        console.log(`✅ WORKS! (${result.latency}ms)`);
        workingCombinations.push({
          key,
          model,
          latency: result.latency || 0,
        });
      } else {
        const statusEmoji = {
          'invalid': '❌',
          'no-access': '🚫',
          'rate-limited': '⏸️',
          'timeout': '⏱️',
          'error': '⚠️',
        }[result.status] || '❓';
        
        console.log(`${statusEmoji} ${result.status.toUpperCase()}`);
      }

      // Delay between model tests
      if (modelIndex < ALTERNATIVE_MODELS.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }

    // Longer delay between keys
    if (keyIndex < FAILED_KEYS.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  // Print summary
  console.log('\n' + '='.repeat(70));
  console.log('📊 ALTERNATIVE MODELS TEST SUMMARY\n');

  // Group by model
  const byModel = new Map<string, Array<{ key: string; latency: number }>>();
  workingCombinations.forEach(combo => {
    if (!byModel.has(combo.model)) {
      byModel.set(combo.model, []);
    }
    byModel.get(combo.model)!.push({ key: combo.key, latency: combo.latency });
  });

  if (byModel.size > 0) {
    console.log('✅ WORKING COMBINATIONS:\n');
    byModel.forEach((keys, model) => {
      console.log(`   📦 ${model} (${keys.length} keys work):`);
      keys.forEach((k, i) => {
        console.log(`      ${i + 1}. ${k.key.substring(0, 30)}... (${k.latency}ms)`);
      });
      console.log('');
    });

    // Find best model (most keys working)
    let bestModel = '';
    let maxKeys = 0;
    byModel.forEach((keys, model) => {
      if (keys.length > maxKeys) {
        maxKeys = keys.length;
        bestModel = model;
      }
    });

    if (bestModel) {
      const bestKeys = byModel.get(bestModel)!;
      console.log(`🏆 BEST MODEL: ${bestModel} (${bestKeys.length} keys working)\n`);
      
      console.log('📋 CODE TO ADD WORKING KEYS FOR BEST MODEL:\n');
      console.log('```javascript');
      console.log('fetch(\'/api/api-keys/bulk\', {');
      console.log('  method: \'POST\',');
      console.log('  headers: { \'Content-Type\': \'application/json\' },');
      console.log('  body: JSON.stringify({');
      console.log('    keys: [');
      bestKeys.forEach(k => {
        console.log(`      '${k.key}',`);
      });
      console.log('    ]');
      console.log('  })');
      console.log('})');
      console.log('.then(r => r.json())');
      console.log('.then(console.log);');
      console.log('```\n');
      
      console.log(`💡 Then update your model in code to: ${bestModel}\n`);
    }
  } else {
    console.log('❌ No working combinations found with alternative models\n');
    console.log('⚠️  These keys may need access granted in your NVIDIA developer account.\n');
  }

  // Save results
  const fs = await import('fs/promises');
  const resultsJson = {
    testedAt: new Date().toISOString(),
    originalModel: 'openai/gpt-oss-120b',
    alternativeModels: ALTERNATIVE_MODELS,
    totalKeys: FAILED_KEYS.length,
    workingCombinations: workingCombinations.length,
    byModel: Object.fromEntries(
      Array.from(byModel.entries()).map(([model, keys]) => [
        model,
        keys.map(k => ({
          key: k.key.substring(0, 30) + '...',
          fullKey: k.key,
          latency: k.latency,
        })),
      ])
    ),
    allResults: results.map(r => ({
      model: r.model,
      keyIndex: r.keyIndex,
      status: r.status,
      latency: r.latency,
      error: r.error,
      keyPrefix: r.key.substring(0, 30) + '...',
    })),
  };

  await fs.writeFile(
    'api-keys-alternative-models-results.json',
    JSON.stringify(resultsJson, null, 2)
  );

  console.log('💾 Results saved to: api-keys-alternative-models-results.json\n');

  return {
    working: workingCombinations,
    byModel,
  };
}

// Run the test
testAlternativeModels()
  .then(({ working, byModel }) => {
    console.log('✨ Testing completed!\n');
    console.log(`✅ ${working.length} working key-model combinations found`);
    console.log(`📦 ${byModel.size} models have working keys\n`);
    
    if (working.length > 0) {
      console.log('🎉 Great! Found alternative models that work!');
      console.log('   Update your code to use the best model found above.\n');
    }
    
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Test failed:', error);
    process.exit(1);
  });








