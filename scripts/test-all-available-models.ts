/**
 * Test All Available Models Script
 * 
 * Tests a sample key with various models to discover what's available
 */

import OpenAI from 'openai';

// Use one of the working keys to discover available models
const TEST_KEY = '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';

// Comprehensive list of possible NVIDIA API models
const MODELS_TO_TEST = [
  // GPT-OSS models
  'openai/gpt-oss-120b',
  'openai/gpt-oss-20b',
  
  // Llama models (large)
  'meta/llama-3.1-405b-instruct',
  'meta/llama-3.1-70b-instruct',
  'meta/llama-3.3-70b-instruct',
  'meta/llama-3-70b-instruct',
  'meta/llama-3.1-8b-instruct',
  'meta/llama-3-8b-instruct',
  
  // Mixtral models (large)
  'mistralai/mixtral-8x22b-instruct',
  'mistralai/mixtral-8x7b-instruct',
  'mistralai/mixtral-8x7b',
  
  // Other large models
  'google/gemma-2-27b-it',
  'google/gemma-2-9b-it',
  'microsoft/phi-3-medium-4k-instruct',
  'microsoft/phi-3-mini-4k-instruct',
  
  // Try variations
  'meta/llama-3.1-405b',
  'meta/llama-3.1-70b',
  'mistralai/mixtral-8x22b',
];

const BASE_URL = 'https://integrate.api.nvidia.com/v1';
const TEST_TIMEOUT = 15000;

async function testModel(model: string): Promise<{ available: boolean; error?: string; latency?: number }> {
  try {
    const startTime = Date.now();
    const client = new OpenAI({
      baseURL: BASE_URL,
      apiKey: TEST_KEY,
      timeout: TEST_TIMEOUT,
    });

    const response = await Promise.race([
      client.chat.completions.create({
        model: model,
        messages: [{ role: 'user', content: 'test' }],
        max_tokens: 5,
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Timeout')), TEST_TIMEOUT)
      ),
    ]);

    const latency = Date.now() - startTime;
    return { available: true, latency };
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    const statusCode = error?.status || error?.response?.status;
    
    if (statusCode === 404) {
      return { available: false, error: 'Model not found (404)' };
    } else if (statusCode === 403) {
      return { available: false, error: 'No access (403)' };
    } else {
      return { available: false, error: errorMsg.substring(0, 50) };
    }
  }
}

async function discoverAvailableModels() {
  console.log('\n🔍 Discovering Available Models on NVIDIA API\n');
  console.log(`Using test key: ${TEST_KEY.substring(0, 20)}...\n`);
  console.log(`Testing ${MODELS_TO_TEST.length} models...\n`);

  const available: string[] = [];
  const unavailable: Array<{ model: string; reason: string }> = [];

  for (let i = 0; i < MODELS_TO_TEST.length; i++) {
    const model = MODELS_TO_TEST[i];
    process.stdout.write(`[${i + 1}/${MODELS_TO_TEST.length}] ${model}... `);

    const result = await testModel(model);

    if (result.available) {
      console.log(`✅ Available (${result.latency}ms)`);
      available.push(model);
    } else {
      console.log(`❌ ${result.error || 'Unavailable'}`);
      unavailable.push({ model, reason: result.error || 'Unknown' });
    }

    await new Promise(resolve => setTimeout(resolve, 300));
  }

  console.log('\n' + '='.repeat(70));
  console.log('📊 AVAILABLE MODELS DISCOVERY\n');
  console.log(`✅ Available: ${available.length}/${MODELS_TO_TEST.length}`);
  console.log(`❌ Unavailable: ${unavailable.length}/${MODELS_TO_TEST.length}\n`);

  if (available.length > 0) {
    console.log('✅ AVAILABLE MODELS:');
    available.forEach((model, i) => {
      console.log(`   ${i + 1}. ${model}`);
    });
    console.log('');
  }

  // Save results
  const fs = await import('fs/promises');
  await fs.writeFile(
    'available-models-discovery.json',
    JSON.stringify({
      discoveredAt: new Date().toISOString(),
      available,
      unavailable,
    }, null, 2)
  );

  console.log('💾 Results saved to: available-models-discovery.json\n');
  console.log('💡 Use these available models to test the 19 failed keys!\n');

  return { available, unavailable };
}

discoverAvailableModels()
  .then(({ available }) => {
    if (available.length > 0) {
      console.log('🎯 Next step: Test the 19 failed keys with these available models');
    }
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Discovery failed:', error);
    process.exit(1);
  });








