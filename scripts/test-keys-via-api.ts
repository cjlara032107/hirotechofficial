/**
 * Test all API keys by fetching them via the API and testing each one
 * This avoids Prisma initialization issues
 */

import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), '.env.local') });

import OpenAI from 'openai';

const API_BASE = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

async function testApiKey(key: string, keyId: string, keyName: string | null): Promise<{ 
  valid: boolean; 
  canListModels: boolean;
  canMakeCalls: boolean;
  hasPrimaryModel: boolean;
  error?: string;
  availableModels?: number;
}> {
  const result = {
    valid: false,
    canListModels: false,
    canMakeCalls: false,
    hasPrimaryModel: false,
    availableModels: 0,
  };

  try {
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: key,
    });

    // Test 1: Can list models?
    try {
      const models = await client.models.list();
      result.canListModels = true;
      result.availableModels = models.data.length;
      result.valid = true;
    } catch (error: any) {
      result.error = `Cannot list models: ${error?.message || String(error)}`;
      return result;
    }

    // Test 2: Can make API calls with primary model?
    const primaryModel = 'openai/gpt-oss-120b';
    try {
      const response = await Promise.race([
        client.chat.completions.create({
          model: primaryModel,
          messages: [{ role: 'user', content: 'Say "test" only.' }],
          max_tokens: 10,
        }),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), 15000)
        ),
      ]);

      if (response.choices?.[0]?.message?.content) {
        result.canMakeCalls = true;
        result.hasPrimaryModel = true;
        return result;
      }
    } catch (error: any) {
      const statusCode = error?.status || error?.response?.status;
      if (statusCode === 403) {
        result.error = `No access to ${primaryModel}`;
      } else if (statusCode === 429) {
        result.canMakeCalls = true;
        result.error = `Rate limited (key is valid)`;
        return result;
      } else {
        result.error = `API call failed: ${error?.message || String(error)}`;
      }
    }

    // Test 3: Try alternative models
    if (!result.canMakeCalls) {
      try {
        const models = await client.models.list();
        const testModels = models.data
          .filter(m => m.id.includes('llama') || m.id.includes('gpt') || m.id.includes('mistral'))
          .slice(0, 3)
          .map(m => m.id);

        for (const model of testModels) {
          try {
            const response = await Promise.race([
              client.chat.completions.create({
                model: model,
                messages: [{ role: 'user', content: 'test' }],
                max_tokens: 5,
              }),
              new Promise<never>((_, reject) => 
                setTimeout(() => reject(new Error('Timeout')), 10000)
              ),
            ]);

            if (response.choices?.[0]?.message?.content) {
              result.canMakeCalls = true;
              result.error = `Can make calls but not to ${primaryModel}`;
              break;
            }
          } catch {
            // Continue
          }
        }
      } catch {
        // Ignore
      }
    }

    return result;
  } catch (error: any) {
    result.error = error?.message || String(error);
    return result;
  }
}

async function testAllKeys() {
  console.log('\n🔍 Testing all active API keys...\n');
  console.log(`📡 Fetching keys from API: ${API_BASE}/api/api-keys\n`);

  try {
    // Fetch keys from API
    const response = await fetch(`${API_BASE}/api/api-keys`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}: ${await response.text()}`);
    }

    const keys = await response.json();

    if (!Array.isArray(keys) || keys.length === 0) {
      console.log('⚠️  No active keys found.\n');
      return;
    }

    console.log(`Found ${keys.length} active key(s) to test:\n`);
    console.log('='.repeat(80));

    const results: Array<{
      id: string;
      name: string | null;
      valid: boolean;
      canListModels: boolean;
      canMakeCalls: boolean;
      hasPrimaryModel: boolean;
      availableModels: number;
      error?: string;
      recommendation: string;
    }> = [];

    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const keyPrefix = key.id?.substring(0, 8) || 'unknown';
      const keyName = key.name || 'Unnamed';
      
      console.log(`\n[${i + 1}/${keys.length}] Testing: ${keyName} (${keyPrefix}...)`);
      console.log('-'.repeat(80));

      // We need the actual decrypted key to test it
      // Since the API doesn't return the key, we'll need to use the validation endpoint
      console.log('  ⚠️  Cannot test key directly (API does not return decrypted keys)');
      console.log('  💡 Use the validation endpoint or test keys manually');
      
      // Try using the validation endpoint if it exists
      try {
        const validateResponse = await fetch(`${API_BASE}/api/api-keys/validate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ keyId: key.id }),
        });

        if (validateResponse.ok) {
          const validation = await validateResponse.json();
          console.log(`  Validation result: ${validation.isValid ? '✅ Valid' : '❌ Invalid'}`);
          if (validation.error) {
            console.log(`  Error: ${validation.error}`);
          }
        }
      } catch {
        // Validation endpoint might not exist
      }
    }

    console.log('\n' + '='.repeat(80));
    console.log('\n💡 To test keys properly, you need to:');
    console.log('   1. Use the Settings → API Keys page in the UI');
    console.log('   2. Or use the validation endpoint: POST /api/api-keys/validate');
    console.log('   3. Or provide the actual key values to test directly\n');

  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    console.error('\n💡 Make sure your dev server is running (npm run dev)');
    process.exit(1);
  }
}

testAllKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});




