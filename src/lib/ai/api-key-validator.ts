/**
 * API Key Validator
 * 
 * Validates API keys by testing them against the actual API
 */

import OpenAI from 'openai';
import { decryptKey } from '@/lib/crypto/encryption';
import { prisma } from '@/lib/db';
import { ApiKeyStatus } from '@prisma/client';

interface ApiKeyValidationResult {
  keyId: string;
  keyName: string | null;
  isValid: boolean;
  error?: string;
  responseTime?: number;
  modelAccess?: string[];
}

/**
 * Test an API key by making a simple API call
 */
export async function validateApiKey(encryptedKey: string, keyId: string, keyName: string | null): Promise<ApiKeyValidationResult> {
  const startTime = Date.now();
  const result: ApiKeyValidationResult = {
    keyId,
    keyName,
    isValid: false,
  };

  try {
    // Decrypt the key
    const apiKey = decryptKey(encryptedKey);
    
    if (!apiKey || apiKey.length === 0) {
      result.error = 'Failed to decrypt API key';
      return result;
    }

    // Create OpenAI client
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: apiKey,
    });

    // Make a simple test request (list models or small completion)
    try {
      // Test with a minimal completion request
      const testResponse = await Promise.race([
        client.chat.completions.create({
          model: 'openai/gpt-oss-120b',
          messages: [{ role: 'user', content: 'test' }],
          max_tokens: 5,
        }),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Validation timeout')), 10000)
        )
      ]);

      const responseTime = Date.now() - startTime;
      
      if (testResponse && testResponse.choices && testResponse.choices.length > 0) {
        result.isValid = true;
        result.responseTime = responseTime;
        console.log(`[API Key Validator] ✅ Key ${keyId} is valid (${responseTime}ms)`);
      } else {
        result.error = 'API returned empty response';
      }
    } catch (apiError: any) {
      const errorMsg = apiError?.message || String(apiError);
      const statusCode = apiError?.status || apiError?.response?.status;
      
      result.error = `API error: ${errorMsg}${statusCode ? ` (${statusCode})` : ''}`;
      
      // Check for specific error types
      if (statusCode === 401 || statusCode === 403) {
        result.error = `Authentication failed (${statusCode}) - Invalid API key or no access to model`;
      } else if (statusCode === 429) {
        result.error = `Rate limited (429) - Key is valid but rate limited`;
        result.isValid = true; // Key is valid, just rate limited
      } else if (errorMsg.includes('timeout')) {
        result.error = 'Validation timeout - API did not respond in time';
      }
      
      console.warn(`[API Key Validator] ⚠️ Key ${keyId} validation failed: ${result.error}`);
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    result.error = `Validation error: ${errorMsg}`;
    console.error(`[API Key Validator] ❌ Key ${keyId} validation error: ${errorMsg}`);
  }

  return result;
}

/**
 * Validate all active API keys
 */
export async function validateAllApiKeys(): Promise<ApiKeyValidationResult[]> {
  console.log('[API Key Validator] 🔍 Starting validation of all active API keys...\n');

  try {
    // Get all active keys
    const activeKeys = await prisma.apiKey.findMany({
      where: {
        status: ApiKeyStatus.ACTIVE,
      },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
      },
    });

    if (activeKeys.length === 0) {
      console.log('[API Key Validator] ⚠️ No active keys found to validate\n');
      return [];
    }

    console.log(`[API Key Validator] Found ${activeKeys.length} active key(s) to validate\n`);

    // Validate each key
    const results: ApiKeyValidationResult[] = [];
    for (const key of activeKeys) {
      console.log(`[API Key Validator] Testing key: ${key.name || key.id}...`);
      const result = await validateApiKey(key.encryptedKey, key.id, key.name);
      results.push(result);
      
      // Small delay between validations to avoid rate limits
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Summary
    const validCount = results.filter(r => r.isValid).length;
    const invalidCount = results.filter(r => !r.isValid).length;
    
    console.log('\n' + '='.repeat(60));
    console.log('📋 API Key Validation Summary');
    console.log('='.repeat(60));
    console.log(`Total Keys Tested: ${results.length}`);
    console.log(`✅ Valid: ${validCount}`);
    console.log(`❌ Invalid: ${invalidCount}`);
    
    if (invalidCount > 0) {
      console.log('\nInvalid Keys:');
      results.filter(r => !r.isValid).forEach(r => {
        console.log(`  - ${r.keyName || r.keyId}: ${r.error}`);
      });
    }
    
    console.log('='.repeat(60) + '\n');

    return results;
  } catch (error) {
    console.error('[API Key Validator] ❌ Validation failed:', error);
    throw error;
  }
}

/**
 * Validate a single API key by ID
 */
export async function validateApiKeyById(keyId: string): Promise<ApiKeyValidationResult | null> {
  try {
    const key = await prisma.apiKey.findUnique({
      where: { id: keyId },
      select: {
        id: true,
        name: true,
        encryptedKey: true,
        status: true,
      },
    });

    if (!key) {
      console.error(`[API Key Validator] ❌ Key ${keyId} not found`);
      return null;
    }

    if (key.status !== ApiKeyStatus.ACTIVE) {
      console.warn(`[API Key Validator] ⚠️ Key ${keyId} is not active (status: ${key.status})`);
    }

    return await validateApiKey(key.encryptedKey, key.id, key.name);
  } catch (error) {
    console.error(`[API Key Validator] ❌ Error validating key ${keyId}:`, error);
    throw error;
  }
}








