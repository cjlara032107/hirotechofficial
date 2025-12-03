/**
 * API Key Health Check
 * 
 * Pre-checks API keys before analysis to ensure they're available and working
 */

import apiKeyManager from './api-key-manager';
import { prisma } from '@/lib/db';
import { ApiKeyStatus } from '@prisma/client';

interface ApiKeyHealthStatus {
  healthy: boolean;
  activeKeyCount: number;
  rateLimitedKeyCount: number;
  totalKeyCount: number;
  hasWorkingKeys: boolean;
  error?: string;
  recommendations: string[];
}

/**
 * Check API key health before starting analysis
 */
export async function checkApiKeyHealth(): Promise<ApiKeyHealthStatus> {
  const status: ApiKeyHealthStatus = {
    healthy: false,
    activeKeyCount: 0,
    rateLimitedKeyCount: 0,
    totalKeyCount: 0,
    hasWorkingKeys: false,
    recommendations: [],
  };

  try {
    // Count keys in database
    const allKeys = await prisma.apiKey.findMany({
      select: {
        id: true,
        status: true,
        rateLimitedAt: true,
      },
    });

    status.totalKeyCount = allKeys.length;
    status.activeKeyCount = allKeys.filter(k => k.status === ApiKeyStatus.ACTIVE && !k.rateLimitedAt).length;
    status.rateLimitedKeyCount = allKeys.filter(k => k.status === ApiKeyStatus.RATE_LIMITED || k.rateLimitedAt).length;

    // Check if we can retrieve a key
    try {
      const testKey = await apiKeyManager.getNextKey({ operation: 'health-check' });
      status.hasWorkingKeys = testKey !== null;
      
      if (testKey) {
        console.log(`[API Key Health] ✅ Health check passed: ${status.activeKeyCount} active keys, retrieved key works`);
        
        // Additional validation: check key format
        if (!testKey.startsWith('nvapi-')) {
          console.warn(`[API Key Health] ⚠️ Retrieved key does not start with 'nvapi-' - may be invalid format`);
          status.recommendations.push('API key format may be invalid. Ensure keys start with "nvapi-".');
        }
        
        // Check key length (NVIDIA keys are typically 50+ characters)
        if (testKey.length < 30) {
          console.warn(`[API Key Health] ⚠️ Retrieved key is unusually short (${testKey.length} chars) - may be invalid`);
          status.recommendations.push('API key length is unusually short. Verify key is complete.');
        }
      } else {
        console.warn(`[API Key Health] ⚠️ Health check: ${status.activeKeyCount} active keys but retrieval returned null`);
        status.recommendations.push('API keys exist but retrieval failed. Check API key manager.');
      }
    } catch (retrievalError) {
      const errorMsg = retrievalError instanceof Error ? retrievalError.message : String(retrievalError);
      console.error(`[API Key Health] ❌ Key retrieval failed: ${errorMsg}`);
      status.error = `Key retrieval failed: ${errorMsg}`;
      status.recommendations.push('API key retrieval is failing. Check database connection and encryption key.');
    }
    
    // Check encryption key availability
    if (!process.env.ENCRYPTION_KEY) {
      status.healthy = false;
      status.error = 'ENCRYPTION_KEY environment variable is not set';
      status.recommendations.push('ENCRYPTION_KEY environment variable is required for API key encryption/decryption.');
    }

    // Determine health status
    if (status.activeKeyCount === 0) {
      status.healthy = false;
      status.recommendations.push('No active API keys found. Add API keys in Settings → API Keys.');
      
      // Check environment variables as fallback
      const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY;
      if (envKey) {
        status.recommendations.push('Environment variable API key found. Consider adding it to database for better management.');
        status.hasWorkingKeys = true;
      } else {
        status.recommendations.push('No API keys in database or environment variables. Add at least one API key.');
      }
    } else if (status.activeKeyCount < 3) {
      status.healthy = true;
      status.recommendations.push(`Only ${status.activeKeyCount} active key(s). Consider adding more keys for better rate limit handling.`);
    } else {
      status.healthy = true;
    }

    // Check rate limiting
    if (status.rateLimitedKeyCount > 0) {
      status.recommendations.push(`${status.rateLimitedKeyCount} key(s) are rate-limited. Wait for rate limit to reset or add more keys.`);
    }

    return status;
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    console.error(`[API Key Health] ❌ Health check failed: ${errorMsg}`);
    status.error = errorMsg;
    status.recommendations.push('Health check failed. Check database connection.');
    return status;
  }
}

/**
 * Log API key health status
 */
export function logApiKeyHealth(status: ApiKeyHealthStatus): void {
  console.log('\n' + '='.repeat(60));
  console.log('🔍 API Key Health Check');
  console.log('='.repeat(60));
  console.log(`Status: ${status.healthy ? '✅ Healthy' : '❌ Unhealthy'}`);
  console.log(`Active Keys: ${status.activeKeyCount}`);
  console.log(`Rate Limited: ${status.rateLimitedKeyCount}`);
  console.log(`Total Keys: ${status.totalKeyCount}`);
  console.log(`Has Working Keys: ${status.hasWorkingKeys ? '✅ Yes' : '❌ No'}`);
  if (status.error) {
    console.log(`Error: ${status.error}`);
  }
  if (status.recommendations.length > 0) {
    console.log('\nRecommendations:');
    status.recommendations.forEach((rec, i) => {
      console.log(`  ${i + 1}. ${rec}`);
    });
  }
  console.log('='.repeat(60) + '\n');
}

