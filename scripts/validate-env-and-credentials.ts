#!/usr/bin/env tsx
/**
 * Comprehensive Environment Variables and API Credentials Validation Script
 * 
 * This script:
 * 1. Verifies all required environment variables are set
 * 2. Validates Facebook API credentials by making a test API call
 * 3. Validates NVIDIA/Gemini API keys by making a test API call
 */

import { resolve } from 'path';
import axios from 'axios';
import OpenAI from 'openai';

// Try to load dotenv if available (optional)
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { config } = require('dotenv');
  config({ path: resolve(process.cwd(), '.env.local') });
  config({ path: resolve(process.cwd(), '.env') });
} catch {
  // dotenv not available, environment variables should be loaded by the system
  // This is fine for scripts run via npm/tsx which may already have env vars loaded
}

interface ValidationResult {
  name: string;
  status: 'pass' | 'fail' | 'warning';
  message: string;
  details?: string;
}

const results: ValidationResult[] = [];

function addResult(
  name: string,
  status: 'pass' | 'fail' | 'warning',
  message: string,
  details?: string
) {
  results.push({ name, status, message, details });
}

/**
 * Check all required environment variables
 */
function checkEnvironmentVariables() {
  console.log('\n🔍 Checking Environment Variables...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  // Required variables
  const required = [
    'DATABASE_URL',
    'NEXTAUTH_SECRET',
    'NEXT_PUBLIC_SUPABASE_URL',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'FACEBOOK_APP_ID',
    'FACEBOOK_APP_SECRET',
  ];

  // Optional but recommended
  const optional = [
    'REDIS_URL',
    'NEXT_PUBLIC_APP_URL',
    'FACEBOOK_WEBHOOK_VERIFY_TOKEN',
    'NVIDIA_API_KEY',
    'GOOGLE_AI_API_KEY',
    'ENCRYPTION_KEY',
  ];

  const missing: string[] = [];
  const found: string[] = [];
  const optionalMissing: string[] = [];

  // Check required variables
  required.forEach((varName) => {
    if (process.env[varName]) {
      found.push(varName);
      // Mask sensitive values in output
      const value = process.env[varName] || '';
      const masked = varName.includes('SECRET') || varName.includes('KEY') || varName.includes('PASSWORD')
        ? `${value.substring(0, 8)}...${value.substring(value.length - 4)}`
        : value;
      console.log(`   ✅ ${varName}: ${masked}`);
    } else {
      missing.push(varName);
      console.log(`   ❌ ${varName}: NOT SET`);
    }
  });

  // Check optional variables
  console.log('\n   Optional Variables:');
  optional.forEach((varName) => {
    if (process.env[varName]) {
      const value = process.env[varName] || '';
      const masked = varName.includes('SECRET') || varName.includes('KEY') || varName.includes('PASSWORD')
        ? `${value.substring(0, 8)}...${value.substring(value.length - 4)}`
        : value;
      console.log(`   ✅ ${varName}: ${masked}`);
    } else {
      optionalMissing.push(varName);
      console.log(`   ⚠️  ${varName}: NOT SET (optional)`);
    }
  });

  if (missing.length > 0) {
    addResult(
      'Environment Variables',
      'fail',
      `Missing ${missing.length} required variable(s)`,
      `Missing: ${missing.join(', ')}`
    );
  } else {
    addResult(
      'Environment Variables',
      'pass',
      `All ${required.length} required variables present`,
      undefined
    );
  }

  if (optionalMissing.length > 0) {
    addResult(
      'Optional Environment Variables',
      'warning',
      `${optionalMissing.length} optional variable(s) not set`,
      `Missing: ${optionalMissing.join(', ')}`
    );
  }
}

/**
 * Validate Facebook API credentials by making a test API call
 */
async function validateFacebookCredentials() {
  console.log('\n🔍 Validating Facebook API Credentials...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const appId = process.env.FACEBOOK_APP_ID;
  const appSecret = process.env.FACEBOOK_APP_SECRET;

  if (!appId || !appSecret) {
    addResult(
      'Facebook API Credentials',
      'fail',
      'Facebook credentials not configured',
      'FACEBOOK_APP_ID or FACEBOOK_APP_SECRET not set'
    );
    console.log('   ❌ Cannot validate - credentials not set');
    return;
  }

  try {
    // Test 1: Validate App ID and Secret by getting app access token
    console.log('   Testing App ID and Secret...');
    const tokenResponse = await axios.get('https://graph.facebook.com/oauth/access_token', {
      params: {
        client_id: appId,
        client_secret: appSecret,
        grant_type: 'client_credentials',
      },
      timeout: 10000,
    });

    if (tokenResponse.data?.access_token) {
      const accessToken = tokenResponse.data.access_token;
      console.log('   ✅ App access token obtained successfully');

      // Test 2: Use the token to get app info
      console.log('   Testing access token validity...');
      const appInfoResponse = await axios.get(`https://graph.facebook.com/v19.0/${appId}`, {
        params: {
          access_token: accessToken,
          fields: 'id,name',
        },
        timeout: 10000,
      });

      if (appInfoResponse.data?.id) {
        console.log(`   ✅ App verified: ${appInfoResponse.data.name || appInfoResponse.data.id}`);
        addResult(
          'Facebook API Credentials',
          'pass',
          'Facebook credentials are valid',
          `App: ${appInfoResponse.data.name || appInfoResponse.data.id}`
        );
      } else {
        throw new Error('Invalid app info response');
      }
    } else {
      throw new Error('No access token in response');
    }
  } catch (error: any) {
    const errorMessage = error.response?.data?.error?.message || error.message || 'Unknown error';
    const errorCode = error.response?.data?.error?.code || 'N/A';
    
    console.log(`   ❌ Validation failed: ${errorMessage} (Code: ${errorCode})`);
    
    if (errorCode === 101 || errorCode === 190) {
      addResult(
        'Facebook API Credentials',
        'fail',
        'Invalid Facebook credentials',
        `Error ${errorCode}: ${errorMessage}. Check FACEBOOK_APP_ID and FACEBOOK_APP_SECRET.`
      );
    } else if (error.response?.status === 401 || error.response?.status === 403) {
      addResult(
        'Facebook API Credentials',
        'fail',
        'Facebook API authentication failed',
        `HTTP ${error.response.status}: ${errorMessage}`
      );
    } else {
      addResult(
        'Facebook API Credentials',
        'warning',
        'Could not validate Facebook credentials',
        `Error: ${errorMessage}. This may be a network issue.`
      );
    }
  }
}

/**
 * Validate NVIDIA/Gemini API keys by making a test API call
 */
async function validateAIServiceKeys() {
  console.log('\n🔍 Validating AI Service API Keys (NVIDIA/Gemini)...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  const nvidiaKey = process.env.NVIDIA_API_KEY;
  const googleKey = process.env.GOOGLE_AI_API_KEY;

  if (!nvidiaKey && !googleKey) {
    addResult(
      'AI Service API Keys',
      'warning',
      'No AI service API keys found in environment',
      'Neither NVIDIA_API_KEY nor GOOGLE_AI_API_KEY is set. Keys may be stored in database.'
    );
    console.log('   ⚠️  No API keys in environment variables');
    console.log('   ℹ️  Note: API keys may be stored in database (encrypted)');
    return;
  }

  // Test NVIDIA API key if present
  if (nvidiaKey) {
    await testNvidiaKey(nvidiaKey);
  }

  // Test Google/Gemini API key if present
  if (googleKey) {
    await testGoogleKey(googleKey);
  }
}

/**
 * Test NVIDIA API key
 */
async function testNvidiaKey(apiKey: string) {
  console.log('   Testing NVIDIA API Key...');
  
  // Check key format
  if (!apiKey.startsWith('nvapi-')) {
    console.log('   ⚠️  Key does not start with "nvapi-" (may still be valid)');
  } else {
    console.log('   ✅ Key format looks correct (starts with "nvapi-")');
  }

  try {
    const openai = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: apiKey,
    });

    // Make a simple test request
    console.log('   Making test API call...');
    const completion = await Promise.race([
      openai.chat.completions.create({
        model: 'meta/llama-3.1-8b-instruct', // Lightweight model for testing
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
        setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000)
      ),
    ]);

    if (completion.choices?.[0]?.message?.content) {
      console.log('   ✅ NVIDIA API key is valid and working');
      addResult(
        'NVIDIA API Key',
        'pass',
        'NVIDIA API key is valid',
        'Successfully made test API call'
      );
    } else {
      throw new Error('No response content');
    }
  } catch (error: any) {
    const errorMessage = error.message || 'Unknown error';
    const statusCode = error.status || error.response?.status;
    
    console.log(`   ❌ Validation failed: ${errorMessage}`);
    
    if (statusCode === 401 || statusCode === 403) {
      addResult(
        'NVIDIA API Key',
        'fail',
        'NVIDIA API key is invalid or expired',
        `HTTP ${statusCode}: ${errorMessage}. Get a new key from https://build.nvidia.com/`
      );
    } else if (errorMessage.includes('timeout') || errorMessage.includes('Timeout')) {
      addResult(
        'NVIDIA API Key',
        'warning',
        'NVIDIA API test timed out',
        'This may be a network issue. Key format looks correct.'
      );
    } else {
      addResult(
        'NVIDIA API Key',
        'warning',
        'Could not validate NVIDIA API key',
        `Error: ${errorMessage}`
      );
    }
  }
}

/**
 * Test Google/Gemini API key
 */
async function testGoogleKey(apiKey: string) {
  console.log('   Testing Google AI API Key...');
  
  try {
    // Try using it as NVIDIA key first (since GOOGLE_AI_API_KEY is used as fallback)
    // If it starts with nvapi-, it's actually an NVIDIA key
    if (apiKey.startsWith('nvapi-')) {
      console.log('   ℹ️  Key appears to be NVIDIA format, testing as NVIDIA key...');
      await testNvidiaKey(apiKey);
      return;
    }

    // For actual Google/Gemini keys, we would test against Google's API
    // For now, just check if it's set
    console.log('   ⚠️  Google/Gemini API validation not implemented');
    console.log('   ℹ️  Key is set but validation requires Google API endpoint');
    addResult(
      'Google AI API Key',
      'warning',
      'Google AI API key is set',
      'Validation not implemented. Key will be used as fallback for NVIDIA API.'
    );
  } catch (error: any) {
    const errorMessage = error.message || 'Unknown error';
    console.log(`   ❌ Validation failed: ${errorMessage}`);
    addResult(
      'Google AI API Key',
      'warning',
      'Could not validate Google AI API key',
      `Error: ${errorMessage}`
    );
  }
}

/**
 * Print validation results summary
 */
function printResults() {
  console.log('\n\n╔══════════════════════════════════════════════════════╗');
  console.log('║         VALIDATION RESULTS                        ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  let passCount = 0;
  let failCount = 0;
  let warningCount = 0;

  results.forEach((result) => {
    const icon =
      result.status === 'pass' ? '✅' : result.status === 'fail' ? '❌' : '⚠️';

    console.log(`${icon} ${result.name}`);
    console.log(`   ${result.message}`);
    if (result.details) {
      console.log(`   Details: ${result.details}`);
    }
    console.log('');

    if (result.status === 'pass') passCount++;
    if (result.status === 'fail') failCount++;
    if (result.status === 'warning') warningCount++;
  });

  console.log('═══════════════════════════════════════════════════════');
  console.log(`Total: ${results.length} checks`);
  console.log(`✅ Passed: ${passCount}`);
  console.log(`❌ Failed: ${failCount}`);
  console.log(`⚠️  Warnings: ${warningCount}`);
  console.log('═══════════════════════════════════════════════════════\n');

  if (failCount > 0) {
    console.log('🔧 RECOMMENDED ACTIONS:');
    console.log('1. Set missing required environment variables in .env.local');
    console.log('2. Verify Facebook App credentials at https://developers.facebook.com');
    console.log('3. Get NVIDIA API key from https://build.nvidia.com/');
    console.log('4. Restart your development server after updating .env.local\n');
    process.exit(1);
  } else if (warningCount > 0) {
    console.log('⚠️  Some warnings detected. Application may run with limited functionality.\n');
  } else {
    console.log('✅ All validations passed! Your configuration looks good.\n');
  }
}

/**
 * Main function
 */
async function main() {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║   HIRO - Environment & Credentials Validation       ║');
  console.log('╚══════════════════════════════════════════════════════╝');

  checkEnvironmentVariables();
  await validateFacebookCredentials();
  await validateAIServiceKeys();

  printResults();
}

main().catch((error) => {
  console.error('Validation failed:', error);
  process.exit(1);
});

