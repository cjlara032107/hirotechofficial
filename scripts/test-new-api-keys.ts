import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.join(process.cwd(), '.env.local') });

import OpenAI from 'openai';

const NEW_KEYS = [
  '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',
  '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',
];

async function testApiKey(key: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: key,
    });

    // Test with a simple, fast request
    const response = await Promise.race([
      client.chat.completions.create({
        model: 'openai/gpt-oss-120b',
        messages: [{ role: 'user', content: 'Say "test" only.' }],
        max_tokens: 10,
      }),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000)
      ),
    ]);

    if (response.choices?.[0]?.message?.content) {
      return { valid: true };
    } else {
      return { valid: false, error: 'Empty response from API' };
    }
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    const statusCode = error?.status || error?.response?.status;
    
    // 403 means invalid key or no access
    if (statusCode === 403) {
      return { valid: false, error: '403 Forbidden - Invalid key or no access' };
    }
    // 429 means rate limited but key is valid
    if (statusCode === 429) {
      return { valid: true, error: 'Rate limited (key is valid)' };
    }
    // 401 means authentication failed
    if (statusCode === 401) {
      return { valid: false, error: '401 Unauthorized - Invalid API key' };
    }
    
    return { valid: false, error: errorMsg };
  }
}

async function testAndAddKeys() {
  console.log('\n🔍 Testing new API keys...\n');

  const results: Array<{ key: string; valid: boolean; error?: string }> = [];

  for (let i = 0; i < NEW_KEYS.length; i++) {
    const key = NEW_KEYS[i];
    const prefix = key.substring(0, 20) + '...';
    
    console.log(`[${i + 1}/${NEW_KEYS.length}] Testing: ${prefix}`);
    
    const testResult = await testApiKey(key);
    results.push({ key, valid: testResult.valid, error: testResult.error });
    
    if (testResult.valid) {
      console.log(`  ✅ Key is valid and working!${testResult.error ? ` (${testResult.error})` : ''}\n`);
    } else {
      console.log(`  ❌ Key test failed: ${testResult.error || 'Unknown error'}\n`);
    }
  }

  console.log('\n📊 Test Results:');
  console.log('============================================================');
  const validKeys = results.filter(r => r.valid);
  const invalidKeys = results.filter(r => !r.valid);
  
  console.log(`✅ Valid keys: ${validKeys.length}/${NEW_KEYS.length}`);
  console.log(`❌ Invalid keys: ${invalidKeys.length}/${NEW_KEYS.length}`);
  
  if (invalidKeys.length > 0) {
    console.log('\nInvalid keys:');
    invalidKeys.forEach(({ key, error }) => {
      console.log(`  - ${key.substring(0, 20)}... (${error || 'Test failed'})`);
    });
  }

  if (validKeys.length === 0) {
    console.log('\n⚠️  No valid keys found. Cannot add keys to database.');
    process.exit(1);
  }

  if (validKeys.length > 0) {
    console.log('\n💾 Adding valid keys to database...\n');
    
    // Import database modules only when needed
    const { prisma } = await import('@/lib/db');
    const { encryptKey } = await import('@/lib/crypto/encryption');
    const { ApiKeyStatus } = await import('@prisma/client');
    
    // Connect to database
    try {
      await prisma.$connect();
      console.log('✅ Connected to database\n');
    } catch (error) {
      console.error('❌ Failed to connect to database:', error instanceof Error ? error.message : String(error));
      console.error('⚠️  Skipping database operations. Keys were tested but not added.');
      process.exit(1);
    }
    
    let added = 0;
    let skipped = 0;
    let errors = 0;

    for (const { key, valid } of validKeys) {
      if (!valid) continue;

      try {
        const encryptedKey = encryptKey(key);
        
        // Check if key already exists
        const existing = await prisma.apiKey.findFirst({
          where: { encryptedKey },
        });

        if (existing) {
          console.log(`⏭️  Skipped: ${key.substring(0, 20)}... (already exists)`);
          skipped++;
          continue;
        }

        // Create new API key
        const apiKey = await prisma.apiKey.create({
          data: {
            name: `NVIDIA Key ${key.substring(0, 12)}`,
            encryptedKey,
            status: ApiKeyStatus.ACTIVE,
            metadata: {
              prefix: key.substring(0, 12),
              length: key.length,
              addedAt: new Date().toISOString(),
              addedBy: 'test-script',
            },
          },
        });

        console.log(`✅ Added: ${key.substring(0, 20)}... (ID: ${apiKey.id.substring(0, 8)}...)`);
        added++;
      } catch (error) {
        console.error(`❌ Error adding ${key.substring(0, 20)}...:`, error instanceof Error ? error.message : String(error));
        errors++;
      }
    }

    console.log('\n📊 Summary:');
    console.log('============================================================');
    console.log(`✅ Added: ${added}`);
    console.log(`⏭️  Skipped: ${skipped}`);
    console.log(`❌ Errors: ${errors}`);
    
    // Show total active keys
    const totalActive = await prisma.apiKey.count({
      where: { status: ApiKeyStatus.ACTIVE },
    });
    console.log(`\n📦 Total active keys in database: ${totalActive}`);
    console.log('\n');

    await prisma.$disconnect();
  } else {
    console.log('\n⚠️  No valid keys to add. Please check the keys and try again.');
  }
}

testAndAddKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

