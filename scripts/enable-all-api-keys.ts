/**
 * Enable All API Keys
 * Re-enables all DISABLED and RATE_LIMITED API keys
 * Use with caution - only enable keys that should be active
 */

import { PrismaClient, ApiKeyStatus } from '@prisma/client';
import { config } from 'dotenv';
import { resolve } from 'path';

// Load environment variables
config({ path: resolve(process.cwd(), '.env.local') });
config({ path: resolve(process.cwd(), '.env') });

const prisma = new PrismaClient();

async function enableAllApiKeys() {
  try {
    console.log('🔧 Enabling All API Keys...\n');

    // Get all disabled and rate-limited keys
    const keysToEnable = await prisma.apiKey.findMany({
      where: {
        status: {
          in: [ApiKeyStatus.DISABLED, ApiKeyStatus.RATE_LIMITED],
        },
      },
    });

    if (keysToEnable.length === 0) {
      console.log('✅ All keys are already ACTIVE!');
      return;
    }

    console.log(`📋 Found ${keysToEnable.length} keys to enable:\n`);

    let enabled = 0;
    let failed = 0;

    for (const key of keysToEnable) {
      try {
        const metadata = key.metadata as any;
        const prefix = metadata?.prefix || key.id.substring(0, 8);
        
        await prisma.apiKey.update({
          where: { id: key.id },
          data: {
            status: ApiKeyStatus.ACTIVE,
            rateLimitedAt: null, // Clear rate limit timestamp
            consecutiveFailures: 0, // Reset consecutive failures
          },
        });

        console.log(`   ✅ Enabled: ${key.name || 'unnamed'} (${prefix}...)`);
        enabled++;
      } catch (error) {
        console.error(`   ❌ Failed to enable ${key.id}:`, error);
        failed++;
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log('📊 Results:');
    console.log(`   ✅ Enabled: ${enabled}`);
    console.log(`   ❌ Failed: ${failed}`);
    console.log('='.repeat(60));

    // Get final count
    const activeCount = await prisma.apiKey.count({
      where: { status: ApiKeyStatus.ACTIVE },
    });

    console.log(`\n🎉 Total Active Keys: ${activeCount}`);

  } catch (error) {
    console.error('❌ Error enabling API keys:', error);
  } finally {
    await prisma.$disconnect();
  }
}

enableAllApiKeys();

