/**
 * Simple script to check API key status from database
 * Uses require to ensure env vars are loaded before Prisma initialization
 */

// Load env vars using require (synchronous, happens before any imports)
require('dotenv').config({ path: require('path').join(process.cwd(), '.env.local') });

// Verify DATABASE_URL
if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL not found');
  console.error('💡 Make sure .env.local exists and contains DATABASE_URL');
  process.exit(1);
}

// Now import Prisma (env vars are already loaded)
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkKeys() {
  console.log('\n📊 Checking API Keys Status...\n');

  try {
    const keys = await prisma.apiKey.findMany({
      where: { status: 'ACTIVE' },
      select: {
        id: true,
        name: true,
        status: true,
        totalRequests: true,
        failedRequests: true,
        consecutiveFailures: true,
        lastSuccessAt: true,
        lastUsedAt: true,
        rateLimitedAt: true,
        metadata: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    if (keys.length === 0) {
      console.log('⚠️  No active keys found.\n');
      await prisma.$disconnect();
      return;
    }

    console.log(`Found ${keys.length} active key(s):\n`);
    console.log('='.repeat(80));

    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const metadata = key.metadata as any || {};
      
      console.log(`\n[${i + 1}] ${key.name || 'Unnamed Key'}`);
      console.log(`    ID: ${key.id.substring(0, 12)}...`);
      console.log(`    Status: ${key.status}`);
      console.log(`    Total Requests: ${key.totalRequests}`);
      console.log(`    Failed Requests: ${key.failedRequests}`);
      console.log(`    Success Rate: ${key.totalRequests > 0 ? ((key.totalRequests - key.failedRequests) / key.totalRequests * 100).toFixed(1) : 0}%`);
      console.log(`    Consecutive Failures: ${key.consecutiveFailures}`);
      
      if (key.lastSuccessAt) {
        const lastSuccess = new Date(key.lastSuccessAt);
        const timeSince = Math.floor((Date.now() - lastSuccess.getTime()) / 1000 / 60);
        console.log(`    Last Success: ${timeSince} minutes ago`);
      } else {
        console.log(`    Last Success: Never`);
      }
      
      if (key.rateLimitedAt) {
        const rateLimitTime = new Date(key.rateLimitedAt);
        const hoursSince = Math.floor((Date.now() - rateLimitTime.getTime()) / 1000 / 60 / 60);
        const hoursRemaining = Math.max(0, 24 - hoursSince);
        console.log(`    ⚠️  Rate Limited: ${hoursSince}h ago (${hoursRemaining}h remaining)`);
      }
      
      if (metadata.hasPrimaryModelAccess === false) {
        console.log(`    ⚠️  No access to openai/gpt-oss-120b`);
      } else if (metadata.hasPrimaryModelAccess === true) {
        console.log(`    ✅ Has access to openai/gpt-oss-120b`);
      }
      
      if (metadata.canMakeApiCalls === false) {
        console.log(`    ❌ Cannot make API calls (read-only)`);
      }
      
      if (metadata.note) {
        console.log(`    📝 Note: ${metadata.note}`);
      }
    }

    console.log('\n' + '='.repeat(80));
    console.log('\n📈 Summary:');
    
    const withPrimaryModel = keys.filter(k => (k.metadata as any)?.hasPrimaryModelAccess === true);
    const withoutPrimaryModel = keys.filter(k => (k.metadata as any)?.hasPrimaryModelAccess === false);
    const readOnly = keys.filter(k => (k.metadata as any)?.canMakeApiCalls === false);
    const neverUsed = keys.filter(k => !k.lastSuccessAt);
    const rateLimited = keys.filter(k => k.rateLimitedAt);
    
    console.log(`   ✅ Keys with primary model access: ${withPrimaryModel.length}`);
    console.log(`   ⚠️  Keys without primary model access: ${withoutPrimaryModel.length}`);
    console.log(`   📖 Read-only keys: ${readOnly.length}`);
    console.log(`   🆕 Never used: ${neverUsed.length}`);
    console.log(`   🚫 Rate limited: ${rateLimited.length}`);
    
    if (withPrimaryModel.length === 0) {
      console.log('\n⚠️  WARNING: No keys have access to openai/gpt-oss-120b!');
      console.log('   The system will not be able to analyze contacts.');
    } else {
      console.log(`\n✅ You have ${withPrimaryModel.length} working key(s) ready to use!`);
    }
    
    console.log('\n');

    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    await prisma.$disconnect();
    process.exit(1);
  }
}

checkKeys().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
