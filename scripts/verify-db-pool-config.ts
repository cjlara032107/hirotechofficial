/**
 * Database Pool Configuration Verification Script
 * 
 * This script verifies the database connection pool configuration
 * and tests connectivity to ensure the new pool settings are working correctly.
 * 
 * Usage:
 *   npm run verify-db-pool
 *   or
 *   tsx scripts/verify-db-pool-config.ts
 */

import { PrismaClient } from '@prisma/client';

interface PoolConfig {
  connectionLimit?: number;
  poolTimeout?: number;
  connectTimeout?: number;
  environment: 'vercel' | 'local';
  host?: string;
  usesPooler: boolean;
}

function extractPoolConfig(url: string): PoolConfig {
  const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
  
  // Extract host
  let host = 'unknown';
  try {
    const urlMatch = url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
    host = urlMatch ? urlMatch[1] : 'unknown';
  } catch {
    // Ignore
  }
  
  // Check if using pooler
  const usesPooler = url.includes('pooler.supabase.com');
  
  // Extract connection parameters
  const connectionLimit = parseInt(url.match(/connection_limit=(\d+)/)?.[1] || '0', 10) || undefined;
  const poolTimeout = parseInt(url.match(/pool_timeout=(\d+)/)?.[1] || '0', 10) || undefined;
  const connectTimeout = parseInt(url.match(/connect_timeout=(\d+)/)?.[1] || '0', 10) || undefined;
  
  return {
    connectionLimit,
    poolTimeout,
    connectTimeout,
    environment: isVercel ? 'vercel' : 'local',
    host,
    usesPooler,
  };
}

function formatCheck(passed: boolean, message: string): string {
  return passed ? `✅ ${message}` : `❌ ${message}`;
}

async function verifyDatabaseConnection(dbUrl: string, dbIndex?: number): Promise<boolean> {
  const dbLabel = dbIndex !== undefined ? `DB ${dbIndex}` : 'Database';
  console.log(`\n🔍 Testing ${dbLabel} connection...`);
  
  const prisma = new PrismaClient({
    datasources: {
      db: { url: dbUrl },
    },
  });
  
  try {
    const startTime = Date.now();
    await prisma.$queryRaw`SELECT 1 as health_check`;
    const duration = Date.now() - startTime;
    
    console.log(`✅ ${dbLabel} connection successful (${duration}ms)`);
    await prisma.$disconnect();
    return true;
  } catch (error: any) {
    console.error(`❌ ${dbLabel} connection failed:`, error?.message || String(error));
    await prisma.$disconnect().catch(() => {});
    return false;
  }
}

async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📊 DATABASE POOL CONFIGURATION VERIFICATION');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  // Check environment
  const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
  console.log(`\n🌍 Environment: ${isVercel ? 'Vercel/Serverless' : 'Local/Traditional'}`);
  
  // Expected values based on environment
  const expectedConnectionLimit = isVercel ? 20 : 30;
  const expectedPoolTimeout = isVercel ? 60 : 90;
  const expectedConnectTimeout = isVercel ? 60 : 30;
  
  console.log(`\n📋 Expected Configuration:`);
  console.log(`   - Connection Limit: ${expectedConnectionLimit}`);
  console.log(`   - Pool Timeout: ${expectedPoolTimeout}s`);
  console.log(`   - Connect Timeout: ${expectedConnectTimeout}s`);
  
  // Check multi-DB mode
  const enableMultiDb = process.env.ENABLE_MULTI_DB === 'true';
  console.log(`\n🔧 Multi-DB Mode: ${enableMultiDb ? 'Enabled' : 'Disabled'}`);
  
  const databases: { url: string; index?: number }[] = [];
  
  if (enableMultiDb) {
    // Check all DATABASE_URL_X variables
    for (let i = 0; i < 10; i++) {
      const dbUrl = process.env[`DATABASE_URL_${i}`];
      if (dbUrl) {
        databases.push({ url: dbUrl, index: i });
      }
    }
    console.log(`   - Configured Databases: ${databases.length}`);
  } else {
    // Single DB mode
    const dbUrl = process.env.DATABASE_URL;
    if (dbUrl) {
      databases.push({ url: dbUrl });
    }
  }
  
  if (databases.length === 0) {
    console.error('\n❌ No database URLs configured!');
    console.error('   Set DATABASE_URL or DATABASE_URL_0, DATABASE_URL_1, etc.');
    process.exit(1);
  }
  
  // Verify each database
  let allPassed = true;
  
  for (const { url, index } of databases) {
    const dbLabel = index !== undefined ? `Database ${index}` : 'Database';
    console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`📦 ${dbLabel} Configuration`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    
    const config = extractPoolConfig(url);
    
    console.log(`\n🔍 Extracted Configuration:`);
    console.log(`   - Host: ${config.host}`);
    console.log(`   - Uses Pooler: ${config.usesPooler ? 'Yes' : 'No'}`);
    console.log(`   - Connection Limit: ${config.connectionLimit || 'Not set'}`);
    console.log(`   - Pool Timeout: ${config.poolTimeout ? `${config.poolTimeout}s` : 'Not set'}`);
    console.log(`   - Connect Timeout: ${config.connectTimeout ? `${config.connectTimeout}s` : 'Not set'}`);
    
    // Validation checks
    console.log(`\n✓ Validation Checks:`);
    
    const checks = [
      {
        passed: config.usesPooler,
        message: 'Using Supabase pooler (pooler.supabase.com)',
        critical: true,
      },
      {
        passed: config.connectionLimit === expectedConnectionLimit,
        message: `Connection limit is ${expectedConnectionLimit}`,
        critical: true,
      },
      {
        passed: config.poolTimeout === expectedPoolTimeout,
        message: `Pool timeout is ${expectedPoolTimeout}s`,
        critical: false,
      },
      {
        passed: config.connectTimeout === expectedConnectTimeout,
        message: `Connect timeout is ${expectedConnectTimeout}s`,
        critical: false,
      },
      {
        passed: url.includes('pgbouncer=true'),
        message: 'pgbouncer parameter set',
        critical: false,
      },
      {
        passed: url.includes('statement_cache_size=0'),
        message: 'Statement cache disabled (recommended for pooler)',
        critical: false,
      },
    ];
    
    for (const check of checks) {
      console.log(`   ${formatCheck(check.passed, check.message)}`);
      if (!check.passed && check.critical) {
        allPassed = false;
      }
    }
    
    // Test connection
    const connectionOk = await verifyDatabaseConnection(url, index);
    if (!connectionOk) {
      allPassed = false;
    }
  }
  
  // Summary
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📊 VERIFICATION SUMMARY');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  if (allPassed) {
    console.log('\n✅ All checks passed!');
    console.log('   Database pool configuration is correct.');
    console.log('   Your application should have reduced P2024 errors.');
  } else {
    console.log('\n⚠️  Some checks failed!');
    console.log('   Review the errors above and update your configuration.');
    console.log('\n📖 Recommendations:');
    console.log('   1. Ensure you are using Supabase pooler URLs');
    console.log('   2. Update connection limits in src/lib/db.ts if needed');
    console.log('   3. Check your .env file for correct DATABASE_URL format');
    console.log('   4. Review docs/database-pool-configuration.md for details');
  }
  
  // Additional recommendations
  console.log('\n💡 Additional Tips:');
  console.log('   • Monitor logs with: [DB Pool] prefix');
  console.log('   • Watch for P2024 errors in production');
  console.log('   • Set up alerts for pool exhaustion warnings');
  console.log('   • Review Supabase connection limits for your plan');
  
  if (enableMultiDb) {
    console.log(`   • Total connections: ${databases.length} × ${expectedConnectionLimit} = ${databases.length * expectedConnectionLimit} per instance`);
  } else {
    console.log(`   • Total connections: ${expectedConnectionLimit} per instance`);
  }
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  process.exit(allPassed ? 0 : 1);
}

main().catch((error) => {
  console.error('\n❌ Fatal error during verification:', error);
  process.exit(1);
});

