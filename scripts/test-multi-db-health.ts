#!/usr/bin/env tsx
/**
 * Test multi-database health endpoint
 */

import * as dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });
dotenv.config();

const ENABLE_MULTI_DB = process.env.ENABLE_MULTI_DB === 'true';
const DB_COUNT = parseInt(process.env.DB_COUNT || '1', 10);

console.log('🧪 Testing Multi-Database Setup...\n');
console.log('='.repeat(80));
console.log(`Multi-DB Enabled: ${ENABLE_MULTI_DB}`);
console.log(`Database Count: ${DB_COUNT}\n`);

if (!ENABLE_MULTI_DB) {
  console.log('⚠️  Multi-DB is disabled. Set ENABLE_MULTI_DB=true in .env.local');
  process.exit(0);
}

// Test the router directly
try {
  const { getDatabaseRouter } = await import('../src/lib/db/multi-db-router');
  const router = getDatabaseRouter();
  const status = router.getStatus();

  console.log('📊 Database Router Status:\n');
  console.log(`   Total Databases: ${status.totalDatabases}`);
  console.log(`   Healthy: ${status.healthyDatabases}`);
  console.log(`   Degraded: ${status.degradedDatabases}`);
  console.log(`   Down: ${status.downDatabases}`);
  console.log(`   Routing Strategy: ${status.routingStrategy}\n`);

  console.log('📋 Individual Database Status:\n');
  status.databases.forEach((db, index) => {
    const healthIcon = db.health === 'healthy' ? '✅' : db.health === 'degraded' ? '⚠️' : '❌';
    console.log(`   ${healthIcon} Database ${db.index}: ${db.health}`);
    console.log(`      Last Health Check: ${new Date(db.lastHealthCheck).toLocaleString()}`);
    console.log(`      Connection Count: ${db.connectionCount}\n`);
  });

  // Test routing
  console.log('🔀 Testing Hash-Based Routing:\n');
  const testOrgIds = ['org-1', 'org-2', 'org-3', 'org-4', 'org-5'];
  const { getPrisma } = await import('../src/lib/db/multi-db-router');
  
  testOrgIds.forEach(orgId => {
    const client = getPrisma(orgId);
    // Just verify we can get a client (don't actually query)
    console.log(`   ✅ Organization "${orgId}" → Database client obtained`);
  });

  console.log('\n' + '='.repeat(80));
  console.log('✅ Multi-Database Setup Test Complete!');
  console.log('\n💡 Next Steps:');
  console.log('   1. Start your dev server: npm run dev');
  console.log('   2. Visit: http://localhost:3000/api/health/db-router');
  console.log('   3. Test API routes that use getPrismaForOrg()');

} catch (error) {
  console.error('❌ Error testing multi-DB setup:', error);
  process.exit(1);
}




