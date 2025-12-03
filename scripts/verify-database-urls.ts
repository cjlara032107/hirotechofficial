/**
 * Verify Database URLs - Check if they're correct or mixed up
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testUrlVariations(projectRef: string, password: string) {
  const variations = [
    // Format 1: AWS pooler (like DB 0)
    `postgresql://postgres.${projectRef}:${password}@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true`,
    // Format 2: Standard pooler (current format)
    `postgresql://postgres.${projectRef}:${password}@pooler.${projectRef}.supabase.co:6543/postgres?pgbouncer=true`,
    // Format 3: Direct connection
    `postgresql://postgres:${password}@db.${projectRef}.supabase.co:5432/postgres`,
  ];

  const results = [];

  for (let i = 0; i < variations.length; i++) {
    const url = variations[i];
    const type = i === 0 ? 'AWS Pooler' : i === 1 ? 'Standard Pooler' : 'Direct';
    
    try {
      const client = new PrismaClient({
        datasources: { db: { url } },
        log: [],
      });

      const startTime = Date.now();
      await Promise.race([
        client.$queryRaw`SELECT 1`,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000))
      ]);
      const responseTime = Date.now() - startTime;

      await client.$disconnect();

      results.push({ type, url: url.replace(/:[^:@]+@/, ':****@'), success: true, responseTime });
    } catch (error: any) {
      results.push({ 
        type, 
        url: url.replace(/:[^:@]+@/, ':****@'), 
        success: false, 
        error: error?.message?.substring(0, 100) || String(error) 
      });
    }
  }

  return results;
}

async function main() {
  console.log('🔍 Verifying Database URLs - Testing All Variations\n');
  console.log('='.repeat(80));

  const password = 'demet5732595';

  // Test Database 1
  console.log('\n📊 Database 1 (vivelzjlltbytnhybdcm)\n');
  const db1Results = await testUrlVariations('vivelzjlltbytnhybdcm', password);
  db1Results.forEach(r => {
    console.log(`${r.success ? '✅' : '❌'} ${r.type}: ${r.success ? `${r.responseTime}ms` : r.error}`);
  });

  // Test Database 2
  console.log('\n📊 Database 2 (kzvhbgqpxykganquikmv)\n');
  const db2Results = await testUrlVariations('kzvhbgqpxykganquikmv', password);
  db2Results.forEach(r => {
    console.log(`${r.success ? '✅' : '❌'} ${r.type}: ${r.success ? `${r.responseTime}ms` : r.error}`);
  });

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('📊 SUMMARY\n');

  const db1Working = db1Results.find(r => r.success);
  const db2Working = db2Results.find(r => r.success);

  if (db1Working) {
    console.log(`✅ Database 1: Working with ${db1Working.type}`);
    console.log(`   URL: ${db1Working.url}`);
  } else {
    console.log(`❌ Database 1: No working connection found`);
  }

  if (db2Working) {
    console.log(`✅ Database 2: Working with ${db2Working.type}`);
    console.log(`   URL: ${db2Working.url}`);
  } else {
    console.log(`❌ Database 2: No working connection found`);
  }

  if (!db1Working && !db2Working) {
    console.log('\n⚠️  Neither database is reachable. Possible causes:');
    console.log('   1. Supabase projects are paused (free tier pauses after inactivity)');
    console.log('   2. Projects were deleted or suspended');
    console.log('   3. Network/firewall blocking connections');
    console.log('   4. Connection strings need to be updated from Supabase dashboard');
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);


 * Verify Database URLs - Check if they're correct or mixed up
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testUrlVariations(projectRef: string, password: string) {
  const variations = [
    // Format 1: AWS pooler (like DB 0)
    `postgresql://postgres.${projectRef}:${password}@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true`,
    // Format 2: Standard pooler (current format)
    `postgresql://postgres.${projectRef}:${password}@pooler.${projectRef}.supabase.co:6543/postgres?pgbouncer=true`,
    // Format 3: Direct connection
    `postgresql://postgres:${password}@db.${projectRef}.supabase.co:5432/postgres`,
  ];

  const results = [];

  for (let i = 0; i < variations.length; i++) {
    const url = variations[i];
    const type = i === 0 ? 'AWS Pooler' : i === 1 ? 'Standard Pooler' : 'Direct';
    
    try {
      const client = new PrismaClient({
        datasources: { db: { url } },
        log: [],
      });

      const startTime = Date.now();
      await Promise.race([
        client.$queryRaw`SELECT 1`,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000))
      ]);
      const responseTime = Date.now() - startTime;

      await client.$disconnect();

      results.push({ type, url: url.replace(/:[^:@]+@/, ':****@'), success: true, responseTime });
    } catch (error: any) {
      results.push({ 
        type, 
        url: url.replace(/:[^:@]+@/, ':****@'), 
        success: false, 
        error: error?.message?.substring(0, 100) || String(error) 
      });
    }
  }

  return results;
}

async function main() {
  console.log('🔍 Verifying Database URLs - Testing All Variations\n');
  console.log('='.repeat(80));

  const password = 'demet5732595';

  // Test Database 1
  console.log('\n📊 Database 1 (vivelzjlltbytnhybdcm)\n');
  const db1Results = await testUrlVariations('vivelzjlltbytnhybdcm', password);
  db1Results.forEach(r => {
    console.log(`${r.success ? '✅' : '❌'} ${r.type}: ${r.success ? `${r.responseTime}ms` : r.error}`);
  });

  // Test Database 2
  console.log('\n📊 Database 2 (kzvhbgqpxykganquikmv)\n');
  const db2Results = await testUrlVariations('kzvhbgqpxykganquikmv', password);
  db2Results.forEach(r => {
    console.log(`${r.success ? '✅' : '❌'} ${r.type}: ${r.success ? `${r.responseTime}ms` : r.error}`);
  });

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('📊 SUMMARY\n');

  const db1Working = db1Results.find(r => r.success);
  const db2Working = db2Results.find(r => r.success);

  if (db1Working) {
    console.log(`✅ Database 1: Working with ${db1Working.type}`);
    console.log(`   URL: ${db1Working.url}`);
  } else {
    console.log(`❌ Database 1: No working connection found`);
  }

  if (db2Working) {
    console.log(`✅ Database 2: Working with ${db2Working.type}`);
    console.log(`   URL: ${db2Working.url}`);
  } else {
    console.log(`❌ Database 2: No working connection found`);
  }

  if (!db1Working && !db2Working) {
    console.log('\n⚠️  Neither database is reachable. Possible causes:');
    console.log('   1. Supabase projects are paused (free tier pauses after inactivity)');
    console.log('   2. Projects were deleted or suspended');
    console.log('   3. Network/firewall blocking connections');
    console.log('   4. Connection strings need to be updated from Supabase dashboard');
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);




