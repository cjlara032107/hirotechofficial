/**
 * Test AWS format for databases 1 and 2
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testConnection(name: string, url: string) {
  console.log(`\n🔍 Testing ${name}...`);
  console.log(`   URL: ${url.replace(/:[^:@]+@/, ':****@')}`);
  
  try {
    const client = new PrismaClient({
      datasources: { db: { url } },
      log: [],
    });

    const startTime = Date.now();
    await Promise.race([
      client.$queryRaw`SELECT 1`,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000))
    ]);
    const responseTime = Date.now() - startTime;

    await client.$disconnect();

    console.log(`   ✅ SUCCESS! (${responseTime}ms)`);
    return { success: true, url, responseTime };
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    console.log(`   ❌ FAILED: ${errorMsg.substring(0, 150)}`);
    return { success: false, url, error: errorMsg };
  }
}

async function main() {
  console.log('🔬 Testing Different Connection String Formats\n');
  console.log('='.repeat(80));

  const password = 'demet5732595';

  // Test Database 1 - Standard format (current)
  const db1Standard = 'postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true';
  const db1StandardResult = await testConnection('Database 1 (Standard)', db1Standard);

  // Test Database 1 - AWS format
  const db1Aws = 'postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true';
  const db1AwsResult = await testConnection('Database 1 (AWS)', db1Aws);

  // Test Database 2 - Standard format (current)
  const db2Standard = 'postgresql://postgres.kzvhbgqpxykganquikmv:demet5732595@pooler.kzvhbgqpxykganquikmv.supabase.co:6543/postgres?pgbouncer=true';
  const db2StandardResult = await testConnection('Database 2 (Standard)', db2Standard);

  // Test Database 2 - AWS format
  const db2Aws = 'postgresql://postgres.kzvhbgqpxykganquikmv:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true';
  const db2AwsResult = await testConnection('Database 2 (AWS)', db2Aws);

  console.log('\n' + '='.repeat(80));
  console.log('📊 RESULTS SUMMARY\n');

  if (db1AwsResult.success) {
    console.log('✅ Database 1: AWS format works!');
    console.log(`   Update DATABASE_URL_1 to: ${db1Aws.replace(/:[^:@]+@/, ':****@')}`);
  } else if (db1StandardResult.success) {
    console.log('✅ Database 1: Standard format works!');
  } else {
    console.log('❌ Database 1: Both formats failed');
    console.log(`   Standard error: ${db1StandardResult.error?.substring(0, 80)}`);
    console.log(`   AWS error: ${db1AwsResult.error?.substring(0, 80)}`);
  }

  if (db2AwsResult.success) {
    console.log('✅ Database 2: AWS format works!');
    console.log(`   Update DATABASE_URL_2 to: ${db2Aws.replace(/:[^:@]+@/, ':****@')}`);
  } else if (db2StandardResult.success) {
    console.log('✅ Database 2: Standard format works!');
  } else {
    console.log('❌ Database 2: Both formats failed');
    console.log(`   Standard error: ${db2StandardResult.error?.substring(0, 80)}`);
    console.log(`   AWS error: ${db2AwsResult.error?.substring(0, 80)}`);
  }

  console.log('\n' + '='.repeat(80));
  console.log('\n💡 NEXT STEPS:\n');
  
  if (db1AwsResult.success || db2AwsResult.success) {
    console.log('If AWS format works, you need to:');
    console.log('1. Get the correct connection string from Supabase dashboard');
    console.log('2. Go to: Settings → Database → Connection Pooling');
    console.log('3. Copy the EXACT "Transaction mode" connection string');
    console.log('4. Update DATABASE_URL_1 and DATABASE_URL_2 in .env.local');
  } else {
    console.log('Both formats failed. This means:');
    console.log('1. Projects may be paused - Unpause them in Supabase dashboard');
    console.log('2. Connection strings may be wrong - Get fresh ones from dashboard');
    console.log('3. Projects may not exist - Verify in Supabase dashboard');
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);


 * Test AWS format for databases 1 and 2
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testConnection(name: string, url: string) {
  console.log(`\n🔍 Testing ${name}...`);
  console.log(`   URL: ${url.replace(/:[^:@]+@/, ':****@')}`);
  
  try {
    const client = new PrismaClient({
      datasources: { db: { url } },
      log: [],
    });

    const startTime = Date.now();
    await Promise.race([
      client.$queryRaw`SELECT 1`,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000))
    ]);
    const responseTime = Date.now() - startTime;

    await client.$disconnect();

    console.log(`   ✅ SUCCESS! (${responseTime}ms)`);
    return { success: true, url, responseTime };
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    console.log(`   ❌ FAILED: ${errorMsg.substring(0, 150)}`);
    return { success: false, url, error: errorMsg };
  }
}

async function main() {
  console.log('🔬 Testing Different Connection String Formats\n');
  console.log('='.repeat(80));

  const password = 'demet5732595';

  // Test Database 1 - Standard format (current)
  const db1Standard = 'postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true';
  const db1StandardResult = await testConnection('Database 1 (Standard)', db1Standard);

  // Test Database 1 - AWS format
  const db1Aws = 'postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true';
  const db1AwsResult = await testConnection('Database 1 (AWS)', db1Aws);

  // Test Database 2 - Standard format (current)
  const db2Standard = 'postgresql://postgres.kzvhbgqpxykganquikmv:demet5732595@pooler.kzvhbgqpxykganquikmv.supabase.co:6543/postgres?pgbouncer=true';
  const db2StandardResult = await testConnection('Database 2 (Standard)', db2Standard);

  // Test Database 2 - AWS format
  const db2Aws = 'postgresql://postgres.kzvhbgqpxykganquikmv:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true';
  const db2AwsResult = await testConnection('Database 2 (AWS)', db2Aws);

  console.log('\n' + '='.repeat(80));
  console.log('📊 RESULTS SUMMARY\n');

  if (db1AwsResult.success) {
    console.log('✅ Database 1: AWS format works!');
    console.log(`   Update DATABASE_URL_1 to: ${db1Aws.replace(/:[^:@]+@/, ':****@')}`);
  } else if (db1StandardResult.success) {
    console.log('✅ Database 1: Standard format works!');
  } else {
    console.log('❌ Database 1: Both formats failed');
    console.log(`   Standard error: ${db1StandardResult.error?.substring(0, 80)}`);
    console.log(`   AWS error: ${db1AwsResult.error?.substring(0, 80)}`);
  }

  if (db2AwsResult.success) {
    console.log('✅ Database 2: AWS format works!');
    console.log(`   Update DATABASE_URL_2 to: ${db2Aws.replace(/:[^:@]+@/, ':****@')}`);
  } else if (db2StandardResult.success) {
    console.log('✅ Database 2: Standard format works!');
  } else {
    console.log('❌ Database 2: Both formats failed');
    console.log(`   Standard error: ${db2StandardResult.error?.substring(0, 80)}`);
    console.log(`   AWS error: ${db2AwsResult.error?.substring(0, 80)}`);
  }

  console.log('\n' + '='.repeat(80));
  console.log('\n💡 NEXT STEPS:\n');
  
  if (db1AwsResult.success || db2AwsResult.success) {
    console.log('If AWS format works, you need to:');
    console.log('1. Get the correct connection string from Supabase dashboard');
    console.log('2. Go to: Settings → Database → Connection Pooling');
    console.log('3. Copy the EXACT "Transaction mode" connection string');
    console.log('4. Update DATABASE_URL_1 and DATABASE_URL_2 in .env.local');
  } else {
    console.log('Both formats failed. This means:');
    console.log('1. Projects may be paused - Unpause them in Supabase dashboard');
    console.log('2. Connection strings may be wrong - Get fresh ones from dashboard');
    console.log('3. Projects may not exist - Verify in Supabase dashboard');
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);




