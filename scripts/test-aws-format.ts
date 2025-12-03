/**
 * Test if databases 1 and 2 work with AWS format (like Database 0)
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testAwsFormat(projectRef: string, password: string) {
  const awsUrl = `postgresql://postgres.${projectRef}:${password}@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true`;
  
  console.log(`\n🔍 Testing AWS format for ${projectRef}...`);
  console.log(`   URL: ${awsUrl.replace(/:[^:@]+@/, ':****@')}`);
  
  try {
    const client = new PrismaClient({
      datasources: { db: { url: awsUrl } },
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
    return { success: true, url: awsUrl, responseTime };
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    console.log(`   ❌ FAILED: ${errorMsg.substring(0, 150)}`);
    return { success: false, url: awsUrl, error: errorMsg };
  }
}

async function main() {
  console.log('🔬 Testing AWS Format for Databases 1 & 2\n');
  console.log('='.repeat(80));

  const password = 'demet5732595';

  // Test Database 1 with AWS format
  const db1Result = await testAwsFormat('vivelzjlltbytnhybdcm', password);
  
  // Test Database 2 with AWS format
  const db2Result = await testAwsFormat('kzvhbgqpxykganquikmv', password);

  console.log('\n' + '='.repeat(80));
  console.log('📊 RESULTS\n');

  if (db1Result.success) {
    console.log('✅ Database 1: AWS format works!');
    console.log(`   Use this URL: ${db1Result.url.replace(/:[^:@]+@/, ':****@')}`);
  } else {
    console.log('❌ Database 1: AWS format also fails');
    console.log(`   Error: ${db1Result.error?.substring(0, 100)}`);
  }

  if (db2Result.success) {
    console.log('✅ Database 2: AWS format works!');
    console.log(`   Use this URL: ${db2Result.url.replace(/:[^:@]+@/, ':****@')}`);
  } else {
    console.log('❌ Database 2: AWS format also fails');
    console.log(`   Error: ${db2Result.error?.substring(0, 100)}`);
  }

  if (db1Result.success || db2Result.success) {
    console.log('\n💡 SOLUTION:');
    console.log('   Update .env.local with AWS format URLs for working databases');
  } else {
    console.log('\n💡 ROOT CAUSE:');
    console.log('   Projects may be:');
    console.log('   1. Deleted or suspended');
    console.log('   2. Paused (free tier pauses after inactivity)');
    console.log('   3. Project references are incorrect');
    console.log('\n   Action: Check Supabase dashboard to verify projects exist');
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);


 * Test if databases 1 and 2 work with AWS format (like Database 0)
 */

import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

async function testAwsFormat(projectRef: string, password: string) {
  const awsUrl = `postgresql://postgres.${projectRef}:${password}@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true`;
  
  console.log(`\n🔍 Testing AWS format for ${projectRef}...`);
  console.log(`   URL: ${awsUrl.replace(/:[^:@]+@/, ':****@')}`);
  
  try {
    const client = new PrismaClient({
      datasources: { db: { url: awsUrl } },
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
    return { success: true, url: awsUrl, responseTime };
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    console.log(`   ❌ FAILED: ${errorMsg.substring(0, 150)}`);
    return { success: false, url: awsUrl, error: errorMsg };
  }
}

async function main() {
  console.log('🔬 Testing AWS Format for Databases 1 & 2\n');
  console.log('='.repeat(80));

  const password = 'demet5732595';

  // Test Database 1 with AWS format
  const db1Result = await testAwsFormat('vivelzjlltbytnhybdcm', password);
  
  // Test Database 2 with AWS format
  const db2Result = await testAwsFormat('kzvhbgqpxykganquikmv', password);

  console.log('\n' + '='.repeat(80));
  console.log('📊 RESULTS\n');

  if (db1Result.success) {
    console.log('✅ Database 1: AWS format works!');
    console.log(`   Use this URL: ${db1Result.url.replace(/:[^:@]+@/, ':****@')}`);
  } else {
    console.log('❌ Database 1: AWS format also fails');
    console.log(`   Error: ${db1Result.error?.substring(0, 100)}`);
  }

  if (db2Result.success) {
    console.log('✅ Database 2: AWS format works!');
    console.log(`   Use this URL: ${db2Result.url.replace(/:[^:@]+@/, ':****@')}`);
  } else {
    console.log('❌ Database 2: AWS format also fails');
    console.log(`   Error: ${db2Result.error?.substring(0, 100)}`);
  }

  if (db1Result.success || db2Result.success) {
    console.log('\n💡 SOLUTION:');
    console.log('   Update .env.local with AWS format URLs for working databases');
  } else {
    console.log('\n💡 ROOT CAUSE:');
    console.log('   Projects may be:');
    console.log('   1. Deleted or suspended');
    console.log('   2. Paused (free tier pauses after inactivity)');
    console.log('   3. Project references are incorrect');
    console.log('\n   Action: Check Supabase dashboard to verify projects exist');
  }

  console.log('\n' + '='.repeat(80));
}

main().catch(console.error);




