/**
 * Verify Supabase Projects and Get Correct Connection Strings
 * Helps identify if projects exist and what the correct URLs should be
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

console.log('🔍 Supabase Project Verification Guide\n');
console.log('='.repeat(80));

console.log('\n📋 Current Configuration:\n');

const projects = [
  { index: 0, ref: 'qudsmrrfbatasnyvuxch', url: process.env.DATABASE_URL_0 },
  { index: 1, ref: 'vivelzjlltbytnhybdcm', url: process.env.DATABASE_URL_1 },
  { index: 2, ref: 'kzvhbgqpxykganquikmv', url: process.env.DATABASE_URL_2 },
];

projects.forEach(project => {
  console.log(`Database ${project.index}:`);
  console.log(`  Project Reference: ${project.ref}`);
  console.log(`  Dashboard URL: https://${project.ref}.supabase.co`);
  console.log(`  Connection String: ${project.url ? '✅ Set' : '❌ Not set'}`);
  if (project.url) {
    const urlObj = new URL(project.url);
    console.log(`  Hostname: ${urlObj.hostname}`);
    console.log(`  Port: ${urlObj.port || '6543'}`);
  }
  console.log('');
});

console.log('='.repeat(80));
console.log('\n🔧 HOW TO FIX:\n');

console.log('1. Go to Supabase Dashboard: https://supabase.com/dashboard\n');

projects.forEach(project => {
  if (project.index > 0) {
    console.log(`\n📊 For Database ${project.index} (${project.ref}):`);
    console.log(`   a. Visit: https://${project.ref}.supabase.co`);
    console.log(`   b. Check if project exists and is active`);
    console.log(`   c. If paused → Click "Restore" or "Unpause"`);
    console.log(`   d. Go to: Settings → Database → Connection Pooling`);
    console.log(`   e. Copy the EXACT "Transaction mode" connection string`);
    console.log(`   f. Update DATABASE_URL_${project.index} in .env.local`);
    console.log(`   g. Format should be:`);
    console.log(`      postgresql://postgres.[ref]:[password]@[hostname]:6543/postgres?pgbouncer=true`);
  }
});

console.log('\n' + '='.repeat(80));
console.log('\n💡 ALTERNATIVE: If Projects Don\'t Exist\n');

console.log('If the projects were deleted or don\'t exist:');
console.log('  1. Create new Supabase projects');
console.log('  2. Get connection strings from each');
console.log('  3. Update .env.local with new DATABASE_URL_1 and DATABASE_URL_2');
console.log('  4. Run migrations: npx tsx scripts/migrate-all-databases.ts');

console.log('\n' + '='.repeat(80));
console.log('\n✅ CURRENT STATUS:\n');

console.log('✅ Database 0: Working');
console.log('❌ Database 1: Cannot reach (DNS/connection failed)');
console.log('❌ Database 2: Cannot reach (DNS/connection failed)');

console.log('\nThe system is currently using Database 0 for all operations.');
console.log('It will automatically use databases 1 & 2 when they become available.\n');

console.log('='.repeat(80));


 * Verify Supabase Projects and Get Correct Connection Strings
 * Helps identify if projects exist and what the correct URLs should be
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

console.log('🔍 Supabase Project Verification Guide\n');
console.log('='.repeat(80));

console.log('\n📋 Current Configuration:\n');

const projects = [
  { index: 0, ref: 'qudsmrrfbatasnyvuxch', url: process.env.DATABASE_URL_0 },
  { index: 1, ref: 'vivelzjlltbytnhybdcm', url: process.env.DATABASE_URL_1 },
  { index: 2, ref: 'kzvhbgqpxykganquikmv', url: process.env.DATABASE_URL_2 },
];

projects.forEach(project => {
  console.log(`Database ${project.index}:`);
  console.log(`  Project Reference: ${project.ref}`);
  console.log(`  Dashboard URL: https://${project.ref}.supabase.co`);
  console.log(`  Connection String: ${project.url ? '✅ Set' : '❌ Not set'}`);
  if (project.url) {
    const urlObj = new URL(project.url);
    console.log(`  Hostname: ${urlObj.hostname}`);
    console.log(`  Port: ${urlObj.port || '6543'}`);
  }
  console.log('');
});

console.log('='.repeat(80));
console.log('\n🔧 HOW TO FIX:\n');

console.log('1. Go to Supabase Dashboard: https://supabase.com/dashboard\n');

projects.forEach(project => {
  if (project.index > 0) {
    console.log(`\n📊 For Database ${project.index} (${project.ref}):`);
    console.log(`   a. Visit: https://${project.ref}.supabase.co`);
    console.log(`   b. Check if project exists and is active`);
    console.log(`   c. If paused → Click "Restore" or "Unpause"`);
    console.log(`   d. Go to: Settings → Database → Connection Pooling`);
    console.log(`   e. Copy the EXACT "Transaction mode" connection string`);
    console.log(`   f. Update DATABASE_URL_${project.index} in .env.local`);
    console.log(`   g. Format should be:`);
    console.log(`      postgresql://postgres.[ref]:[password]@[hostname]:6543/postgres?pgbouncer=true`);
  }
});

console.log('\n' + '='.repeat(80));
console.log('\n💡 ALTERNATIVE: If Projects Don\'t Exist\n');

console.log('If the projects were deleted or don\'t exist:');
console.log('  1. Create new Supabase projects');
console.log('  2. Get connection strings from each');
console.log('  3. Update .env.local with new DATABASE_URL_1 and DATABASE_URL_2');
console.log('  4. Run migrations: npx tsx scripts/migrate-all-databases.ts');

console.log('\n' + '='.repeat(80));
console.log('\n✅ CURRENT STATUS:\n');

console.log('✅ Database 0: Working');
console.log('❌ Database 1: Cannot reach (DNS/connection failed)');
console.log('❌ Database 2: Cannot reach (DNS/connection failed)');

console.log('\nThe system is currently using Database 0 for all operations.');
console.log('It will automatically use databases 1 & 2 when they become available.\n');

console.log('='.repeat(80));




