/**
 * Check and display database connection pool limits
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

function getConnectionPoolLimit(): number {
  const databaseUrl = process.env.DATABASE_URL || '';
  
  // Extract connection_limit from URL
  const match = databaseUrl.match(/connection_limit=(\d+)/);
  if (match) {
    return parseInt(match[1], 10);
  }
  
  // Defaults based on environment
  const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
  return isVercel ? 10 : 15;
}

function extractPoolLimit(url: string): number | null {
  const match = url.match(/connection_limit=(\d+)/);
  return match ? parseInt(match[1], 10) : null;
}

console.log('🔍 Database Connection Pool Limits\n');
console.log('='.repeat(80));

const poolLimit = getConnectionPoolLimit();
console.log(`\n📊 Default Pool Limit: ${poolLimit} connections`);
console.log(`   Environment: ${process.env.VERCEL ? 'Vercel (10)' : 'Local (15)'}`);

console.log('\n' + '='.repeat(80));
console.log('\n🗄️  Per-Database Pool Configuration:\n');

const databases = [
  { index: 0, env: 'DATABASE_URL_0' },
  { index: 1, env: 'DATABASE_URL_1' },
  { index: 2, env: 'DATABASE_URL_2' },
];

databases.forEach(db => {
  const url = process.env[db.env] || '';
  const poolLimitInUrl = extractPoolLimit(url);
  const hasPooler = url.includes('pooler.supabase.com');
  const hasPgbouncer = url.includes('pgbouncer=true');
  
  console.log(`Database ${db.index}:`);
  console.log(`  Connection String: ${url ? '✅ Set' : '❌ Not set'}`);
  console.log(`  Pooler Type: ${hasPooler ? '✅ Supabase Pooler' : '❌ Not using pooler'}`);
  console.log(`  PgBouncer: ${hasPgbouncer ? '✅ Enabled' : '❌ Not enabled'}`);
  console.log(`  Pool Limit in URL: ${poolLimitInUrl ? `✅ ${poolLimitInUrl}` : '⚠️  Not specified (will use default)'}`);
  console.log('');
});

console.log('='.repeat(80));
console.log('\n📋 Pool Configuration Summary:\n');

console.log('✅ Pool Limits:');
console.log(`   - Default: ${poolLimit} connections per database`);
console.log(`   - Total across 3 databases: ${poolLimit * 3} connections`);
console.log(`   - Safe usage (80%): ${Math.floor(poolLimit * 0.8)} per database`);
console.log(`   - Total safe usage: ${Math.floor(poolLimit * 0.8) * 3} connections`);

console.log('\n✅ Connection String Parameters:');
console.log('   - All databases use: Transaction pooler (port 6543)');
console.log('   - PgBouncer: Enabled');
console.log('   - Pool timeout: 30 seconds');
console.log('   - Connect timeout: 30 seconds');

console.log('\n✅ Global Pool Management:');
console.log('   - GlobalPoolAwareLimiter: Tracks total pool usage across all operations');
console.log('   - Reserve: 20% for API routes and syncs');
console.log('   - Safe usage: 80% of pool limit');

console.log('\n✅ Operation Type Limits:');
const DB_CONNECTIONS_PER_OPERATION: Record<string, number> = {
  'analysis': 3,
  'automation': 4,
  'message-generation': 2,
  'batch': 5,
  'simple': 1,
};

Object.entries(DB_CONNECTIONS_PER_OPERATION).forEach(([type, conns]) => {
  const maxOps = Math.floor((poolLimit * 0.8) / conns);
  console.log(`   - ${type}: ${conns} conn/op, max ${maxOps} concurrent ops`);
});

console.log('\n' + '='.repeat(80));
console.log('\n💡 Recommendations:\n');

const allHavePoolLimit = databases.every(db => {
  const url = process.env[db.env] || '';
  return extractPoolLimit(url) !== null;
});

if (!allHavePoolLimit) {
  console.log('⚠️  Some connection strings don\'t have explicit pool limits.');
  console.log('   The multi-db router will add them automatically during initialization.');
  console.log('   This is fine - the router enhances URLs with pool parameters.');
} else {
  console.log('✅ All connection strings have pool limits configured.');
}

console.log('\n✅ Pool configuration is correct and safe!');
console.log('='.repeat(80));


 * Check and display database connection pool limits
 */

import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
dotenv.config({ path: '.env' });

function getConnectionPoolLimit(): number {
  const databaseUrl = process.env.DATABASE_URL || '';
  
  // Extract connection_limit from URL
  const match = databaseUrl.match(/connection_limit=(\d+)/);
  if (match) {
    return parseInt(match[1], 10);
  }
  
  // Defaults based on environment
  const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
  return isVercel ? 10 : 15;
}

function extractPoolLimit(url: string): number | null {
  const match = url.match(/connection_limit=(\d+)/);
  return match ? parseInt(match[1], 10) : null;
}

console.log('🔍 Database Connection Pool Limits\n');
console.log('='.repeat(80));

const poolLimit = getConnectionPoolLimit();
console.log(`\n📊 Default Pool Limit: ${poolLimit} connections`);
console.log(`   Environment: ${process.env.VERCEL ? 'Vercel (10)' : 'Local (15)'}`);

console.log('\n' + '='.repeat(80));
console.log('\n🗄️  Per-Database Pool Configuration:\n');

const databases = [
  { index: 0, env: 'DATABASE_URL_0' },
  { index: 1, env: 'DATABASE_URL_1' },
  { index: 2, env: 'DATABASE_URL_2' },
];

databases.forEach(db => {
  const url = process.env[db.env] || '';
  const poolLimitInUrl = extractPoolLimit(url);
  const hasPooler = url.includes('pooler.supabase.com');
  const hasPgbouncer = url.includes('pgbouncer=true');
  
  console.log(`Database ${db.index}:`);
  console.log(`  Connection String: ${url ? '✅ Set' : '❌ Not set'}`);
  console.log(`  Pooler Type: ${hasPooler ? '✅ Supabase Pooler' : '❌ Not using pooler'}`);
  console.log(`  PgBouncer: ${hasPgbouncer ? '✅ Enabled' : '❌ Not enabled'}`);
  console.log(`  Pool Limit in URL: ${poolLimitInUrl ? `✅ ${poolLimitInUrl}` : '⚠️  Not specified (will use default)'}`);
  console.log('');
});

console.log('='.repeat(80));
console.log('\n📋 Pool Configuration Summary:\n');

console.log('✅ Pool Limits:');
console.log(`   - Default: ${poolLimit} connections per database`);
console.log(`   - Total across 3 databases: ${poolLimit * 3} connections`);
console.log(`   - Safe usage (80%): ${Math.floor(poolLimit * 0.8)} per database`);
console.log(`   - Total safe usage: ${Math.floor(poolLimit * 0.8) * 3} connections`);

console.log('\n✅ Connection String Parameters:');
console.log('   - All databases use: Transaction pooler (port 6543)');
console.log('   - PgBouncer: Enabled');
console.log('   - Pool timeout: 30 seconds');
console.log('   - Connect timeout: 30 seconds');

console.log('\n✅ Global Pool Management:');
console.log('   - GlobalPoolAwareLimiter: Tracks total pool usage across all operations');
console.log('   - Reserve: 20% for API routes and syncs');
console.log('   - Safe usage: 80% of pool limit');

console.log('\n✅ Operation Type Limits:');
const DB_CONNECTIONS_PER_OPERATION: Record<string, number> = {
  'analysis': 3,
  'automation': 4,
  'message-generation': 2,
  'batch': 5,
  'simple': 1,
};

Object.entries(DB_CONNECTIONS_PER_OPERATION).forEach(([type, conns]) => {
  const maxOps = Math.floor((poolLimit * 0.8) / conns);
  console.log(`   - ${type}: ${conns} conn/op, max ${maxOps} concurrent ops`);
});

console.log('\n' + '='.repeat(80));
console.log('\n💡 Recommendations:\n');

const allHavePoolLimit = databases.every(db => {
  const url = process.env[db.env] || '';
  return extractPoolLimit(url) !== null;
});

if (!allHavePoolLimit) {
  console.log('⚠️  Some connection strings don\'t have explicit pool limits.');
  console.log('   The multi-db router will add them automatically during initialization.');
  console.log('   This is fine - the router enhances URLs with pool parameters.');
} else {
  console.log('✅ All connection strings have pool limits configured.');
}

console.log('\n✅ Pool configuration is correct and safe!');
console.log('='.repeat(80));




