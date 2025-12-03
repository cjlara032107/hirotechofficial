/**
 * Verify Database Connection Pool Settings
 * 
 * This script verifies:
 * 1. Database connection pool configuration
 * 2. Connection limits
 * 3. Timeout settings
 * 4. Pool health and performance
 */

import { PrismaClient } from '@prisma/client';
import { prisma } from '../src/lib/db';

interface TestResult {
  name: string;
  status: 'pass' | 'fail' | 'warning';
  message: string;
  details?: string;
}

const results: TestResult[] = [];

function addResult(name: string, status: 'pass' | 'fail' | 'warning', message: string, details?: string) {
  results.push({ name, status, message, details });
  const icon = status === 'pass' ? '✅' : status === 'fail' ? '❌' : '⚠️';
  console.log(`${icon} ${name}: ${message}`);
  if (details) {
    console.log(`   ${details}`);
  }
}

async function verifyDatabasePoolSettings() {
  console.log('\n🔍 Verifying Database Connection Pool Settings...\n');

  // Check DATABASE_URL configuration
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    addResult(
      'Database Configuration',
      'fail',
      'DATABASE_URL not configured',
      'Set DATABASE_URL in your .env file'
    );
    return;
  }

  // Parse connection pool parameters from URL
  const urlParams = new URLSearchParams(databaseUrl.split('?')[1] || '');
  const connectionLimit = urlParams.get('connection_limit');
  const poolTimeout = urlParams.get('pool_timeout');
  const connectTimeout = urlParams.get('connect_timeout');
  const pgbouncer = urlParams.get('pgbouncer');

  addResult(
    'Database URL Configuration',
    'pass',
    'DATABASE_URL is configured',
    `Using ${pgbouncer === 'true' ? 'PgBouncer pooler' : 'direct connection'}`
  );

  // Verify connection pool settings
  console.log('\n📊 Connection Pool Settings:\n');

  if (connectionLimit) {
    const limit = parseInt(connectionLimit, 10);
    if (limit >= 5 && limit <= 50) {
      addResult(
        'Connection Limit',
        'pass',
        `Connection limit: ${limit}`,
        limit >= 10
          ? 'Good for serverless environments'
          : 'Consider increasing for high concurrency'
      );
    } else if (limit < 5) {
      addResult(
        'Connection Limit',
        'warning',
        `Connection limit is low: ${limit}`,
        'May cause pool exhaustion under high load. Consider increasing to 10-20.'
      );
    } else {
      addResult(
        'Connection Limit',
        'warning',
        `Connection limit is high: ${limit}`,
        'May exceed database server limits. Verify with your database provider.'
      );
    }
  } else {
    addResult(
      'Connection Limit',
      'warning',
      'Connection limit not specified in URL',
      'Using default Prisma connection limit. Consider adding connection_limit parameter.'
    );
  }

  if (poolTimeout) {
    const timeout = parseInt(poolTimeout, 10);
    if (timeout >= 10 && timeout <= 60) {
      addResult(
        'Pool Timeout',
        'pass',
        `Pool timeout: ${timeout}s`,
        'Reasonable timeout for acquiring connections'
      );
    } else if (timeout > 60) {
      addResult(
        'Pool Timeout',
        'warning',
        `Pool timeout is high: ${timeout}s`,
        'Long timeouts may indicate connection pool exhaustion. Consider investigating.'
      );
    } else {
      addResult(
        'Pool Timeout',
        'warning',
        `Pool timeout is low: ${timeout}s`,
        'May cause premature timeouts under load. Consider increasing to 30-60s.'
      );
    }
  } else {
    addResult(
      'Pool Timeout',
      'warning',
      'Pool timeout not specified',
      'Using default timeout. Consider adding pool_timeout parameter (30-60s recommended).'
    );
  }

  if (connectTimeout) {
    const timeout = parseInt(connectTimeout, 10);
    if (timeout >= 10 && timeout <= 30) {
      addResult(
        'Connect Timeout',
        'pass',
        `Connect timeout: ${timeout}s`,
        'Reasonable timeout for initial connection'
      );
    } else if (timeout > 30) {
      addResult(
        'Connect Timeout',
        'warning',
        `Connect timeout is high: ${timeout}s`,
        'May indicate network issues. Consider investigating.'
      );
    } else {
      addResult(
        'Connect Timeout',
        'warning',
        `Connect timeout is low: ${timeout}s`,
        'May cause connection failures on slow networks. Consider increasing to 20-30s.'
      );
    }
  } else {
    addResult(
      'Connect Timeout',
      'warning',
      'Connect timeout not specified',
      'Using default timeout. Consider adding connect_timeout parameter (20-30s recommended).'
    );
  }

  // Test database connection
  console.log('\n🔌 Testing Database Connection...\n');

  try {
    await prisma.$connect();
    addResult(
      'Database Connection',
      'pass',
      'Successfully connected to database',
      'Connection pool is accessible'
    );
  } catch (error) {
    const err = error as Error;
    addResult(
      'Database Connection',
      'fail',
      'Failed to connect to database',
      err.message
    );
    return;
  }

  // Test connection pool with concurrent queries
  console.log('\n📊 Testing Connection Pool Performance...\n');

  const concurrencyTests = [1, 5, 10];
  let maxConcurrency = 0;

  for (const concurrency of concurrencyTests) {
    try {
      const startTime = Date.now();
      const promises = Array.from({ length: concurrency }, () =>
        prisma.$queryRaw`SELECT 1 as test`
      );
      await Promise.all(promises);
      const duration = Date.now() - startTime;

      if (duration < 5000) {
        maxConcurrency = concurrency;
        addResult(
          `Concurrent Queries Test (${concurrency} queries)`,
          'pass',
          `Completed in ${duration}ms`,
          `All ${concurrency} queries executed successfully`
        );
      } else {
        addResult(
          `Concurrent Queries Test (${concurrency} queries)`,
          'warning',
          `Took ${duration}ms (may be slow)`,
          'Consider checking database performance or connection pool size'
        );
        break;
      }
    } catch (error) {
      const err = error as Error;
      if (err.message.includes('P2024') || err.message.includes('pool')) {
        addResult(
          `Concurrent Queries Test (${concurrency} queries)`,
          'fail',
          'Connection pool exhausted',
          `Error: ${err.message}. Consider increasing connection_limit.`
        );
        break;
      } else {
        addResult(
          `Concurrent Queries Test (${concurrency} queries)`,
          'fail',
          'Query execution failed',
          err.message
        );
        break;
      }
    }
  }

  addResult(
    'Connection Pool Performance',
    maxConcurrency >= 5 ? 'pass' : 'warning',
    `Successfully handled ${maxConcurrency} concurrent queries`,
    maxConcurrency >= 5
      ? 'Connection pool can handle concurrent operations'
      : 'Consider increasing connection_limit or investigating database performance'
  );

  // Test connection pool exhaustion scenario
  console.log('\n🔍 Testing Connection Pool Limits...\n');

  const connectionLimit = connectionLimit ? parseInt(connectionLimit, 10) : 10;
  const testLimit = Math.min(connectionLimit + 2, 15); // Test slightly above limit

  try {
    const startTime = Date.now();
    const promises = Array.from({ length: testLimit }, () =>
      prisma.$queryRaw`SELECT 1 as test`
    );
    await Promise.all(promises);
    const duration = Date.now() - startTime;

    addResult(
      'Connection Pool Limit Test',
      'pass',
      `Handled ${testLimit} concurrent queries in ${duration}ms`,
      'Connection pool is working within limits'
    );
  } catch (error) {
    const err = error as Error;
    if (err.message.includes('P2024') || err.message.includes('pool')) {
      addResult(
        'Connection Pool Limit Test',
        'warning',
        'Connection pool exhausted under load',
        `Error: ${err.message}. This is expected when exceeding limits. Consider increasing connection_limit if this happens frequently.`
      );
    } else {
      addResult(
        'Connection Pool Limit Test',
        'fail',
        'Unexpected error during limit test',
        err.message
      );
    }
  }

  // Cleanup
  await prisma.$disconnect();
}

async function main() {
  console.log('🚀 Database Connection Pool Verification\n');
  console.log('='.repeat(60));

  await verifyDatabasePoolSettings();

  console.log('\n' + '='.repeat(60));
  console.log('\n📊 Verification Summary:\n');

  const passed = results.filter(r => r.status === 'pass').length;
  const failed = results.filter(r => r.status === 'fail').length;
  const warnings = results.filter(r => r.status === 'warning').length;

  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`⚠️  Warnings: ${warnings}`);

  if (failed > 0) {
    console.log('\n❌ Some verifications failed. Please review the errors above.');
    process.exit(1);
  } else if (warnings > 0) {
    console.log('\n⚠️  Some verifications have warnings. Review recommendations above.');
    process.exit(0);
  } else {
    console.log('\n✅ All verifications passed!');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Verification script error:', error);
  process.exit(1);
});









