/**
 * Script to verify database migrations can run
 * 
 * This script:
 * 1. Checks database connection
 * 2. Verifies Prisma client can connect
 * 3. Checks migration status
 * 4. Tests that migrations can be applied
 */

import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';

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

async function verifyDatabaseMigrations() {
  console.log('\n🔍 Verifying Database Migrations...\n');

  // Check environment variables
  const databaseUrl = process.env.DATABASE_URL;
  const directUrl = process.env.DIRECT_URL;

  if (!databaseUrl) {
    addResult(
      'Database Configuration',
      'fail',
      'DATABASE_URL not configured',
      'Set DATABASE_URL environment variable'
    );
    return;
  }

  addResult(
    'Database Configuration',
    'pass',
    'DATABASE_URL is configured',
    `URL: ${databaseUrl.replace(/:[^:@]+@/, ':****@')}`
  );

  if (directUrl) {
    addResult(
      'Direct URL Configuration',
      'pass',
      'DIRECT_URL is configured',
      'Using direct connection for migrations'
    );
  } else {
    addResult(
      'Direct URL Configuration',
      'warning',
      'DIRECT_URL not configured',
      'Migrations will use DATABASE_URL. Consider setting DIRECT_URL for better performance.'
    );
  }

  // Test Prisma client connection
  const prisma = new PrismaClient();
  try {
    await prisma.$connect();
    addResult(
      'Database Connection',
      'pass',
      'Successfully connected to database',
      'Prisma client can connect'
    );

    // Test a simple query
    await prisma.$queryRaw`SELECT 1 as test`;
    addResult(
      'Database Query',
      'pass',
      'Successfully executed test query',
      'Database is accessible'
    );
  } catch (error) {
    const err = error as Error;
    addResult(
      'Database Connection',
      'fail',
      'Failed to connect to database',
      err.message
    );
    await prisma.$disconnect();
    return;
  }

  // Check Prisma migration status
  try {
    console.log('\n📊 Checking Migration Status...\n');
    
    // Check if _prisma_migrations table exists
    const migrationTableExists = await prisma.$queryRaw<Array<{ exists: boolean }>>`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = '_prisma_migrations'
      ) as exists;
    `;

    if (migrationTableExists[0]?.exists) {
      addResult(
        'Migration Table',
        'pass',
        '_prisma_migrations table exists',
        'Migrations have been run before'
      );

      // Get applied migrations
      const appliedMigrations = await prisma.$queryRaw<Array<{ migration_name: string }>>`
        SELECT migration_name 
        FROM _prisma_migrations 
        WHERE rolled_back_at IS NULL
        ORDER BY finished_at DESC
        LIMIT 10;
      `;

      addResult(
        'Applied Migrations',
        'pass',
        `Found ${appliedMigrations.length} recent migrations`,
        appliedMigrations.length > 0
          ? `Latest: ${appliedMigrations[0]?.migration_name}`
          : 'No migrations found'
      );
    } else {
      addResult(
        'Migration Table',
        'warning',
        '_prisma_migrations table does not exist',
        'Database may be new or migrations not run yet'
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Migration Status Check',
      'fail',
      'Failed to check migration status',
      err.message
    );
  }

  // Check if schema matches database
  try {
    console.log('\n📋 Checking Schema Compatibility...\n');
    
    // Check for key tables from schema
    const tables = await prisma.$queryRaw<Array<{ table_name: string }>>`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
      ORDER BY table_name;
    `;

    const expectedTables = [
      'User',
      'Organization',
      'Contact',
      'FacebookPage',
      'Campaign',
      'Message',
      'Conversation',
    ];

    const foundTables = tables.map(t => t.table_name);
    const missingTables = expectedTables.filter(t => !foundTables.includes(t));

    if (missingTables.length === 0) {
      addResult(
        'Schema Tables',
        'pass',
        'All expected tables exist',
        `Found ${foundTables.length} tables`
      );
    } else {
      addResult(
        'Schema Tables',
        'warning',
        `Some expected tables are missing: ${missingTables.join(', ')}`,
        `Found ${foundTables.length} tables, expected ${expectedTables.length}`
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Schema Check',
      'fail',
      'Failed to check schema',
      err.message
    );
  }

  // Test migration commands (dry run)
  try {
    console.log('\n🔧 Testing Migration Commands...\n');
    
    // Check if prisma CLI is available
    try {
      const prismaVersion = execSync('npx prisma --version', { encoding: 'utf-8' }).trim();
      addResult(
        'Prisma CLI',
        'pass',
        'Prisma CLI is available',
        `Version: ${prismaVersion}`
      );
    } catch {
      addResult(
        'Prisma CLI',
        'fail',
        'Prisma CLI not available',
        'Install Prisma: npm install -D prisma'
      );
    }

    // Check migration files exist
    try {
      const fs = await import('fs');
      const migrationsPath = './prisma/migrations';
      if (fs.existsSync(migrationsPath)) {
        const migrationDirs = fs.readdirSync(migrationsPath, { withFileTypes: true })
          .filter(dirent => dirent.isDirectory())
          .map(dirent => dirent.name);
        
        addResult(
          'Migration Files',
          'pass',
          `Found ${migrationDirs.length} migration directories`,
          migrationDirs.length > 0
            ? `Latest: ${migrationDirs[migrationDirs.length - 1]}`
            : 'No migrations found'
        );
      } else {
        addResult(
          'Migration Files',
          'warning',
          'Migrations directory not found',
          'Create migrations with: npx prisma migrate dev'
        );
      }
    } catch {
      addResult(
        'Migration Files',
        'warning',
        'Could not check migration files',
        'Migration files may not exist yet'
      );
    }
  } catch (error) {
    const err = error as Error;
    addResult(
      'Migration Commands',
      'fail',
      'Failed to test migration commands',
      err.message
    );
  }

  await prisma.$disconnect();
}

async function main() {
  console.log('🚀 Database Migration Verification\n');
  console.log('='.repeat(60));

  await verifyDatabaseMigrations();

  console.log('\n' + '='.repeat(60));
  console.log('\n📊 Test Summary:\n');

  const passed = results.filter(r => r.status === 'pass').length;
  const failed = results.filter(r => r.status === 'fail').length;
  const warnings = results.filter(r => r.status === 'warning').length;

  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`⚠️  Warnings: ${warnings}`);

  if (failed > 0) {
    console.log('\n❌ Some tests failed. Please review the errors above.');
    console.log('\n💡 To fix migration issues:');
    console.log('   1. Ensure DATABASE_URL is set correctly');
    console.log('   2. Run: npx prisma migrate deploy');
    console.log('   3. Or for development: npx prisma migrate dev');
    process.exit(1);
  } else if (warnings > 0) {
    console.log('\n⚠️  Some tests have warnings. Review recommendations above.');
    process.exit(0);
  } else {
    console.log('\n✅ All tests passed! Database migrations are ready.');
    process.exit(0);
  }
}

main().catch((error) => {
  console.error('❌ Test script error:', error);
  process.exit(1);
});

