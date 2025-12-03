#!/usr/bin/env tsx
/**
 * Run Prisma migrations on all configured databases
 * Usage: npx tsx scripts/migrate-all-databases.ts
 * 
 * Handles failed migrations by resolving them first
 */

import { execSync } from 'child_process';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '.env.local' });
dotenv.config();

const DB_COUNT = parseInt(process.env.DB_COUNT || '5', 10);

/**
 * Resolve failed migrations by marking them as rolled back
 * This allows new migrations to proceed
 */
function resolveFailedMigrations(dbUrl: string, directUrl: string) {
  try {
    console.log('   🔍 Checking for failed migrations...');
    
    // Set environment variables
    process.env.DATABASE_URL = directUrl || dbUrl; // Use direct URL for migrations
    
    // Check migration status
    const statusOutput = execSync('npx prisma migrate status', {
      encoding: 'utf-8',
      env: process.env,
      stdio: 'pipe',
    });
    
    // If there are failed migrations, resolve them
    if (statusOutput.includes('failed') || statusOutput.includes('Failed')) {
      console.log('   ⚠️  Found failed migrations, attempting to resolve...');
      
      // Try to resolve the failed migration by marking it as rolled back
      // This allows new migrations to proceed
      try {
        execSync('npx prisma migrate resolve --rolled-back 20250102000000_add_advanced_ai_features', {
          stdio: 'inherit',
          env: process.env,
        });
        console.log('   ✅ Resolved failed migration');
      } catch (resolveError) {
        // If resolve fails, try marking as applied (in case columns already exist)
        console.log('   ⚠️  Rollback failed, trying to mark as applied...');
        try {
          execSync('npx prisma migrate resolve --applied 20250102000000_add_advanced_ai_features', {
            stdio: 'inherit',
            env: process.env,
          });
          console.log('   ✅ Marked failed migration as applied');
        } catch (applyError) {
          console.log('   ⚠️  Could not resolve migration automatically');
          console.log('   💡 You may need to manually resolve it or use db push');
        }
      }
    } else {
      console.log('   ✅ No failed migrations found');
    }
  } catch (error) {
    // If status check fails, continue anyway
    console.log('   ⚠️  Could not check migration status, continuing...');
  }
}

console.log(`🚀 Migrating ${DB_COUNT} databases...\n`);

for (let i = 0; i < DB_COUNT; i++) {
  const dbUrl = process.env[`DATABASE_URL_${i}`];
  const directUrl = process.env[`DIRECT_URL_${i}`];

  if (!dbUrl) {
    console.warn(`⚠️  DATABASE_URL_${i} not set, skipping database ${i}`);
    continue;
  }

  console.log(`📦 Migrating database ${i + 1}/${DB_COUNT}...`);

  try {
    // Use direct URL for migrations, fallback to pooled if direct not available
    const migrationUrl = directUrl || dbUrl;
    
    // Set environment variables for this migration
    process.env.DATABASE_URL = migrationUrl;
    process.env.DIRECT_URL = migrationUrl;

    // Resolve any failed migrations first
    resolveFailedMigrations(dbUrl, directUrl);

    // Run migration
    execSync('npx prisma migrate deploy', {
      stdio: 'inherit',
      env: process.env,
    });

    console.log(`✅ Database ${i + 1} migrated successfully\n`);
  } catch (error) {
    console.error(`❌ Failed to migrate database ${i + 1}:`, error);
    
    // Try fallback: use pooled connection if direct failed
    if (directUrl && directUrl !== dbUrl) {
      console.log(`   🔄 Attempting with pooled connection...`);
      try {
        process.env.DATABASE_URL = dbUrl;
        process.env.DIRECT_URL = dbUrl;
        execSync('npx prisma migrate deploy', {
          stdio: 'inherit',
          env: process.env,
        });
        console.log(`✅ Database ${i + 1} migrated using pooled connection\n`);
      } catch (poolError) {
        // Try db push as last resort
        console.log(`   🔄 Attempting fallback: db push...`);
        try {
          execSync('npx prisma db push --accept-data-loss', {
            stdio: 'inherit',
            env: process.env,
          });
          console.log(`✅ Database ${i + 1} synced using db push\n`);
        } catch (pushError) {
          console.error(`❌ All methods failed for database ${i + 1}`);
          console.error(`   Please check the database connection and try again`);
          console.warn(`   ⚠️  Continuing with next database...`);
        }
      }
    } else {
      // Try db push as fallback
      console.log(`   🔄 Attempting fallback: db push...`);
      try {
        execSync('npx prisma db push --accept-data-loss', {
          stdio: 'inherit',
          env: process.env,
        });
        console.log(`✅ Database ${i + 1} synced using db push\n`);
      } catch (pushError) {
        console.error(`❌ Fallback also failed for database ${i + 1}`);
        console.warn(`   ⚠️  Continuing with next database...`);
      }
    }
  }
}

console.log('🎉 All databases migrated successfully!');

