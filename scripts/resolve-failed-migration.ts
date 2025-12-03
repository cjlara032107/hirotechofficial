#!/usr/bin/env tsx
/**
 * Resolve failed migration for all databases
 * Usage: npx tsx scripts/resolve-failed-migration.ts
 */

import { execSync } from 'child_process';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config({ path: '.env.local' });
dotenv.config();

const DB_COUNT = parseInt(process.env.DB_COUNT || '3', 10);
const FAILED_MIGRATION = '20250102000000_add_advanced_ai_features';

console.log(`🔧 Resolving failed migration "${FAILED_MIGRATION}" on ${DB_COUNT} databases...\n`);

for (let i = 0; i < DB_COUNT; i++) {
  const dbUrl = process.env[`DATABASE_URL_${i}`];
  const directUrl = process.env[`DIRECT_URL_${i}`];

  if (!dbUrl) {
    console.warn(`⚠️  DATABASE_URL_${i} not set, skipping database ${i}`);
    continue;
  }

  console.log(`📦 Resolving migration for database ${i + 1}/${DB_COUNT}...`);

  try {
    // Use direct URL for migrations (not pooled)
    const migrationUrl = directUrl || dbUrl.replace(':6543', ':5432').replace('pooler.', 'db.').replace('?pgbouncer=true', '');
    
    process.env.DATABASE_URL = migrationUrl;
    process.env.DIRECT_URL = migrationUrl; // Prisma schema requires this

    // First, try to mark as rolled back (safest option)
    try {
      console.log(`   🔄 Attempting to mark as rolled back...`);
      execSync(`npx prisma migrate resolve --rolled-back ${FAILED_MIGRATION}`, {
        stdio: 'inherit',
        env: process.env,
      });
      console.log(`   ✅ Migration marked as rolled back\n`);
    } catch (rollbackError) {
      // If rollback fails, try marking as applied (in case columns already exist)
      console.log(`   🔄 Rollback failed, trying to mark as applied...`);
      try {
        execSync(`npx prisma migrate resolve --applied ${FAILED_MIGRATION}`, {
          stdio: 'inherit',
          env: process.env,
        });
        console.log(`   ✅ Migration marked as applied\n`);
      } catch (applyError) {
        console.error(`   ❌ Could not resolve migration automatically`);
        console.error(`   💡 You may need to check the database manually`);
        console.error(`   Error: ${applyError instanceof Error ? applyError.message : String(applyError)}\n`);
      }
    }
  } catch (error) {
    console.error(`❌ Failed to resolve migration for database ${i + 1}:`, error);
  }
}

console.log('✅ Migration resolution complete!');
console.log('💡 You can now run: npx tsx scripts/migrate-all-databases.ts');

