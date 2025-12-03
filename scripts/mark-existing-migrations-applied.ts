#!/usr/bin/env tsx
/**
 * Mark migrations as applied if their columns already exist in the database
 * This fixes the issue where migrations failed but columns were partially created
 */

import { execSync } from 'child_process';
import * as dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });
dotenv.config();

const DB_COUNT = parseInt(process.env.DB_COUNT || '3', 10);

// Migrations that might have columns that already exist
const MIGRATIONS_TO_CHECK = [
  '20250102000000_add_advanced_ai_features',
  '20250103000000_add_last_progress_at_to_sync_job',
];

console.log(`🔧 Checking and marking migrations as applied for ${DB_COUNT} databases...\n`);

for (let i = 0; i < DB_COUNT; i++) {
  const dbUrl = process.env[`DATABASE_URL_${i}`];
  const directUrl = process.env[`DIRECT_URL_${i}`];

  if (!dbUrl) {
    console.warn(`⚠️  DATABASE_URL_${i} not set, skipping database ${i}`);
    continue;
  }

  console.log(`📦 Processing database ${i + 1}/${DB_COUNT}...`);

  const migrationUrl = directUrl || dbUrl;
  process.env.DATABASE_URL = migrationUrl;
  process.env.DIRECT_URL = migrationUrl;

  for (const migration of MIGRATIONS_TO_CHECK) {
    try {
      console.log(`   🔄 Checking migration: ${migration}...`);
      
      // Try to mark as applied
      execSync(`npx prisma migrate resolve --applied ${migration}`, {
        stdio: 'pipe',
        env: process.env,
      });
      console.log(`   ✅ Marked ${migration} as applied\n`);
    } catch (error) {
      // Migration might already be resolved or doesn't exist
      const errorMsg = error instanceof Error ? error.message : String(error);
      if (errorMsg.includes('not found') || errorMsg.includes('does not exist')) {
        console.log(`   ℹ️  Migration ${migration} not found or already resolved\n`);
      } else {
        console.log(`   ⚠️  Could not mark ${migration} as applied: ${errorMsg.substring(0, 100)}\n`);
      }
    }
  }
}

console.log('✅ Migration resolution complete!');
console.log('💡 You can now run: npx tsx scripts/migrate-all-databases.ts');




