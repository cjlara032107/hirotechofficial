#!/usr/bin/env tsx
/**
 * Mark migration as applied for Database 0 (columns already exist)
 */

import { execSync } from 'child_process';
import * as dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });
dotenv.config();

const directUrl = process.env.DIRECT_URL_0 || process.env.DATABASE_URL_0?.replace(':6543', ':5432').replace('pooler.', 'db.').replace('?pgbouncer=true', '');

if (!directUrl) {
  console.error('❌ DIRECT_URL_0 not found');
  process.exit(1);
}

console.log('🔧 Marking migration as applied for Database 0 (columns already exist)...\n');

process.env.DATABASE_URL = directUrl;
process.env.DIRECT_URL = directUrl;

try {
  execSync('npx prisma migrate resolve --applied 20250102000000_add_advanced_ai_features', {
    stdio: 'inherit',
    env: process.env,
  });
  console.log('\n✅ Migration marked as applied!');
  console.log('💡 You can now run: npx tsx scripts/migrate-all-databases.ts');
} catch (error) {
  console.error('❌ Failed:', error);
  process.exit(1);
}




