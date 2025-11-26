/**
 * Production Migration Script
 * Adds contactInfo and bestContactTimes columns to Contact table
 * 
 * Usage:
 *   node -r dotenv/config apply-production-migration.js
 * 
 * Or with explicit env file:
 *   node -r dotenv/config -e "require('dotenv').config({ path: '.env.production' }); require('./apply-production-migration.js')"
 */

require('dotenv').config({ path: '.env.local' });

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function applyMigration() {
  console.log('🚀 Starting production migration...');
  console.log('📋 Adding contactInfo and bestContactTimes columns to Contact table\n');

  try {
    // Add contactInfo column
    console.log('1. Adding contactInfo column...');
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "Contact" 
      ADD COLUMN IF NOT EXISTS "contactInfo" JSONB;
    `);
    console.log('   ✅ contactInfo column added\n');

    // Add bestContactTimes column
    console.log('2. Adding bestContactTimes column...');
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "Contact" 
      ADD COLUMN IF NOT EXISTS "bestContactTimes" JSONB;
    `);
    console.log('   ✅ bestContactTimes column added\n');

    // Verify columns exist
    console.log('3. Verifying columns...');
    const result = await prisma.$queryRawUnsafe(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'Contact' 
      AND column_name IN ('contactInfo', 'bestContactTimes');
    `);
    
    console.log('   Columns found:');
    result.forEach((row: any) => {
      console.log(`   - ${row.column_name} (${row.data_type})`);
    });

    console.log('\n✅ Migration completed successfully!');
    console.log('🎉 Your production database is now ready for enhanced contact analysis features.');

  } catch (error) {
    console.error('\n❌ Migration failed:');
    console.error(error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

applyMigration();


