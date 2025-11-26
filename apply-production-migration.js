/**
 * Production Migration Script
 * Adds contactInfo and bestContactTimes columns to Contact table
 * 
 * Usage: node apply-production-migration.js
 */

// Load environment variables
require('dotenv').config({ path: '.env.local' });
require('dotenv').config({ path: '.env' });

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function applyMigration() {
  console.log('========================================');
  console.log('Production Database Migration');
  console.log('========================================');
  console.log('');
  console.log('Adding contactInfo and bestContactTimes columns...');
  console.log('');

  try {
    // Connect to database
    await prisma.$connect();
    console.log('✅ Connected to database');
    console.log('');

    // Apply migration using raw SQL
    console.log('Executing migration SQL...');
    
    // Add contactInfo column
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "Contact" ADD COLUMN IF NOT EXISTS "contactInfo" JSONB;
    `);
    console.log('✅ Added contactInfo column');

    // Add bestContactTimes column
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "Contact" ADD COLUMN IF NOT EXISTS "bestContactTimes" JSONB;
    `);
    console.log('✅ Added bestContactTimes column');

    // Add comments
    try {
      await prisma.$executeRawUnsafe(`
        COMMENT ON COLUMN "Contact"."contactInfo" IS 'Stores extracted contact information (age, phone, email, socials, etc.)';
      `);
      await prisma.$executeRawUnsafe(`
        COMMENT ON COLUMN "Contact"."bestContactTimes" IS 'Stores best contact times analysis with multiple estimates and days of week';
      `);
      console.log('✅ Added column comments');
    } catch (commentError) {
      // Comments might fail if database doesn't support them, that's okay
      console.log('⚠️  Could not add comments (non-critical)');
    }

    // Verify columns were added
    console.log('');
    console.log('Verifying columns...');
    const result = await prisma.$queryRawUnsafe(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'Contact' 
      AND column_name IN ('contactInfo', 'bestContactTimes');
    `);

    console.log('');
    console.log('✅ Migration completed successfully!');
    console.log('');
    console.log('Columns added:');
    if (Array.isArray(result) && result.length > 0) {
      result.forEach((row) => {
        console.log(`  - ${row.column_name} (${row.data_type})`);
      });
    } else {
      console.log('  ⚠️  Could not verify columns (they may still have been added)');
    }
    console.log('');

  } catch (error) {
    console.error('');
    console.error('❌ Migration failed!');
    console.error('');
    console.error('Error:', error instanceof Error ? error.message : String(error));
    if (error instanceof Error && error.stack) {
      console.error('');
      console.error('Stack trace:');
      console.error(error.stack);
    }
    console.error('');
    process.exit(1);
  } finally {
    await prisma.$disconnect();
    console.log('Disconnected from database');
  }
}

// Run migration
applyMigration()
  .then(() => {
    console.log('========================================');
    console.log('Migration script completed');
    console.log('========================================');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
