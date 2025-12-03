/**
 * Apply Advanced AI Features Migration
 * Adds new columns to Contact table for enhanced AI analysis
 */

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function applyMigration() {
  try {
    console.log('🚀 Applying Advanced AI Features migration...');

    // Apply migration SQL directly
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "Contact" 
      ADD COLUMN IF NOT EXISTS "conversionPath" TEXT[] DEFAULT ARRAY[]::TEXT[],
      ADD COLUMN IF NOT EXISTS "similarLeadsInsight" TEXT,
      ADD COLUMN IF NOT EXISTS "botAccuracyScore" DOUBLE PRECISION,
      ADD COLUMN IF NOT EXISTS "conversationPatterns" JSONB,
      ADD COLUMN IF NOT EXISTS "indirectIntent" JSONB,
      ADD COLUMN IF NOT EXISTS "buyerReliability" JSONB,
      ADD COLUMN IF NOT EXISTS "buyerStyle" TEXT;
    `);

    console.log('✅ Migration applied successfully!');
    console.log('📋 New columns added:');
    console.log('   - conversionPath (TEXT[])');
    console.log('   - similarLeadsInsight (TEXT)');
    console.log('   - botAccuracyScore (DOUBLE PRECISION)');
    console.log('   - conversationPatterns (JSONB)');
    console.log('   - indirectIntent (JSONB)');
    console.log('   - buyerReliability (JSONB)');
    console.log('   - buyerStyle (TEXT)');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

applyMigration()
  .then(() => {
    console.log('✅ Migration completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  });













