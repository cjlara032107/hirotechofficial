import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { logger } from '@/lib/utils/logger';

/**
 * POST /api/admin/apply-ai-migration
 * Apply the Advanced AI Features migration
 * Adds new columns to Contact table
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    logger.info('Applying Advanced AI Features migration');

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

    logger.info('Migration applied successfully');

    return NextResponse.json({
      success: true,
      message: 'Migration applied successfully',
      columnsAdded: [
        'conversionPath',
        'similarLeadsInsight',
        'botAccuracyScore',
        'conversationPatterns',
        'indirectIntent',
        'buyerReliability',
        'buyerStyle',
      ],
    });
  } catch (error) {
    logger.error('Migration failed', error instanceof Error ? error : new Error(String(error)));
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: `Migration failed: ${errorMessage}` },
      { status: 500 }
    );
  }
}





