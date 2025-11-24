import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { ApiKeyStatus } from '@prisma/client';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

/**
 * Cron job to re-enable API keys after 24-hour cooldown
 * 
 * Runs every hour and checks for keys that were rate-limited more than 24 hours ago
 * Can be called by:
 * - Vercel Cron (vercel.json configuration)
 * - External cron services (with proper authentication)
 * - Manual trigger for testing
 * 
 * Usage:
 * GET /api/cron/api-keys
 */
export async function GET(request: NextRequest) {
  try {
    // Verify cron secret if set (security for production)
    const authHeader = request.headers.get('authorization');
    if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      console.log('[API Keys Cron] Unauthorized request');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    console.log('[API Keys Cron] Starting execution...');
    const startTime = Date.now();

    // Find all rate-limited keys
    const rateLimitedKeys = await prisma.apiKey.findMany({
      where: {
        status: ApiKeyStatus.RATE_LIMITED,
        rateLimitedAt: {
          not: null,
        },
      },
      select: {
        id: true,
        name: true,
        rateLimitedAt: true,
      },
    });

    if (rateLimitedKeys.length === 0) {
      console.log('[API Keys Cron] No rate-limited keys found');
      return NextResponse.json({
        success: true,
        keysChecked: 0,
        keysReEnabled: 0,
        duration: Date.now() - startTime,
      });
    }

    console.log(`[API Keys Cron] Found ${rateLimitedKeys.length} rate-limited key(s)`);

    const now = new Date();
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    let reEnabledCount = 0;
    const reEnabledKeys: string[] = [];

    // Check each key
    for (const key of rateLimitedKeys) {
      if (!key.rateLimitedAt) {
        continue;
      }

      // If rate limited more than 24 hours ago, re-enable
      if (key.rateLimitedAt <= twentyFourHoursAgo) {
        try {
          await prisma.apiKey.update({
            where: { id: key.id },
            data: {
              status: ApiKeyStatus.ACTIVE,
              rateLimitedAt: null,
              consecutiveFailures: 0, // Reset consecutive failures
            },
          });

          reEnabledCount++;
          reEnabledKeys.push(key.name || key.id);
          console.log(`[API Keys Cron] Re-enabled key: ${key.name || key.id} (rate-limited at ${key.rateLimitedAt.toISOString()})`);
        } catch (error) {
          console.error(`[API Keys Cron] Error re-enabling key ${key.id}:`, error);
        }
      } else {
        // Calculate time remaining
        const timeRemaining = key.rateLimitedAt.getTime() + 24 * 60 * 60 * 1000 - now.getTime();
        const hoursRemaining = Math.floor(timeRemaining / (1000 * 60 * 60));
        const minutesRemaining = Math.floor((timeRemaining % (1000 * 60 * 60)) / (1000 * 60));
        console.log(`[API Keys Cron] Key ${key.name || key.id} still in cooldown: ${hoursRemaining}h ${minutesRemaining}m remaining`);
      }
    }

    const duration = Date.now() - startTime;
    console.log(`[API Keys Cron] Execution complete in ${duration}ms: ${reEnabledCount} key(s) re-enabled`);

    return NextResponse.json({
      success: true,
      keysChecked: rateLimitedKeys.length,
      keysReEnabled: reEnabledCount,
      reEnabledKeys,
      duration,
      timestamp: now.toISOString(),
    });
  } catch (error) {
    console.error('[API Keys Cron] Fatal error:', error);
    return NextResponse.json(
      { 
        error: 'Failed to execute API keys cron job',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

// Allow POST as well for manual testing
export async function POST(request: NextRequest) {
  return GET(request);
}

