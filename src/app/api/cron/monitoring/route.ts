import { NextRequest, NextResponse } from 'next/server';
import { acquireCronLock, getCronStaggerDelay } from '@/lib/cron-lock';
import { runMonitoringChecks, autoResolveAlerts } from '@/lib/monitoring/alert-monitor';
import { logJobStart, logJobComplete, logJobFailure } from '@/lib/logging/job-logger';
import { logErrorWithContext } from '@/lib/logging/error-logger';
import { logger } from '@/lib/utils/logger';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

/**
 * Cron job to monitor system health and create alerts
 * This endpoint is called by Vercel Cron every 5 minutes
 */
export async function GET(request: NextRequest) {
  let jobStartTime: number | undefined;
  const jobType = 'cron-monitoring';
  
  try {
    // Security: Verify cron secret (optional)
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      logger.warn('Unauthorized access attempt', { operation: 'cron-monitoring' });
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Stagger cron job execution to prevent simultaneous pool access
    const staggerDelay = getCronStaggerDelay('monitoring');
    await new Promise(resolve => setTimeout(resolve, staggerDelay));

    // Acquire database lock to prevent simultaneous cron job access across instances
    const releaseLock = await acquireCronLock('monitoring');
    
    if (!releaseLock) {
      logger.info('Another instance is running, skipping', { operation: 'cron-monitoring' });
      return NextResponse.json({
        success: true,
        skipped: true,
        message: 'Another instance is processing',
      });
    }
    
    try {
      jobStartTime = Date.now();
      const currentTime = new Date();
      
      await logJobStart(jobType, undefined, `Starting monitoring checks at ${currentTime.toISOString()}`);
      logger.info('Starting monitoring checks', { operation: 'cron-monitoring', timestamp: currentTime.toISOString() });

      // Run monitoring checks
      const results = await runMonitoringChecks();

      // Auto-resolve alerts that have improved
      await autoResolveAlerts();

      const duration = Date.now() - jobStartTime;
      await logJobComplete(
        jobType,
        undefined,
        `Monitoring checks completed: ${results.jobFailures} job failures, ${results.errorRate.toFixed(2)} errors/min`,
        duration,
        results
      );

      logger.info('Monitoring checks completed', { operation: 'cron-monitoring', results });

      return NextResponse.json({
        success: true,
        results,
        duration,
      });
    } finally {
      // Always release lock
      await releaseLock();
    }
  } catch (error) {
    const duration = jobStartTime ? Date.now() - jobStartTime : 0;
    await logJobFailure(
      jobType,
      undefined,
      'Fatal error running monitoring checks',
      error as Error,
      { duration }
    );
    await logErrorWithContext(error as Error, {
      operation: 'cron-monitoring',
      metadata: { duration },
    });
    
    logger.error('Fatal error running monitoring checks', error as Error, { operation: 'cron-monitoring', duration });
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        success: false,
      },
      { status: 500 }
    );
  }
}

