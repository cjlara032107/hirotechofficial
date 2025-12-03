import { NextRequest, NextResponse } from 'next/server';
import { acquireCronLock, getCronStaggerDelay } from '@/lib/cron-lock';
import { getIntelligentUpdater } from '@/lib/pipelines/intelligent-updater';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

/**
 * Cron job to intelligently update pipelines based on activity, cost-benefit, and predictions
 * This endpoint is called by Vercel Cron every 5 minutes
 */
export async function GET(request: NextRequest) {
  try {
    // Security: Verify cron secret (optional)
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      console.log('[Cron Pipeline Updates] Unauthorized access attempt');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Stagger cron job execution to prevent simultaneous pool access
    const staggerDelay = getCronStaggerDelay('pipeline-updates');
    await new Promise(resolve => setTimeout(resolve, staggerDelay));

    // Acquire database lock to prevent simultaneous cron job access across instances
    const releaseLock = await acquireCronLock('pipeline-updates');
    
    if (!releaseLock) {
      console.log('[Cron Pipeline Updates] Another instance is running, skipping...');
      return NextResponse.json({
        success: true,
        skipped: true,
        message: 'Another instance is processing',
      });
    }
    
    try {
      console.log('[Cron Pipeline Updates] Starting intelligent pipeline update job...');
      
      const updater = getIntelligentUpdater();
      
      // Step 1: Schedule updates for all active pipelines
      const scheduleResult = await updater.scheduleUpdates();
      
      console.log('[Cron Pipeline Updates] Scheduling complete:', scheduleResult);
      
      // Step 2: Process ready updates from queue
      const updateResults = await updater.processQueue();
      
      const successCount = updateResults.filter(r => r.success).length;
      const failureCount = updateResults.filter(r => !r.success).length;
      const totalContactsProcessed = updateResults.reduce(
        (sum, r) => sum + (r.contactsProcessed || 0), 
        0
      );
      
      console.log('[Cron Pipeline Updates] Processing complete:', {
        success: successCount,
        failures: failureCount,
        totalContactsProcessed
      });

      // Get final queue status
      const queueStatus = updater.getQueueStatus();

      return NextResponse.json({
        success: true,
        scheduling: {
          scheduled: scheduleResult.scheduled,
          skipped: scheduleResult.skipped,
          queueStatus: scheduleResult.queueStatus
        },
        processing: {
          processed: updateResults.length,
          success: successCount,
          failures: failureCount,
          totalContactsProcessed
        },
        queueStatus,
        timestamp: new Date().toISOString()
      });
    } finally {
      // Release lock
      await releaseLock();
    }
  } catch (error) {
    console.error('[Cron Pipeline Updates] Fatal error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      },
      { status: 500 }
    );
  }
}













