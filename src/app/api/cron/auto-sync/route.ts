import { NextRequest, NextResponse } from 'next/server';
import { prisma, connectPrisma } from '@/lib/db';
import { startInstantSync } from '@/lib/facebook/instant-sync';
import { acquireCronLock, getCronStaggerDelay } from '@/lib/cron-lock';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

/**
 * Cron job to automatically sync Facebook pages at midnight (12 AM)
 * Runs daily and syncs all pages with autoSync enabled
 * 
 * Schedule: 0 0 * * * (every day at 12:00 AM)
 */
export async function GET(request: NextRequest) {
  const jobStartTime = Date.now();
  let releaseLock: (() => Promise<void>) | null = null;
  
  try {
    // Security: Verify cron secret (optional but recommended)
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      console.log('[Auto Sync Cron] Unauthorized access attempt');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Stagger cron job execution to prevent simultaneous pool access
    const staggerDelay = getCronStaggerDelay('auto-sync');
    await new Promise(resolve => setTimeout(resolve, staggerDelay));

    // Acquire database lock to prevent simultaneous cron job access across instances
    releaseLock = await acquireCronLock('auto-sync');
    
    if (!releaseLock) {
      console.log('[Auto Sync Cron] Another instance is running, skipping...');
      return NextResponse.json({
        success: true,
        skipped: true,
        message: 'Another instance is processing',
      });
    }

    console.log('[Auto Sync Cron] Starting midnight auto-sync job...');

    // CRITICAL: Ensure database connection
    await connectPrisma();

    // Get current time to check if it's around midnight
    const now = new Date();
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();
    
    // Only run if it's between 12:00 AM and 12:05 AM (5 minute window)
    // This allows for slight timing variations in cron execution
    if (currentHour !== 0 || currentMinute > 5) {
      console.log(`[Auto Sync Cron] Not midnight yet (current time: ${now.toISOString()}), skipping...`);
      return NextResponse.json({
        success: true,
        skipped: true,
        message: `Not midnight yet (current: ${currentHour}:${currentMinute})`,
        timestamp: now.toISOString(),
      });
    }

    // Find all active Facebook pages with autoSync enabled
    const pagesToSync = await prisma.facebookPage.findMany({
      where: {
        isActive: true,
        autoSync: true,
      },
      select: {
        id: true,
        pageName: true,
        pageId: true,
        organizationId: true,
        lastSyncedAt: true,
      },
    });

    console.log(`[Auto Sync Cron] Found ${pagesToSync.length} page(s) with auto-sync enabled`);

    if (pagesToSync.length === 0) {
      return NextResponse.json({
        success: true,
        message: 'No pages with auto-sync enabled',
        pagesProcessed: 0,
        timestamp: now.toISOString(),
      });
    }

    // Check for active sync jobs to avoid duplicate syncs
    const activeSyncJobs = await prisma.syncJob.findMany({
      where: {
        facebookPageId: { in: pagesToSync.map(p => p.id) },
        status: {
          in: ['PENDING', 'IN_PROGRESS'],
        },
      },
      select: {
        facebookPageId: true,
      },
    });

    const pagesWithActiveSyncs = new Set(activeSyncJobs.map(job => job.facebookPageId));
    const pagesToSyncNow = pagesToSync.filter(page => !pagesWithActiveSyncs.has(page.id));

    if (pagesToSyncNow.length === 0) {
      console.log('[Auto Sync Cron] All pages already have active sync jobs, skipping...');
      return NextResponse.json({
        success: true,
        message: 'All pages already syncing',
        pagesProcessed: 0,
        skipped: pagesToSync.length,
        timestamp: now.toISOString(),
      });
    }

    console.log(`[Auto Sync Cron] Starting sync for ${pagesToSyncNow.length} page(s)...`);

    // Start syncs for all eligible pages
    // Note: We need a userId, but for cron jobs we'll use the organization owner
    // or create a system user. For now, we'll get the first user from each organization.
    const results = await Promise.allSettled(
      pagesToSyncNow.map(async (page) => {
        try {
          // Get the first user from the organization to use as the sync initiator
          const orgUser = await prisma.user.findFirst({
            where: {
              organizationId: page.organizationId,
            },
            select: {
              id: true,
            },
          });

          if (!orgUser) {
            throw new Error(`No user found for organization ${page.organizationId}`);
          }

          console.log(`[Auto Sync Cron] Starting sync for page: ${page.pageName} (${page.id})`);
          
          const result = await startInstantSync(page.id, orgUser.id);
          
          console.log(`[Auto Sync Cron] ✅ Sync started for ${page.pageName}: ${result.jobId}`);
          
          return {
            pageId: page.id,
            pageName: page.pageName,
            jobId: result.jobId,
            success: true,
          };
        } catch (error) {
          console.error(`[Auto Sync Cron] ❌ Failed to sync page ${page.pageName}:`, error);
          return {
            pageId: page.id,
            pageName: page.pageName,
            success: false,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      })
    );

    const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
    const failed = results.filter(r => r.status === 'rejected' || (r.status === 'fulfilled' && !r.value.success)).length;

    const duration = Date.now() - jobStartTime;

    console.log(`[Auto Sync Cron] ✅ Completed in ${duration}ms: ${successful} successful, ${failed} failed`);

    return NextResponse.json({
      success: true,
      message: `Auto-sync completed: ${successful} successful, ${failed} failed`,
      pagesProcessed: pagesToSyncNow.length,
      successful,
      failed,
      skipped: pagesToSync.length - pagesToSyncNow.length,
      duration: `${duration}ms`,
      timestamp: now.toISOString(),
      results: results.map(r => r.status === 'fulfilled' ? r.value : { error: 'Promise rejected' }),
    });
  } catch (error) {
    const duration = Date.now() - jobStartTime;
    console.error('[Auto Sync Cron] ❌ Fatal error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        duration: `${duration}ms`,
        timestamp: new Date().toISOString(),
      },
      { status: 500 }
    );
  } finally {
    // Release the lock if it was acquired
    if (releaseLock) {
      await releaseLock().catch(err => {
        console.error('[Auto Sync Cron] Error releasing lock:', err);
      });
    }
  }
}

