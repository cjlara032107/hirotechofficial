import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { withRetry } from '@/lib/db-retry';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

const QUERY_TIMEOUT = 10000; // 10 seconds per query

/**
 * Cron job to recover stuck sync jobs
 * This endpoint is called by Vercel Cron to check for and recover syncs stuck in PENDING or IN_PROGRESS
 * 
 * Recovery logic:
 * - PENDING jobs older than 5 minutes → Mark as FAILED (likely never started)
 * - IN_PROGRESS jobs older than 30 minutes → Mark as FAILED (likely timed out)
 */
export async function GET(request: NextRequest) {
  try {
    // Security: Verify cron secret (optional)
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      console.log('[Cron Recover Stuck Syncs] Unauthorized access attempt');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const now = new Date();
    const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
    const thirtyMinutesAgo = new Date(now.getTime() - 30 * 60 * 1000);

    // Find stuck PENDING jobs (older than 5 minutes, never started)
    // Use retry logic and timeout to handle pool exhaustion
    const stuckPendingJobs = await withRetry(
      async () => {
        const queryPromise = prisma.syncJob.findMany({
          where: {
            status: 'PENDING',
            createdAt: {
              lt: fiveMinutesAgo,
            },
          },
          include: {
            facebookPage: {
              select: {
                pageName: true,
              },
            },
          },
        });
        
        const timeoutPromise = new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout')), QUERY_TIMEOUT)
        );
        
        return await Promise.race([queryPromise, timeoutPromise]);
      },
      {
        maxRetries: 2,
        initialDelay: 1000,
        retryableErrors: [
          'Unable to check out process from the pool',
          'P2024',
          'P1001',
          'timeout',
        ],
      }
    );

    // Find stuck IN_PROGRESS jobs (older than 30 minutes, likely timed out)
    const stuckInProgressJobs = await withRetry(
      async () => {
        const queryPromise = prisma.syncJob.findMany({
          where: {
            status: 'IN_PROGRESS',
            startedAt: {
              lt: thirtyMinutesAgo,
            },
          },
          include: {
            facebookPage: {
              select: {
                pageName: true,
              },
            },
          },
        });
        
        const timeoutPromise = new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Query timeout')), QUERY_TIMEOUT)
        );
        
        return await Promise.race([queryPromise, timeoutPromise]);
      },
      {
        maxRetries: 2,
        initialDelay: 1000,
        retryableErrors: [
          'Unable to check out process from the pool',
          'P2024',
          'P1001',
          'timeout',
        ],
      }
    );

    let recoveredPending = 0;
    let recoveredInProgress = 0;

    // Recover stuck PENDING jobs
    for (const job of stuckPendingJobs) {
      try {
        await withRetry(
          async () => {
            const updatePromise = prisma.syncJob.update({
              where: { id: job.id },
              data: {
                status: 'FAILED',
                errors: [
                  {
                    error: 'Sync job stuck in PENDING status - likely never started due to serverless function termination',
                    timestamp: now.toISOString(),
                    recoveredAt: now.toISOString(),
                  },
                ] as Prisma.InputJsonValue,
                completedAt: now,
              },
            });
            
            const timeoutPromise = new Promise<never>((_, reject) => 
              setTimeout(() => reject(new Error('Update timeout')), QUERY_TIMEOUT)
            );
            
            return await Promise.race([updatePromise, timeoutPromise]);
          },
          {
            maxRetries: 2,
            initialDelay: 500,
            retryableErrors: [
              'Unable to check out process from the pool',
              'P2024',
              'P1001',
              'timeout',
            ],
          }
        );
        recoveredPending++;
        console.log(`[Cron Recover Stuck Syncs] Recovered PENDING job ${job.id} for page ${job.facebookPage?.pageName || 'unknown'}`);
      } catch (error) {
        console.error(`[Cron Recover Stuck Syncs] Failed to recover PENDING job ${job.id}:`, error);
      }
    }

    // Recover stuck IN_PROGRESS jobs
    for (const job of stuckInProgressJobs) {
      try {
        await withRetry(
          async () => {
            const updatePromise = prisma.syncJob.update({
              where: { id: job.id },
              data: {
                status: 'FAILED',
                errors: [
                  {
                    error: 'Sync job stuck in IN_PROGRESS status - likely timed out or crashed',
                    timestamp: now.toISOString(),
                    recoveredAt: now.toISOString(),
                    syncedContacts: job.syncedContacts,
                    failedContacts: job.failedContacts,
                  },
                ] as Prisma.InputJsonValue,
                completedAt: now,
              },
            });
            
            const timeoutPromise = new Promise<never>((_, reject) => 
              setTimeout(() => reject(new Error('Update timeout')), QUERY_TIMEOUT)
            );
            
            return await Promise.race([updatePromise, timeoutPromise]);
          },
          {
            maxRetries: 2,
            initialDelay: 500,
            retryableErrors: [
              'Unable to check out process from the pool',
              'P2024',
              'P1001',
              'timeout',
            ],
          }
        );
        recoveredInProgress++;
        console.log(`[Cron Recover Stuck Syncs] Recovered IN_PROGRESS job ${job.id} for page ${job.facebookPage?.pageName || 'unknown'} (${job.syncedContacts} synced, ${job.failedContacts} failed)`);
      } catch (error) {
        console.error(`[Cron Recover Stuck Syncs] Failed to recover IN_PROGRESS job ${job.id}:`, error);
      }
    }

    const totalRecovered = recoveredPending + recoveredInProgress;

    if (totalRecovered > 0) {
      console.log(`[Cron Recover Stuck Syncs] ✅ Recovered ${totalRecovered} stuck sync jobs (${recoveredPending} PENDING, ${recoveredInProgress} IN_PROGRESS)`);
    } else {
      console.log(`[Cron Recover Stuck Syncs] ✅ No stuck sync jobs found`);
    }

    return NextResponse.json({
      success: true,
      recovered: {
        pending: recoveredPending,
        inProgress: recoveredInProgress,
        total: totalRecovered,
      },
      found: {
        pending: stuckPendingJobs.length,
        inProgress: stuckInProgressJobs.length,
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('[Cron Recover Stuck Syncs] Error:', error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}


