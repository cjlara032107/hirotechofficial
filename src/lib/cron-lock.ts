/**
 * Simple connection availability check for cron jobs
 * If connection isn't available quickly, skip execution to prevent pool exhaustion
 */

import { prisma } from './db';

// Increase timeout for Vercel serverless (cold starts, network latency)
const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
const CONNECTION_TIMEOUT_MS = isVercel ? 5000 : 2000; // 5s for Vercel, 2s for traditional

/**
 * Check if database connection is available quickly
 * Returns true if connection is available, false if timeout or error
 */
export async function acquireCronLock(
  lockName: string
): Promise<(() => Promise<void>) | null> {
  try {
    // Try to get a connection with a very short timeout
    // If we can't get it quickly, another instance is likely using it
    const connectionAvailable = await Promise.race([
      (async () => {
        try {
          // Quick health check - if this succeeds, we have a connection
          await prisma.$queryRaw`SELECT 1`;
          return true;
        } catch {
          return false;
        }
      })(),
      new Promise<false>((resolve) => 
        setTimeout(() => resolve(false), CONNECTION_TIMEOUT_MS)
      )
    ]);

    if (!connectionAvailable) {
      // Connection not available quickly - skip this execution
      console.log(`[Cron Lock] ${lockName} - Connection unavailable (timeout ${CONNECTION_TIMEOUT_MS}ms), skipping to prevent pool exhaustion`);
      return null;
    }

    // Connection available - proceed
    console.log(`[Cron Lock] ${lockName} - Connection available, proceeding`);
    
    return async () => {
      // Lock released when function completes
      // Connection will be automatically managed by Prisma
    };
  } catch (error) {
    // Any error means we should skip
    console.log(`[Cron Lock] ${lockName} - Error checking connection, skipping:`, error);
    return null;
  }
}

/**
 * Stagger cron execution to prevent simultaneous runs
 * Returns a delay in milliseconds based on the lock name
 */
export function getCronStaggerDelay(lockName: string): number {
  // Different delays for different cron jobs
  const delays: Record<string, number> = {
    'send-scheduled': 0, // Run first
    'ai-automations': 30000, // Run 30 seconds later
    'pipeline-updates': 60000, // Run 60 seconds later (after ai-automations)
  };
  
  const baseDelay = delays[lockName] || 0;
  // Add random jitter (0-10 seconds) to spread out multiple instances
  const jitter = Math.random() * 10000;
  return baseDelay + jitter;
}

