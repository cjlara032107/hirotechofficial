/**
 * Utility functions for safely updating job progress
 * 
 * Features:
 * - Handles database errors gracefully (logs, doesn't throw)
 * - Uses atomic increments for concurrent updates
 * - Handles null/undefined counts
 */

import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

/**
 * Safely updates AnalysisJob progress with atomic increments
 * Logs errors but doesn't throw to avoid interrupting processing
 * 
 * Note: For SyncJob updates, use updateSyncJobProgress from './pipeline-analyzer/update-progress'
 */
export async function updateAnalysisJobProgress(
  jobId: string,
  options: {
    analyzedIncrement?: number | null;
    failedIncrement?: number | null;
    analyzedCount?: number | null;
    failedCount?: number | null;
    errors?: Array<{ contactId: string; error: string }> | null;
  } = {}
): Promise<void> {
  const { analyzedIncrement, failedIncrement, analyzedCount, failedCount, errors } = options;

  try {
    const updateData: Prisma.AnalysisJobUpdateInput = {};

    // Use atomic increment if provided, otherwise use direct count
    if (analyzedIncrement != null && analyzedIncrement !== 0) {
      updateData.analyzedContacts = {
        increment: analyzedIncrement,
      };
    } else if (analyzedCount != null) {
      updateData.analyzedContacts = analyzedCount;
    }

    if (failedIncrement != null && failedIncrement !== 0) {
      updateData.failedContacts = {
        increment: failedIncrement,
      };
    } else if (failedCount != null) {
      updateData.failedContacts = failedCount;
    }

    // Handle errors array
    if (errors != null) {
      updateData.errors = errors.length > 0 ? errors : undefined;
    }

    // Only update if there's data to update
    if (Object.keys(updateData).length === 0) {
      return;
    }

    await prisma.analysisJob.update({
      where: { id: jobId },
      data: updateData,
    });
  } catch (error) {
    // Log error but don't throw - progress updates are non-critical
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorCode = (error as any)?.code;
    
    console.error(`[Progress Update] Failed to update AnalysisJob ${jobId} progress:`, {
      error: errorMessage,
      code: errorCode,
      options,
    });
    
    // Don't rethrow - allow processing to continue
  }
}

/**
 * Normalizes a count value, converting null/undefined to 0
 */
export function normalizeCount(count: number | null | undefined): number {
  return count ?? 0;
}

/**
 * Calculates progress percentage safely handling null/undefined counts
 */
export function calculateProgressPercentage(
  current: number | null | undefined,
  total: number | null | undefined
): number {
  const currentCount = normalizeCount(current);
  const totalCount = normalizeCount(total);
  
  if (totalCount === 0) {
    return 0;
  }
  
  return Math.min(100, Math.max(0, (currentCount / totalCount) * 100));
}

