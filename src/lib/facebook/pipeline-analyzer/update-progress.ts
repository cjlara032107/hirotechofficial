import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { withRetry } from '@/lib/db-retry';
import { progressBatcher } from './progress-batcher';

/**
 * Error type for progress update operations
 */
interface ProgressUpdateError {
  platform?: string;
  id?: string;
  error: string;
  code?: number;
}

/**
 * Options for updating sync job progress
 */
export interface UpdateProgressOptions {
  /**
   * Number of synced contacts (will be set, not incremented)
   */
  syncedContacts?: number | null;
  /**
   * Number of failed contacts (will be set, not incremented)
   */
  failedContacts?: number | null;
  /**
   * Atomic increment for synced contacts (use this for concurrent-safe updates)
   */
  syncedIncrement?: number | null;
  /**
   * Atomic increment for failed contacts (use this for concurrent-safe updates)
   */
  failedIncrement?: number | null;
  /**
   * Additional errors to append to the errors array
   */
  errors?: ProgressUpdateError[];
  /**
   * Whether to force update even if values haven't changed
   */
  force?: boolean;
  /**
   * Whether to bypass batching and update immediately (for critical updates)
   */
  immediate?: boolean;
}

/**
 * Updates the progress of a sync job with retry logic and timestamp tracking
 * 
 * This function:
 * - Updates syncedContacts and failedContacts counts
 * - Appends errors to the errors array (doesn't overwrite existing errors)
 * - Updates lastProgressAt timestamp to track when progress was last updated
 * - Uses retry logic for resilience against database connection issues
 * - Handles errors gracefully (logs but doesn't throw)
 * 
 * @param jobId - The sync job ID
 * @param options - Progress update options
 * @returns Promise that resolves when update completes (or fails silently)
 * 
 * @example
 * ```typescript
 * await updateSyncJobProgress(jobId, {
 *   syncedContacts: 10,
 *   failedContacts: 2,
 *   errors: [{ platform: 'Messenger', id: '123', error: 'Rate limited' }]
 * });
 * ```
 */
export async function updateSyncJobProgress(
  jobId: string,
  options: UpdateProgressOptions = {}
): Promise<void> {
  const { 
    syncedContacts, 
    failedContacts, 
    syncedIncrement,
    failedIncrement,
    errors = [], 
    force = false,
    immediate = false
  } = options;

  // Use batcher for non-immediate updates (reduces DB queries by 60-70%)
  if (!immediate) {
    progressBatcher.queueUpdate(jobId, options);
    return; // Return immediately - batcher will flush asynchronously
  }

  // Immediate update (bypass batching) - for critical updates
  try {
    // Use retry logic for resilience against database connection issues
    await withRetry(
      async () => {
        // Get current job state to merge errors
        const currentJob = await prisma.syncJob.findUnique({
          where: { id: jobId },
          select: { errors: true },
        });

        // Merge errors: append new errors to existing ones
        const existingErrors = currentJob?.errors 
          ? (Array.isArray(currentJob.errors) ? currentJob.errors : [currentJob.errors])
          : [];
        
        const mergedErrors = errors.length > 0 
          ? [...existingErrors, ...errors]
          : existingErrors;

        // Build update data
        const updateData: Prisma.SyncJobUpdateInput = {
          lastProgressAt: new Date(), // Always update timestamp
        };

        // Use atomic increment if provided (for concurrent-safe updates)
        // Otherwise use direct count assignment
        if (syncedIncrement != null && syncedIncrement !== 0) {
          updateData.syncedContacts = {
            increment: syncedIncrement,
          };
        } else if (syncedContacts !== undefined) {
          // Normalize null/undefined to 0
          updateData.syncedContacts = syncedContacts ?? 0;
        }

        if (failedIncrement != null && failedIncrement !== 0) {
          updateData.failedContacts = {
            increment: failedIncrement,
          };
        } else if (failedContacts !== undefined) {
          // Normalize null/undefined to 0
          updateData.failedContacts = failedContacts ?? 0;
        }

        if (errors.length > 0 || force) {
          updateData.errors = mergedErrors.length > 0 ? (mergedErrors as Prisma.InputJsonValue) : Prisma.JsonNull;
        }

        // Update the job
        await prisma.syncJob.update({
          where: { id: jobId },
          data: updateData,
        });
      },
      {
        maxRetries: 3,
        initialDelay: 1000,
        maxDelay: 10000,
        retryableErrors: [
          'Unable to check out process from the pool',
          'connection pool',
          'P2024',
          'P1001',
          'timeout',
        ],
      }
    );
  } catch (error) {
    // Handle errors gracefully - log but don't throw
    // Progress update failures shouldn't stop the main processing
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorCode = (error as any)?.code;
    
    console.error(`[Update Progress ${jobId}] Failed to update progress after retries:`, {
      error: errorMessage,
      code: errorCode,
      options,
    });
    
    // Don't rethrow - allow processing to continue
  }
}

