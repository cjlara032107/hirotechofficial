/**
 * Chunked Contact Updates Utility
 * 
 * Processes contact updates in chunks of 50 per transaction with:
 * - Chunk-level transaction rollback (failed chunks don't affect others)
 * - Progress updates per chunk
 * - Independent retry for failed chunks
 */

import { prisma as defaultPrisma } from '@/lib/db';
import { Prisma, PrismaClient } from '@prisma/client';

export interface ChunkedUpdateOptions {
  contactIds: string[];
  chunkSize?: number; // Default: 50
  maxRetries?: number; // Default: 3
  prisma?: PrismaClient; // Optional: Use routed prisma client for multi-DB support
  onProgress?: (progress: ChunkProgress) => void;
  onChunkComplete?: (chunkIndex: number, success: boolean, count: number) => void;
  onChunkError?: (chunkIndex: number, error: Error, contactIds: string[]) => void;
}

export interface ChunkProgress {
  totalContacts: number;
  processedContacts: number;
  successfulContacts: number;
  failedContacts: number;
  completedChunks: number;
  totalChunks: number;
  failedChunks: number;
  retryingChunks: number;
}

export interface ChunkedUpdateResult {
  success: boolean;
  totalContacts: number;
  successfulContacts: number;
  failedContacts: number;
  completedChunks: number;
  failedChunks: number;
  errors: Array<{ chunkIndex: number; contactIds: string[]; error: string }>;
}

/**
 * Updates contacts in chunks with transaction rollback per chunk
 * 
 * This function processes contact updates in batches with the following features:
 * - **Chunk-level transactions**: Each chunk is processed in its own transaction
 * - **Independent failure**: Failed chunks don't affect successful chunks
 * - **Automatic retry**: Failed chunks are retried with exponential backoff
 * - **Progress tracking**: Callbacks for progress, completion, and errors
 * - **Input validation**: Validates and clamps chunk size and retry limits
 * 
 * The function splits contacts into chunks (default: 50 per chunk), processes each
 * chunk in a separate database transaction, and retries failed chunks up to maxRetries
 * times before marking them as failed.
 * 
 * @param updateFn - Function that performs the update operation on a chunk of contacts
 * @param updateFn.contactIds - Array of contact IDs to update in this chunk
 * @param updateFn.tx - Prisma transaction client for database operations
 * @param options - Configuration options for chunked updates
 * @param options.contactIds - Array of all contact IDs to update
 * @param options.chunkSize - Number of contacts per chunk (default: 50, clamped 1-1000)
 * @param options.maxRetries - Maximum retry attempts per chunk (default: 3, clamped 0-10)
 * @param options.onProgress - Optional callback called after each chunk with progress info
 * @param options.onChunkComplete - Optional callback called when a chunk completes (success or failure)
 * @param options.onChunkError - Optional callback called when a chunk fails after all retries
 * @returns Promise resolving to update results with success/failure counts
 * 
 * @example
 * ```typescript
 * const result = await updateContactsInChunks(
 *   async (contactIds, tx) => {
 *     await tx.contact.updateMany({
 *       where: { id: { in: contactIds } },
 *       data: { status: 'ACTIVE' }
 *     });
 *   },
 *   {
 *     contactIds: allContactIds,
 *     chunkSize: 50,
 *     maxRetries: 3,
 *     onProgress: (progress) => console.log(`${progress.processedContacts}/${progress.totalContacts}`)
 *   }
 * );
 * ```
 */
export async function updateContactsInChunks(
  updateFn: (contactIds: string[], tx: Prisma.TransactionClient) => Promise<void>,
  options: ChunkedUpdateOptions
): Promise<ChunkedUpdateResult> {
  const {
    contactIds,
    chunkSize = 50,
    maxRetries = 3,
    prisma = defaultPrisma, // Use provided prisma client or default
    onProgress,
    onChunkComplete,
    onChunkError,
  } = options;

  // Validate inputs
  if (!Array.isArray(contactIds)) {
    throw new Error('contactIds must be an array');
  }

  if (contactIds.length === 0) {
    return {
      success: true,
      totalContacts: 0,
      successfulContacts: 0,
      failedContacts: 0,
      completedChunks: 0,
      failedChunks: 0,
      errors: [],
    };
  }

  const validChunkSize = Math.max(1, Math.min(chunkSize || 50, 1000)); // Clamp between 1 and 1000
  const validMaxRetries = Math.max(0, Math.min(maxRetries || 3, 10)); // Clamp between 0 and 10

  // Split into chunks
  const chunks: string[][] = [];
  for (let i = 0; i < contactIds.length; i += validChunkSize) {
    chunks.push(contactIds.slice(i, i + validChunkSize));
  }

  const progress: ChunkProgress = {
    totalContacts: contactIds.length,
    processedContacts: 0,
    successfulContacts: 0,
    failedContacts: 0,
    completedChunks: 0,
    totalChunks: chunks.length,
    failedChunks: 0,
    retryingChunks: 0,
  };

  const errors: Array<{ chunkIndex: number; contactIds: string[]; error: string }> = [];
  const failedChunks: Array<{ chunkIndex: number; contactIds: string[]; error: Error; retryCount: number }> = [];

  // Process each chunk with transaction rollback
  for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex++) {
    const chunk = chunks[chunkIndex];
    let success = false;
    let lastError: Error | null = null;

    // Try to process chunk with retries
    let isRetrying = false;
    for (let retryCount = 0; retryCount <= validMaxRetries; retryCount++) {
      try {
        if (retryCount > 0 && !isRetrying) {
          isRetrying = true;
          progress.retryingChunks++;
          onProgress?.(progress);
          console.log(
            `[ChunkedUpdates] Retrying chunk ${chunkIndex + 1}/${chunks.length} ` +
            `(attempt ${retryCount + 1}/${validMaxRetries + 1})`
          );
        }

        // Process chunk in transaction (rollback on error)
        await prisma.$transaction(
          async (tx) => {
            await updateFn(chunk, tx);
          },
          {
            timeout: 30000, // 30 second timeout per chunk
            maxWait: 10000, // 10 second max wait for transaction
          }
        );

        // Success - update progress
        success = true;
        progress.successfulContacts += chunk.length;
        progress.processedContacts += chunk.length;
        progress.completedChunks++;
        if (isRetrying) {
          progress.retryingChunks--;
          isRetrying = false;
        }

        onProgress?.(progress);
        onChunkComplete?.(chunkIndex, true, chunk.length);

        break; // Exit retry loop on success
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        // Log error but continue to retry
        if (retryCount < validMaxRetries) {
          console.warn(
            `[ChunkedUpdates] Chunk ${chunkIndex + 1}/${chunks.length} failed ` +
            `(attempt ${retryCount + 1}/${validMaxRetries + 1}):`,
            lastError.message
          );
          // Wait before retry (exponential backoff)
          await new Promise((resolve) => setTimeout(resolve, 1000 * (retryCount + 1)));
        }
      }
    }

    // If chunk failed after all retries
    if (!success && lastError) {
      progress.failedContacts += chunk.length;
      progress.processedContacts += chunk.length;
      progress.failedChunks++;
      if (isRetrying) {
        progress.retryingChunks--;
      }

      errors.push({
        chunkIndex,
        contactIds: chunk,
        error: lastError.message,
      });

      failedChunks.push({
        chunkIndex,
        contactIds: chunk,
        error: lastError,
        retryCount: validMaxRetries,
      });

      onProgress?.(progress);
      onChunkComplete?.(chunkIndex, false, chunk.length);
      onChunkError?.(chunkIndex, lastError, chunk);

      console.error(
        `[ChunkedUpdates] Chunk ${chunkIndex + 1}/${chunks.length} failed after ${validMaxRetries + 1} attempts:`,
        lastError.message
      );
    }
  }

  return {
    success: progress.failedChunks === 0,
    totalContacts: contactIds.length,
    successfulContacts: progress.successfulContacts,
    failedContacts: progress.failedContacts,
    completedChunks: progress.completedChunks,
    failedChunks: progress.failedChunks,
    errors,
  };
}

/**
 * Retries failed chunks independently from a previous update operation
 * 
 * This function allows you to retry chunks that failed during a previous
 * `updateContactsInChunks` call. It processes each failed chunk with the
 * same retry logic and transaction isolation as the original operation.
 * 
 * Useful for:
 * - Recovering from transient errors after they're resolved
 * - Retrying specific failed chunks without reprocessing successful ones
 * - Manual retry workflows
 * 
 * @param updateFn - Function that performs the update operation (same as original)
 * @param failedChunks - Array of failed chunks from a previous operation
 * @param failedChunks[].chunkIndex - Original chunk index for reference
 * @param failedChunks[].contactIds - Contact IDs in this chunk
 * @param failedChunks[].error - The error that caused the failure
 * @param options - Retry configuration options
 * @param options.maxRetries - Maximum retry attempts per chunk (default: 3)
 * @param options.onProgress - Optional progress callback
 * @param options.onChunkComplete - Optional completion callback
 * @returns Promise resolving to retry results with success/failure counts
 * 
 * @example
 * ```typescript
 * const originalResult = await updateContactsInChunks(updateFn, options);
 * if (originalResult.failedChunks > 0) {
 *   // Retry failed chunks
 *   const retryResult = await retryFailedChunks(
 *     updateFn,
 *     originalResult.errors.map(e => ({
 *       chunkIndex: e.chunkIndex,
 *       contactIds: e.contactIds,
 *       error: new Error(e.error)
 *     })),
 *     { maxRetries: 5 }
 *   );
 * }
 * ```
 */
export async function retryFailedChunks(
  updateFn: (contactIds: string[], tx: Prisma.TransactionClient) => Promise<void>,
  failedChunks: Array<{ chunkIndex: number; contactIds: string[]; error: Error }>,
  options: {
    maxRetries?: number;
    prisma?: PrismaClient; // Optional: Use routed prisma client for multi-DB support
    onProgress?: (progress: ChunkProgress) => void;
    onChunkComplete?: (chunkIndex: number, success: boolean, count: number) => void;
  } = {}
): Promise<ChunkedUpdateResult> {
  const { 
    maxRetries = 3, 
    prisma = defaultPrisma, // Use provided prisma client or default
    onProgress, 
    onChunkComplete 
  } = options;

  // Validate inputs
  if (!Array.isArray(failedChunks)) {
    throw new Error('failedChunks must be an array');
  }

  if (failedChunks.length === 0) {
    return {
      success: true,
      totalContacts: 0,
      successfulContacts: 0,
      failedContacts: 0,
      completedChunks: 0,
      failedChunks: 0,
      errors: [],
    };
  }

  const validMaxRetries = Math.max(0, Math.min(maxRetries || 3, 10)); // Clamp between 0 and 10

  const totalContacts = failedChunks.reduce((sum, chunk) => sum + chunk.contactIds.length, 0);
  const progress: ChunkProgress = {
    totalContacts,
    processedContacts: 0,
    successfulContacts: 0,
    failedContacts: 0,
    completedChunks: 0,
    totalChunks: failedChunks.length,
    failedChunks: 0,
    retryingChunks: 0,
  };

  const errors: Array<{ chunkIndex: number; contactIds: string[]; error: string }> = [];

  // Retry each failed chunk independently
  for (const failedChunk of failedChunks) {
    const { chunkIndex, contactIds } = failedChunk;
    let success = false;
    let lastError: Error | null = null;
    let isRetrying = false;

    for (let retryCount = 0; retryCount <= validMaxRetries; retryCount++) {
      try {
        if (retryCount > 0 && !isRetrying) {
          isRetrying = true;
          progress.retryingChunks++;
          onProgress?.(progress);
          console.log(
            `[ChunkedUpdates] Retrying failed chunk ${chunkIndex} ` +
            `(attempt ${retryCount + 1}/${validMaxRetries + 1})`
          );
        }

        await prisma.$transaction(
          async (tx) => {
            await updateFn(contactIds, tx);
          },
          {
            timeout: 30000,
            maxWait: 10000,
          }
        );

        success = true;
        progress.successfulContacts += contactIds.length;
        progress.processedContacts += contactIds.length;
        progress.completedChunks++;
        if (isRetrying) {
          progress.retryingChunks--;
          isRetrying = false;
        }

        onProgress?.(progress);
        onChunkComplete?.(chunkIndex, true, contactIds.length);

        break;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        if (retryCount < validMaxRetries) {
          console.warn(
            `[ChunkedUpdates] Retry attempt ${retryCount + 1}/${validMaxRetries} failed for chunk ${chunkIndex}:`,
            lastError.message
          );
          await new Promise((resolve) => setTimeout(resolve, 1000 * (retryCount + 1)));
        }
      }
    }

    if (!success && lastError) {
      progress.failedContacts += contactIds.length;
      progress.processedContacts += contactIds.length;
      progress.failedChunks++;
      if (isRetrying) {
        progress.retryingChunks--;
      }

      errors.push({
        chunkIndex,
        contactIds,
        error: lastError.message,
      });

      onProgress?.(progress);
      onChunkComplete?.(chunkIndex, false, contactIds.length);
    }
  }

  return {
    success: progress.failedChunks === 0,
    totalContacts,
    successfulContacts: progress.successfulContacts,
    failedContacts: progress.failedContacts,
    completedChunks: progress.completedChunks,
    failedChunks: progress.failedChunks,
    errors,
  };
}

