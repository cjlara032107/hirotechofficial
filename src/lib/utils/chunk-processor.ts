/**
 * Chunk Processor with Controlled Concurrency
 * 
 * Processes items in chunks with controlled parallelism, memory monitoring,
 * and resource-aware concurrency limiting.
 * 
 * Phase 5: Proper chunking strategy implementation
 */

import { memoryMonitor, type MemoryStats } from './memory-monitor';
import { resourceLimiter, type ResourceType } from './resource-limiter';

export interface ChunkProcessorOptions<T> {
  items: T[];
  chunkSize: number;
  concurrency: number; // Max concurrent chunks to process
  resourceType?: ResourceType; // Resource type for limiting
  onProgress?: (processed: number, total: number) => void;
  onChunkStart?: (chunkIndex: number, chunkSize: number) => void;
  onChunkComplete?: (chunkIndex: number, results: unknown[]) => void;
  onError?: (error: Error, item: T, index: number) => void;
  checkMemory?: boolean; // Enable memory-based backpressure
  memoryThreshold?: number; // Pause if memory usage exceeds this (0-100)
  pauseOnMemoryPressure?: boolean; // Pause processing when memory is high
}

export interface ChunkProcessorResult<T> {
  results: Array<{ item: T; result?: unknown; error?: Error }>;
  processed: number;
  failed: number;
  memoryStats?: MemoryStats;
}

/**
 * Processes items in chunks with controlled concurrency and memory monitoring
 * 
 * This implements Phase 5 chunking strategy:
 * - Processes multiple chunks concurrently (not sequentially)
 * - Limits concurrent chunks to prevent resource exhaustion
 * - Monitors memory and pauses if needed
 * - Uses resource-aware concurrency limiting
 * 
 * @template T - The type of items being processed
 * @param processor - Async function that processes a single item
 * @param options - Configuration options for chunk processing
 * @returns Promise resolving to processing results with statistics
 * 
 * @example
 * ```typescript
 * const results = await processChunks(
 *   async (item) => await processItem(item),
 *   {
 *     items: myItems,
 *     chunkSize: 50,
 *     concurrency: 5,
 *     onProgress: (processed, total) => console.log(`${processed}/${total}`)
 *   }
 * );
 * ```
 */
export async function processChunks<T>(
  processor: (item: T, index: number) => Promise<unknown>,
  options: ChunkProcessorOptions<T>
): Promise<ChunkProcessorResult<T>> {
  const {
    items,
    chunkSize,
    concurrency,
    resourceType = 'api-call',
    onProgress,
    onChunkStart,
    onChunkComplete,
    onError,
    checkMemory = true,
    memoryThreshold = 85,
    pauseOnMemoryPressure = true,
  } = options;

  // Create chunks
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += chunkSize) {
    chunks.push(items.slice(i, i + chunkSize));
  }

  const results: Array<{ item: T; result?: unknown; error?: Error }> = [];
  let processed = 0;
  let failed = 0;

  // Track active chunk promises
  const activeChunks: Promise<void>[] = [];
  let chunkIndex = 0;

  // Process chunks with controlled concurrency
  const processChunk = async (chunk: T[], index: number): Promise<void> => {
    onChunkStart?.(index, chunk.length);

    // Check memory before processing chunk
    if (checkMemory && pauseOnMemoryPressure) {
      const stats = memoryMonitor.getStats();
      if (stats.usagePercent >= memoryThreshold) {
        console.warn(
          `[ChunkProcessor] ⏸️ Pausing chunk ${index + 1}/${chunks.length} - ` +
          `Memory usage: ${stats.usagePercent.toFixed(1)}%`
        );
        
        // Wait for memory to drop below threshold
        await waitForMemoryPressure(memoryThreshold - 10); // Wait until 10% below threshold
      }
    }

    const chunkResults: unknown[] = [];
    
    // Process items in chunk with resource limiting
    const itemPromises = chunk.map(async (item, itemIndex) => {
      const globalIndex = index * chunkSize + itemIndex;
      
      try {
        // Use resource limiter if resource type is specified
        const result = resourceType
          ? await resourceLimiter.execute(resourceType, () => processor(item, globalIndex))
          : await processor(item, globalIndex);
        
        chunkResults.push(result);
        results.push({ item, result });
        processed++;
        
        onProgress?.(processed, items.length);
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        results.push({ item, error: err });
        failed++;
        processed++;
        
        onError?.(err, item, globalIndex);
        onProgress?.(processed, items.length);
      }
    });

    await Promise.all(itemPromises);
    
    onChunkComplete?.(index, chunkResults);

    // Force GC hint after chunk if available
    if (global.gc && index % 10 === 0) {
      // GC every 10 chunks to prevent memory buildup
      memoryMonitor.forceGC();
    }
  };

  // Process chunks with concurrency limit
  while (chunkIndex < chunks.length || activeChunks.length > 0) {
    // Start new chunks up to concurrency limit
    while (
      activeChunks.length < concurrency &&
      chunkIndex < chunks.length
    ) {
      const chunk = chunks[chunkIndex];
      const index = chunkIndex;
      chunkIndex++;

      const chunkPromise = processChunk(chunk, index)
        .finally(() => {
          // Remove from active chunks when done
          const idx = activeChunks.indexOf(chunkPromise);
          if (idx > -1) {
            activeChunks.splice(idx, 1);
          }
        });

      activeChunks.push(chunkPromise);
    }

    // Wait for at least one chunk to complete before starting more
    if (activeChunks.length > 0) {
      await Promise.race(activeChunks);
    }
  }

  // Wait for all remaining chunks
  await Promise.all(activeChunks);

  return {
    results,
    processed,
    failed,
    memoryStats: memoryMonitor.getLastStats() || memoryMonitor.getStats(),
  };
}

/**
 * Waits for memory pressure to decrease below a target threshold
 * 
 * Polls memory usage every second until it drops below the target percentage.
 * Also triggers garbage collection to help reduce memory usage.
 * 
 * @param targetPercent - Target memory usage percentage (0-100)
 * @returns Promise that resolves when memory drops below target
 */
async function waitForMemoryPressure(targetPercent: number): Promise<void> {
  return new Promise((resolve) => {
    const checkInterval = setInterval(() => {
      const stats = memoryMonitor.getStats();
      if (stats.usagePercent < targetPercent) {
        clearInterval(checkInterval);
        resolve();
      }
    }, 1000); // Check every second

    // Force GC to help reduce memory
    memoryMonitor.forceGC();
  });
}

/**
 * Processes chunks with automatic chunk size adjustment based on memory pressure
 * 
 * Dynamically adjusts chunk size based on memory usage:
 * - Reduces chunk size when memory usage is high (>80%)
 * - Increases chunk size when memory usage is low (<50%)
 * - Maintains chunk size within min/max bounds
 * 
 * @template T - The type of items being processed
 * @param processor - Async function that processes a single item
 * @param options - Configuration options with adaptive chunk sizing
 * @returns Promise resolving to processing results with statistics
 * 
 * @example
 * ```typescript
 * const results = await processChunksAdaptive(
 *   async (item) => await processItem(item),
 *   {
 *     items: myItems,
 *     initialChunkSize: 100,
 *     minChunkSize: 10,
 *     maxChunkSize: 500,
 *     concurrency: 5
 *   }
 * );
 * ```
 */
export async function processChunksAdaptive<T>(
  processor: (item: T, index: number) => Promise<unknown>,
  options: Omit<ChunkProcessorOptions<T>, 'chunkSize'> & {
    initialChunkSize: number;
    minChunkSize?: number;
    maxChunkSize?: number;
  }
): Promise<ChunkProcessorResult<T>> {
  const {
    initialChunkSize,
    minChunkSize = 10,
    maxChunkSize = 500,
    ...restOptions
  } = options;

  let currentChunkSize = initialChunkSize;
  const memoryHistory: number[] = [];

  // Process with adaptive chunking
  return processChunks(processor, {
    ...restOptions,
    chunkSize: currentChunkSize,
    onChunkComplete: (chunkIndex, results) => {
      // Monitor memory after each chunk
      const stats = memoryMonitor.getStats();
      memoryHistory.push(stats.usagePercent);

      // Keep only last 5 measurements
      if (memoryHistory.length > 5) {
        memoryHistory.shift();
      }

      // Adjust chunk size based on memory pressure
      const avgMemory = memoryHistory.reduce((a, b) => a + b, 0) / memoryHistory.length;
      
      if (avgMemory > 80 && currentChunkSize > minChunkSize) {
        // Reduce chunk size if memory is high
        currentChunkSize = Math.max(minChunkSize, Math.floor(currentChunkSize * 0.8));
        console.log(
          `[ChunkProcessor] 🔽 Reduced chunk size to ${currentChunkSize} ` +
          `(memory: ${avgMemory.toFixed(1)}%)`
        );
      } else if (avgMemory < 50 && currentChunkSize < maxChunkSize) {
        // Increase chunk size if memory is low
        currentChunkSize = Math.min(maxChunkSize, Math.floor(currentChunkSize * 1.2));
        console.log(
          `[ChunkProcessor] 🔼 Increased chunk size to ${currentChunkSize} ` +
          `(memory: ${avgMemory.toFixed(1)}%)`
        );
      }

      restOptions.onChunkComplete?.(chunkIndex, results);
    },
  });
}

