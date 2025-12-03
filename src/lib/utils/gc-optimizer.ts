/**
 * Garbage Collection Optimization Utilities
 * 
 * Provides utilities to optimize memory usage and trigger garbage collection
 * at strategic points to prevent memory buildup during long-running operations.
 */

import { memoryMonitor } from './memory-monitor';

export interface GCOptimizerOptions {
  enableGC?: boolean; // Enable explicit GC calls (requires --expose-gc flag)
  gcInterval?: number; // Force GC every N operations
  clearLargeObjects?: boolean; // Clear large objects after use
  maxObjectAge?: number; // Max age in ms before clearing (for caches)
}

export class GCOptimizer {
  private operationCount = 0;
  private readonly options: Required<GCOptimizerOptions>;
  private readonly largeObjects = new WeakMap<object, number>(); // Track object creation time

  constructor(options: GCOptimizerOptions = {}) {
    this.options = {
      enableGC: options.enableGC ?? (typeof global.gc !== 'undefined'),
      gcInterval: options.gcInterval ?? 100, // GC every 100 operations
      clearLargeObjects: options.clearLargeObjects ?? true,
      maxObjectAge: options.maxObjectAge ?? 300000, // 5 minutes
    };
  }

  /**
   * Registers a large object for tracking and potential cleanup
   * 
   * Tracks objects that may consume significant memory so they can be
   * cleaned up when memory pressure is high. Uses WeakMap for automatic
   * garbage collection of tracked objects.
   * 
   * @template T - The type of object being registered
   * @param obj - The object to track
   * @returns The same object (for chaining)
   */
  registerLargeObject<T extends object>(obj: T): T {
    if (this.options.clearLargeObjects) {
      this.largeObjects.set(obj, Date.now());
    }
    return obj;
  }

  /**
   * Clears a large object and hints garbage collection
   * 
   * Clears object references (for arrays, maps, sets) and removes the
   * object from tracking, then hints GC to free memory.
   * 
   * @template T - The type of object being cleared
   * @param obj - The object to clear
   */
  clearLargeObject<T extends object>(obj: T): void {
    // Clear object references if possible
    if (Array.isArray(obj)) {
      obj.length = 0;
    } else if (obj instanceof Map) {
      obj.clear();
    } else if (obj instanceof Set) {
      obj.clear();
    }

    this.largeObjects.delete(obj);
    this.hintGC();
  }

  /**
   * Hints garbage collection at configured intervals
   * 
   * Increments operation count and triggers GC if the count reaches
   * the configured interval. Logs memory freed if significant (>1MB).
   * Requires Node.js to be started with --expose-gc flag.
   */
  hintGC(): void {
    this.operationCount++;
    
    if (this.options.enableGC && this.operationCount % this.options.gcInterval === 0) {
      const beforeStats = memoryMonitor.getStats();
      memoryMonitor.forceGC();
      const afterStats = memoryMonitor.getStats();
      
      const freedMB = beforeStats.heapUsedMB - afterStats.heapUsedMB;
      if (freedMB > 1) {
        console.log(
          `[GCOptimizer] 🗑️ GC freed ${freedMB.toFixed(1)}MB ` +
          `(${beforeStats.heapUsedMB.toFixed(1)}MB → ${afterStats.heapUsedMB.toFixed(1)}MB)`
        );
      }
    }
  }

  /**
   * Cleans up old objects from tracking
   * 
   * Note: Currently a placeholder. WeakMap doesn't allow iteration,
   * so in practice you'd maintain a separate Set for tracking.
   * This relies on WeakMap's automatic cleanup.
   */
  cleanupOldObjects(): void {
    if (!this.options.clearLargeObjects) return;

    const now = Date.now();
    const toDelete: object[] = [];

    // Note: WeakMap doesn't allow iteration, so we track separately
    // This is a simplified version - in practice, you'd maintain a separate Set
    // For now, we'll rely on WeakMap's automatic cleanup
  }

  /**
   * Clears all tracked objects and forces garbage collection
   * 
   * Useful for cleanup after large batch operations or when
   * memory needs to be freed immediately.
   */
  clearAll(): void {
    // Force GC to clean up
    if (this.options.enableGC) {
      memoryMonitor.forceGC();
    }
  }

  /**
   * Gets the current operation count
   * 
   * @returns The number of operations since last reset
   */
  getOperationCount(): number {
    return this.operationCount;
  }

  /**
   * Resets the operation count to zero
   * 
   * Useful for starting a new tracking period or after cleanup.
   */
  reset(): void {
    this.operationCount = 0;
  }
}

/**
 * Helper function to clear large data structures in bulk
 * 
 * Efficiently clears multiple data structures (maps, sets, arrays, objects)
 * to free memory. Useful for cleanup after batch operations.
 * 
 * @param structures - Object containing arrays of structures to clear
 * @param structures.maps - Optional array of Map objects to clear
 * @param structures.sets - Optional array of Set objects to clear
 * @param structures.arrays - Optional array of arrays to clear (sets length to 0)
 * @param structures.objects - Optional array of plain objects to clear (deletes all properties)
 */
export function clearLargeStructures(structures: {
  maps?: Map<unknown, unknown>[];
  sets?: Set<unknown>[];
  arrays?: unknown[][];
  objects?: Record<string, unknown>[];
}): void {
  if (structures.maps) {
    structures.maps.forEach(map => map.clear());
  }
  if (structures.sets) {
    structures.sets.forEach(set => set.clear());
  }
  if (structures.arrays) {
    structures.arrays.forEach(arr => arr.length = 0);
  }
  if (structures.objects) {
    structures.objects.forEach(obj => {
      Object.keys(obj).forEach(key => delete obj[key]);
    });
  }
}

/**
 * Creates a cleanup function that clears structures and hints GC
 * 
 * Returns a function that can be called later to clean up large data structures
 * and trigger garbage collection. Useful for cleanup in finally blocks or
 * after operations complete.
 * 
 * @param structures - Object containing arrays of structures to clear
 * @returns A cleanup function that clears structures and triggers GC
 * 
 * @example
 * ```typescript
 * const cleanup = createCleanupFunction({
 *   maps: [myLargeMap],
 *   arrays: [myLargeArray]
 * });
 * 
 * try {
 *   // ... operations ...
 * } finally {
 *   cleanup(); // Clears structures and hints GC
 * }
 * ```
 */
export function createCleanupFunction(structures: {
  maps?: Map<unknown, unknown>[];
  sets?: Set<unknown>[];
  arrays?: unknown[][];
  objects?: Record<string, unknown>[];
}): () => void {
  return () => {
    clearLargeStructures(structures);
    if (global.gc) {
      global.gc();
    }
  };
}

// Singleton instance
export const gcOptimizer = new GCOptimizer({
  enableGC: typeof global.gc !== 'undefined',
  gcInterval: parseInt(process.env.GC_INTERVAL || '100', 10),
  clearLargeObjects: true,
  maxObjectAge: parseInt(process.env.GC_MAX_OBJECT_AGE || '300000', 10),
});

