/**
 * Resource-Aware Concurrency Limiter
 * 
 * Limits concurrent operations per resource type to prevent resource exhaustion.
 * Tracks usage across different resource types (API calls, DB operations, etc.)
 * and enforces limits per resource.
 */

export type ResourceType = 
  | 'api-call'
  | 'db-query'
  | 'db-write'
  | 'ai-request'
  | 'facebook-api'
  | 'file-io'
  | 'network';

export interface ResourceLimits {
  [key: string]: number; // resource type -> max concurrent
}

export interface ResourceUsage {
  resourceType: ResourceType;
  current: number;
  max: number;
  available: number;
}

export class ResourceLimiter {
  private limits: Map<ResourceType, number> = new Map();
  private current: Map<ResourceType, number> = new Map();
  private queues: Map<ResourceType, Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: unknown) => void;
  }>> = new Map();

  constructor(limits: ResourceLimits = {}) {
    // Set default limits if not provided
    const defaultLimits: ResourceLimits = {
      'api-call': parseInt(process.env.MAX_CONCURRENT_API_CALLS || '50', 10),
      'db-query': parseInt(process.env.MAX_CONCURRENT_DB_QUERIES || '30', 10),
      'db-write': parseInt(process.env.MAX_CONCURRENT_DB_WRITES || '20', 10),
      'ai-request': parseInt(process.env.MAX_CONCURRENT_AI_REQUESTS || '50', 10),
      'facebook-api': parseInt(process.env.MAX_CONCURRENT_FACEBOOK_API || '30', 10),
      'file-io': parseInt(process.env.MAX_CONCURRENT_FILE_IO || '10', 10),
      'network': parseInt(process.env.MAX_CONCURRENT_NETWORK || '50', 10),
      ...limits,
    };

    for (const [resourceType, limit] of Object.entries(defaultLimits)) {
      this.limits.set(resourceType as ResourceType, limit);
      this.current.set(resourceType as ResourceType, 0);
      this.queues.set(resourceType as ResourceType, []);
    }
  }

  /**
   * Executes a function with resource-based concurrency limiting
   * 
   * If the resource type is at capacity, the function is queued and executed
   * when capacity becomes available. This prevents resource exhaustion by
   * limiting concurrent operations per resource type.
   * 
   * @template T - The return type of the function
   * @param resourceType - The type of resource being used (e.g., 'api-call', 'db-query')
   * @param fn - The async function to execute
   * @returns Promise resolving to the function's result
   * 
   * @example
   * ```typescript
   * const result = await resourceLimiter.execute('api-call', async () => {
   *   return await fetch('https://api.example.com/data');
   * });
   * ```
   */
  async execute<T>(
    resourceType: ResourceType,
    fn: () => Promise<T>
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const limit = this.limits.get(resourceType) || 10;
      const current = this.current.get(resourceType) || 0;

      // If under limit, execute immediately
      if (current < limit) {
        this.current.set(resourceType, current + 1);
        
        fn()
          .then((result) => {
            this.current.set(resourceType, (this.current.get(resourceType) || 0) - 1);
            this.processQueue(resourceType);
            resolve(result);
          })
          .catch((error) => {
            this.current.set(resourceType, (this.current.get(resourceType) || 0) - 1);
            this.processQueue(resourceType);
            reject(error);
          });
      } else {
        // Queue the request
        const queue = this.queues.get(resourceType) || [];
        queue.push({
          fn: fn as () => Promise<unknown>,
          resolve: resolve as (value: unknown) => void,
          reject: reject as (error: unknown) => void,
        });
        this.queues.set(resourceType, queue);
      }
    });
  }

  /**
   * Process queued requests for a resource type
   */
  private processQueue(resourceType: ResourceType): void {
    const limit = this.limits.get(resourceType) || 10;
    const current = this.current.get(resourceType) || 0;
    const queue = this.queues.get(resourceType) || [];

    while (current < limit && queue.length > 0) {
      const task = queue.shift();
      if (!task) break;

      this.current.set(resourceType, current + 1);

      task.fn()
        .then((result) => {
          this.current.set(resourceType, (this.current.get(resourceType) || 0) - 1);
          this.processQueue(resourceType);
          task.resolve(result);
        })
        .catch((error) => {
          this.current.set(resourceType, (this.current.get(resourceType) || 0) - 1);
          this.processQueue(resourceType);
          task.reject(error);
        });
    }
  }

  /**
   * Get current usage for a resource type
   */
  getUsage(resourceType: ResourceType): ResourceUsage {
    const current = this.current.get(resourceType) || 0;
    const max = this.limits.get(resourceType) || 10;
    
    return {
      resourceType,
      current,
      max,
      available: max - current,
    };
  }

  /**
   * Get usage for all resource types
   */
  getAllUsage(): ResourceUsage[] {
    const usage: ResourceUsage[] = [];
    for (const resourceType of Array.from(this.limits.keys())) {
      usage.push(this.getUsage(resourceType));
    }
    return usage;
  }

  /**
   * Check if a resource type has available capacity
   */
  hasCapacity(resourceType: ResourceType): boolean {
    const usage = this.getUsage(resourceType);
    return usage.available > 0;
  }

  /**
   * Get queue size for a resource type
   */
  getQueueSize(resourceType: ResourceType): number {
    return (this.queues.get(resourceType) || []).length;
  }

  /**
   * Get total queue size across all resources
   */
  getTotalQueueSize(): number {
    let total = 0;
    for (const queue of Array.from(this.queues.values())) {
      total += queue.length;
    }
    return total;
  }

  /**
   * Update limit for a resource type
   */
  setLimit(resourceType: ResourceType, limit: number): void {
    this.limits.set(resourceType, limit);
    if (!this.current.has(resourceType)) {
      this.current.set(resourceType, 0);
    }
    if (!this.queues.has(resourceType)) {
      this.queues.set(resourceType, []);
    }
    // Process queue with new limit
    this.processQueue(resourceType);
  }

  /**
   * Get statistics
   */
  getStats(): {
    limits: Record<string, number>;
    current: Record<string, number>;
    queues: Record<string, number>;
    totalQueued: number;
  } {
    const limits: Record<string, number> = {};
    const current: Record<string, number> = {};
    const queues: Record<string, number> = {};

    for (const [resourceType, limit] of Array.from(this.limits.entries())) {
      limits[resourceType] = limit;
      current[resourceType] = this.current.get(resourceType) || 0;
      queues[resourceType] = this.getQueueSize(resourceType);
    }

    return {
      limits,
      current,
      queues,
      totalQueued: this.getTotalQueueSize(),
    };
  }
}

// Singleton instance
export const resourceLimiter = new ResourceLimiter();

