/**
 * Pool-Aware Concurrency Limiter
 * 
 * Prevents database connection pool exhaustion by:
 * 1. Tracking estimated DB connection usage per operation
 * 2. Limiting concurrent DB-heavy operations based on pool capacity
 * 3. Allowing high concurrency for API-only operations (no DB connections)
 * 
 * Key insight: API calls (AI generation) don't use DB connections,
 * so they can run at high concurrency. DB operations use 2-3 connections each.
 */

/**
 * Get the current database connection pool limit
 * Extracts from DATABASE_URL or uses defaults
 */
export function getConnectionPoolLimit(): number {
  const databaseUrl = process.env.DATABASE_URL || '';
  
  // Extract connection_limit from URL
  const match = databaseUrl.match(/connection_limit=(\d+)/);
  if (match) {
    return parseInt(match[1], 10);
  }
  
  // Defaults based on environment
  const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
  return isVercel ? 10 : 15;
}

/**
 * Estimate DB connections needed per operation type
 */
const DB_CONNECTIONS_PER_OPERATION: Record<string, number> = {
  // Analysis operations: read contact, read conversations, write analysis result
  'analysis': 3,
  // Automation: read contact, read rule, write execution record, send message
  'automation': 4,
  // Message generation: read contact, write message
  'message-generation': 2,
  // Batch operations: multiple queries
  'batch': 5,
  // Simple read/write
  'simple': 1,
};

/**
 * Pool-Aware Concurrency Limiter
 * 
 * Limits concurrent operations based on:
 * - Total pool size
 * - Estimated connections per operation
 * - Current pool usage
 */
export class PoolAwareLimiter {
  private activeOperations = new Map<string, number>();
  private poolLimit: number;
  private connectionsPerOperation: number;
  private operationType: string;
  
  constructor(
    operationType: keyof typeof DB_CONNECTIONS_PER_OPERATION,
    maxConcurrency?: number
  ) {
    this.operationType = operationType;
    this.connectionsPerOperation = DB_CONNECTIONS_PER_OPERATION[operationType] || 1;
    this.poolLimit = getConnectionPoolLimit();
    
    // Calculate safe concurrency: leave 20% buffer for other operations
    const safePoolUsage = Math.floor(this.poolLimit * 0.8);
    const calculatedMax = Math.floor(safePoolUsage / this.connectionsPerOperation);
    
    // Use provided maxConcurrency if lower, otherwise use calculated safe limit
    this.maxConcurrency = maxConcurrency 
      ? Math.min(maxConcurrency, calculatedMax)
      : calculatedMax;
    
    // Ensure minimum of 1
    this.maxConcurrency = Math.max(1, this.maxConcurrency);
  }
  
  private maxConcurrency: number;
  private queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: unknown) => void;
    operationId: string;
  }> = [];
  private running = 0;
  
  /**
   * Get the current concurrency limit
   */
  getLimit(): number {
    return this.maxConcurrency;
  }
  
  /**
   * Get current pool usage estimate
   */
  getEstimatedPoolUsage(): number {
    let totalConnections = 0;
    for (const count of this.activeOperations.values()) {
      totalConnections += count * this.connectionsPerOperation;
    }
    return totalConnections;
  }
  
  /**
   * Execute a function with pool-aware concurrency limiting
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    const operationId = `${Date.now()}-${Math.random()}`;
    
    return new Promise<T>((resolve, reject) => {
      this.queue.push({
        fn: fn as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject: reject as (error: unknown) => void,
        operationId,
      });
      this.process();
    });
  }
  
  private async process() {
    while (this.running < this.maxConcurrency && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;
      
      this.running++;
      this.activeOperations.set(task.operationId, 1);
      
      task.fn()
        .then(task.resolve)
        .catch(task.reject)
        .finally(() => {
          this.running--;
          this.activeOperations.delete(task.operationId);
          this.process();
        });
    }
  }
  
  /**
   * Get pool status for monitoring
   */
  getStatus() {
    const estimatedUsage = this.getEstimatedPoolUsage();
    const usagePercent = (estimatedUsage / this.poolLimit) * 100;
    
    return {
      poolLimit: this.poolLimit,
      estimatedUsage,
      usagePercent: Math.round(usagePercent * 10) / 10,
      maxConcurrency: this.maxConcurrency,
      running: this.running,
      queued: this.queue.length,
      operationType: this.operationType,
      connectionsPerOperation: this.connectionsPerOperation,
      isHealthy: usagePercent < 80, // Healthy if using <80% of pool
    };
  }
}

/**
 * Create a pool-aware limiter for a specific operation type
 * Automatically calculates safe concurrency based on pool size
 */
export function createPoolAwareLimiter(
  operationType: keyof typeof DB_CONNECTIONS_PER_OPERATION,
  maxConcurrency?: number
): PoolAwareLimiter {
  return new PoolAwareLimiter(operationType, maxConcurrency);
}

/**
 * Get recommended concurrency for an operation type
 * This can be used to set limits in dynamic-concurrency.ts
 */
export function getRecommendedConcurrency(
  operationType: keyof typeof DB_CONNECTIONS_PER_OPERATION,
  desiredConcurrency?: number
): number {
  const poolLimit = getConnectionPoolLimit();
  const connectionsPerOp = DB_CONNECTIONS_PER_OPERATION[operationType] || 1;
  
  // Leave 20% buffer for other operations (API routes, syncs, etc.)
  const safePoolUsage = Math.floor(poolLimit * 0.8);
  const calculatedMax = Math.floor(safePoolUsage / connectionsPerOp);
  
  if (desiredConcurrency) {
    // Use the lower of desired or calculated safe limit
    return Math.min(desiredConcurrency, calculatedMax);
  }
  
  return Math.max(1, calculatedMax);
}

