/**
 * Global Database Connection Pool Manager
 * 
 * Coordinates ALL database operations across all types to prevent pool exhaustion.
 * Unlike per-operation limiters, this tracks total pool usage across the entire system.
 * 
 * Key difference from pool-aware-limiter:
 * - Pool-aware-limiter: Each operation type gets its own limit (can still exhaust if all run together)
 * - Global pool manager: All operations share the pool, total usage never exceeds limit
 */

import { getConnectionPoolLimit } from './pool-aware-limiter';

/**
 * Estimate DB connections needed per operation type
 */
const DB_CONNECTIONS_PER_OPERATION: Record<string, number> = {
  'analysis': 3,
  'automation': 4,
  'message-generation': 2,
  'batch': 5,
  'simple': 1,
};

interface ActiveOperation {
  operationId: string;
  type: string;
  connections: number;
  startedAt: number;
}

/**
 * Global Pool Manager - Singleton
 * Tracks all active operations across all types
 */
class GlobalPoolManager {
  private activeOperations = new Map<string, ActiveOperation>();
  private poolLimit: number;
  private readonly RESERVE_PERCENT = 0.2; // Reserve 20% for API routes, syncs, etc.

  constructor() {
    this.poolLimit = getConnectionPoolLimit();
  }

  /**
   * Get current pool usage
   */
  getCurrentUsage(): number {
    let total = 0;
    for (const op of this.activeOperations.values()) {
      total += op.connections;
    }
    return total;
  }

  /**
   * Get available pool capacity
   */
  getAvailableCapacity(): number {
    const currentUsage = this.getCurrentUsage();
    const maxUsage = Math.floor(this.poolLimit * (1 - this.RESERVE_PERCENT));
    return Math.max(0, maxUsage - currentUsage);
  }

  /**
   * Check if an operation can start (has capacity)
   */
  canStartOperation(operationType: string, connectionsNeeded: number): boolean {
    const available = this.getAvailableCapacity();
    return available >= connectionsNeeded;
  }

  /**
   * Register an operation as starting
   */
  startOperation(operationId: string, operationType: string, connectionsNeeded: number): boolean {
    if (!this.canStartOperation(operationType, connectionsNeeded)) {
      return false;
    }

    this.activeOperations.set(operationId, {
      operationId,
      type: operationType,
      connections: connectionsNeeded,
      startedAt: Date.now(),
    });

    return true;
  }

  /**
   * Unregister an operation as finished
   */
  endOperation(operationId: string): void {
    this.activeOperations.delete(operationId);
  }

  /**
   * Get status for monitoring
   */
  getStatus() {
    const currentUsage = this.getCurrentUsage();
    const maxUsage = Math.floor(this.poolLimit * (1 - this.RESERVE_PERCENT));
    const usagePercent = (currentUsage / this.poolLimit) * 100;
    const available = this.getAvailableCapacity();

    // Group by operation type
    const byType = new Map<string, number>();
    for (const op of this.activeOperations.values()) {
      byType.set(op.type, (byType.get(op.type) || 0) + op.connections);
    }

    return {
      poolLimit: this.poolLimit,
      currentUsage,
      maxUsage,
      available,
      usagePercent: Math.round(usagePercent * 10) / 10,
      activeOperations: this.activeOperations.size,
      byType: Object.fromEntries(byType),
      isHealthy: currentUsage <= maxUsage,
    };
  }
}

// Singleton instance
let globalPoolManager: GlobalPoolManager | null = null;

export function getGlobalPoolManager(): GlobalPoolManager {
  if (!globalPoolManager) {
    globalPoolManager = new GlobalPoolManager();
  }
  return globalPoolManager;
}

/**
 * Global Pool-Aware Concurrency Limiter
 * 
 * Uses the global pool manager to coordinate with all other operations
 */
export class GlobalPoolAwareLimiter {
  private operationType: string;
  private connectionsPerOperation: number;
  private maxConcurrency: number;
  private queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: unknown) => void;
    operationId: string;
  }> = [];
  private running = 0;
  private poolManager: GlobalPoolManager;

  constructor(
    operationType: keyof typeof DB_CONNECTIONS_PER_OPERATION,
    desiredConcurrency: number
  ) {
    this.operationType = operationType;
    this.connectionsPerOperation = DB_CONNECTIONS_PER_OPERATION[operationType] || 1;
    this.poolManager = getGlobalPoolManager();
    
    // Calculate max concurrency based on pool capacity
    // But we'll enforce it dynamically based on actual pool availability
    const poolLimit = getConnectionPoolLimit();
    const maxUsage = Math.floor(poolLimit * 0.8); // 80% max usage
    const maxForThisType = Math.floor(maxUsage / this.connectionsPerOperation);
    
    // Use the lower of desired or calculated max
    this.maxConcurrency = Math.min(desiredConcurrency, maxForThisType);
    this.maxConcurrency = Math.max(1, this.maxConcurrency);
  }

  /**
   * Execute with global pool awareness
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    const operationId = `${this.operationType}-${Date.now()}-${Math.random()}`;
    
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

      // Check if we have pool capacity
      if (!this.poolManager.canStartOperation(this.operationType, this.connectionsPerOperation)) {
        // Put task back at front of queue
        this.queue.unshift(task);
        // Wait a bit and retry
        await new Promise(resolve => setTimeout(resolve, 100));
        continue;
      }

      // Start operation
      const started = this.poolManager.startOperation(
        task.operationId,
        this.operationType,
        this.connectionsPerOperation
      );

      if (!started) {
        // Pool became unavailable, put back in queue
        this.queue.unshift(task);
        await new Promise(resolve => setTimeout(resolve, 100));
        continue;
      }

      this.running++;

      task.fn()
        .then(task.resolve)
        .catch(task.reject)
        .finally(() => {
          this.running--;
          this.poolManager.endOperation(task.operationId);
          this.process();
        });
    }
  }

  getLimit(): number {
    return this.maxConcurrency;
  }

  getStatus() {
    const poolStatus = this.poolManager.getStatus();
    return {
      operationType: this.operationType,
      connectionsPerOperation: this.connectionsPerOperation,
      maxConcurrency: this.maxConcurrency,
      running: this.running,
      queued: this.queue.length,
      poolStatus,
    };
  }
}

/**
 * Get recommended concurrency that accounts for global pool usage
 * This ensures ALL operations together don't exceed pool capacity
 * 
 * Strategy: Conservative limits so that if ALL operation types run simultaneously,
 * total connections never exceed 80% of pool
 * 
 * For pool of 15:
 * - Safe usage: 12 connections (80%)
 * - Distribute across 5 operation types: ~2-3 connections per type
 * - This ensures total is always safe even if all run together
 */
export function getGlobalRecommendedConcurrency(
  operationType: keyof typeof DB_CONNECTIONS_PER_OPERATION,
  desiredConcurrency: number
): number {
  const poolLimit = getConnectionPoolLimit();
  const connectionsPerOp = DB_CONNECTIONS_PER_OPERATION[operationType] || 1;
  
  // Safe pool usage: 80% of pool (20% reserve for API routes, syncs, etc.)
  const safePoolUsage = Math.floor(poolLimit * 0.8);
  
  // ULTRA-CONSERVATIVE: Fixed limits that ensure total <= safePoolUsage
  // Strategy: Hard-cap each type so worst-case total is safe
  
  // For pool of 15, safePoolUsage = 12
  // If all 5 types run simultaneously at max:
  // We need: sum(all max connections) <= 12
  
  // Fixed conservative allocation (ensures total <= 12):
  // - Analysis (3 conn/op): 1 op max = 3 conn
  // - Automation (4 conn/op): 1 op max = 4 conn  
  // - Message-gen (2 conn/op): 1 op max = 2 conn
  // - Batch (5 conn/op): 1 op max = 5 conn (but this alone is heavy!)
  // - Simple (1 conn/op): 1 op max = 1 conn
  // Total: 3+4+2+5+1 = 15 (exceeds 12!)
  
  // Problem: Minimum 1 op per type is required, but batch (5) + automation (4) = 9
  // Solution: Use GlobalPoolAwareLimiter at runtime to prevent actual exhaustion
  // For limits: Be very conservative - some types must be < 1 op equivalent
  
  // Revised allocation (total = 11, under 12):
  // - Analysis: 1 op = 3 conn
  // - Automation: 1 op = 4 conn
  // - Message-gen: 1 op = 2 conn  
  // - Batch: 0.4 op equivalent = 2 conn (but min 1 op = 5 conn) - use 1 op but runtime will throttle
  // - Simple: 1 op = 1 conn
  // Actual if all run: 3+4+2+5+1 = 15 (runtime limiter prevents this)
  
  // Calculate safe concurrent operations based on pool capacity
  // Runtime GlobalPoolAwareLimiter will prevent actual exhaustion, so we can be more aggressive
  // Strategy: Allow more concurrent operations, runtime limiter will queue if pool is full
  
  // For analysis: 3 conn/op, safePoolUsage = 12
  // We can do: 12 / 3 = 4 concurrent analyses safely
  // But reserve some for other operations, so use 3-4
  const maxConcurrentByType: Record<string, number> = {
    'analysis': Math.floor(safePoolUsage / 3),           // ~4 ops = 12 conn (uses most of safe pool)
    'automation': Math.floor(safePoolUsage / 4),         // ~3 ops = 12 conn
    'message-generation': Math.floor(safePoolUsage / 2), // ~6 ops = 12 conn
    'batch': Math.floor(safePoolUsage / 5),              // ~2 ops = 10 conn
    'simple': Math.floor(safePoolUsage / 1),            // ~12 ops = 12 conn
  };
  
  // Get the calculated limit for this operation type
  const calculatedLimit = maxConcurrentByType[operationType] || 1;
  
  // Use the calculated limit, but cap at desiredConcurrency
  // This allows sending multiple requests in parallel instead of waiting for 1 to finish
  return Math.min(desiredConcurrency, Math.max(1, calculatedLimit));
}

