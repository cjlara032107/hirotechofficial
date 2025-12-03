/**
 * Memory Monitoring Utility
 * 
 * Monitors memory usage and provides backpressure mechanisms
 * to prevent memory exhaustion during large batch operations.
 */

export interface MemoryStats {
  heapUsed: number;
  heapTotal: number;
  external: number;
  rss: number;
  heapUsedMB: number;
  heapTotalMB: number;
  rssMB: number;
  usagePercent: number;
}

export interface MemoryThresholds {
  warning: number; // Percentage (0-100) - warn when exceeded
  critical: number; // Percentage (0-100) - pause processing when exceeded
  maxHeapMB?: number; // Optional absolute heap limit in MB
}

export class MemoryMonitor {
  private readonly thresholds: MemoryThresholds;
  private readonly checkInterval: number;
  private intervalId: NodeJS.Timeout | null = null;
  private onWarning?: (stats: MemoryStats) => void;
  private onCritical?: (stats: MemoryStats) => void;
  private lastStats: MemoryStats | null = null;

  constructor(
    thresholds: MemoryThresholds = {
      warning: 70, // Warn at 70% memory usage
      critical: 85, // Pause at 85% memory usage
    },
    checkInterval: number = 5000 // Check every 5 seconds
  ) {
    this.thresholds = thresholds;
    this.checkInterval = checkInterval;
  }

  /**
   * Gets current memory usage statistics from Node.js process
   * 
   * @returns Memory statistics including heap usage, RSS, and usage percentage
   */
  getStats(): MemoryStats {
    const usage = process.memoryUsage();
    const heapUsedMB = usage.heapUsed / 1024 / 1024;
    const heapTotalMB = usage.heapTotal / 1024 / 1024;
    const rssMB = usage.rss / 1024 / 1024;
    const usagePercent = (usage.heapUsed / usage.heapTotal) * 100;

    return {
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      external: usage.external,
      rss: usage.rss,
      heapUsedMB,
      heapTotalMB,
      rssMB,
      usagePercent,
    };
  }

  /**
   * Checks if current memory usage exceeds the warning threshold
   * 
   * @returns True if memory usage is at or above the warning threshold
   */
  isAboveWarning(): boolean {
    const stats = this.getStats();
    return stats.usagePercent >= this.thresholds.warning;
  }

  /**
   * Checks if current memory usage exceeds the critical threshold
   * 
   * Checks both percentage-based threshold and optional absolute heap limit.
   * 
   * @returns True if memory usage is at or above the critical threshold
   */
  isAboveCritical(): boolean {
    const stats = this.getStats();
    const isPercentCritical = stats.usagePercent >= this.thresholds.critical;
    
    if (this.thresholds.maxHeapMB) {
      const isAbsoluteCritical = stats.heapUsedMB >= this.thresholds.maxHeapMB;
      return isPercentCritical || isAbsoluteCritical;
    }
    
    return isPercentCritical;
  }

  /**
   * Gets the current memory pressure level based on usage percentage
   * 
   * Levels:
   * - low: < 50%
   * - medium: 50-69%
   * - high: 70-84% (warning threshold)
   * - critical: >= 85% (critical threshold)
   * 
   * @returns Memory pressure level as a string
   */
  getPressureLevel(): 'low' | 'medium' | 'high' | 'critical' {
    if (this.isAboveCritical()) return 'critical';
    if (this.isAboveWarning()) return 'high';
    
    const stats = this.getStats();
    if (stats.usagePercent >= 50) return 'medium';
    return 'low';
  }

  /**
   * Starts continuous memory monitoring with callbacks
   * 
   * Checks memory usage at the configured interval and triggers callbacks
   * when thresholds are exceeded. Stops any existing monitoring first.
   * 
   * @param onWarning - Optional callback triggered when warning threshold is exceeded
   * @param onCritical - Optional callback triggered when critical threshold is exceeded
   */
  startMonitoring(
    onWarning?: (stats: MemoryStats) => void,
    onCritical?: (stats: MemoryStats) => void
  ): void {
    this.onWarning = onWarning;
    this.onCritical = onCritical;

    if (this.intervalId) {
      this.stopMonitoring();
    }

    this.intervalId = setInterval(() => {
      const stats = this.getStats();
      this.lastStats = stats;

      if (this.isAboveCritical()) {
        console.warn(
          `[MemoryMonitor] 🚨 CRITICAL memory usage: ${stats.usagePercent.toFixed(1)}% ` +
          `(${stats.heapUsedMB.toFixed(1)}MB / ${stats.heapTotalMB.toFixed(1)}MB)`
        );
        this.onCritical?.(stats);
      } else if (this.isAboveWarning()) {
        console.warn(
          `[MemoryMonitor] ⚠️ High memory usage: ${stats.usagePercent.toFixed(1)}% ` +
          `(${stats.heapUsedMB.toFixed(1)}MB / ${stats.heapTotalMB.toFixed(1)}MB)`
        );
        this.onWarning?.(stats);
      }
    }, this.checkInterval);
  }

  /**
   * Stops continuous memory monitoring
   * 
   * Clears the monitoring interval if one is active.
   */
  stopMonitoring(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /**
   * Forces garbage collection if available
   * 
   * Requires Node.js to be started with the --expose-gc flag.
   * 
   * @returns True if GC was triggered, false if not available
   */
  forceGC(): boolean {
    if (global.gc) {
      global.gc();
      return true;
    }
    return false;
  }

  /**
   * Gets the last recorded memory statistics from monitoring
   * 
   * Returns null if monitoring has never been started or no stats have been recorded.
   * 
   * @returns Last recorded memory stats or null
   */
  getLastStats(): MemoryStats | null {
    return this.lastStats;
  }

  /**
   * Formats memory statistics as a human-readable string
   * 
   * @param stats - Optional memory stats to format. If not provided, uses current stats.
   * @returns Formatted string with heap and RSS information
   */
  formatStats(stats?: MemoryStats): string {
    const s = stats || this.getStats();
    return `Heap: ${s.heapUsedMB.toFixed(1)}MB / ${s.heapTotalMB.toFixed(1)}MB ` +
           `(${s.usagePercent.toFixed(1)}%) | RSS: ${s.rssMB.toFixed(1)}MB`;
  }
}

// Singleton instance
export const memoryMonitor = new MemoryMonitor(
  {
    warning: parseFloat(process.env.MEMORY_WARNING_THRESHOLD || '70'),
    critical: parseFloat(process.env.MEMORY_CRITICAL_THRESHOLD || '85'),
    maxHeapMB: process.env.MEMORY_MAX_HEAP_MB 
      ? parseFloat(process.env.MEMORY_MAX_HEAP_MB) 
      : undefined,
  },
  parseFloat(process.env.MEMORY_CHECK_INTERVAL || '5000')
);

