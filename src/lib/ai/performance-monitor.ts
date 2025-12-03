/**
 * Performance Monitor for AI API Calls
 * 
 * Tracks metrics, logs performance, and provides insights
 * into AI call performance patterns.
 * 
 * Now includes database persistence for long-term analysis.
 */

import { logPerformanceMetric } from '@/lib/logging/performance-logger';

export interface PerformanceMetrics {
  operation: string;
  duration: number;
  success: boolean;
  errorType?: string;
  timestamp: number;
  apiKeyId?: string;
  requestId?: string;
  priority?: string;
}

export interface AggregatedMetrics {
  operation: string;
  totalCalls: number;
  successCount: number;
  failureCount: number;
  averageDuration: number;
  p50Duration: number;
  p95Duration: number;
  p99Duration: number;
  minDuration: number;
  maxDuration: number;
  errorRate: number;
  last24Hours: {
    totalCalls: number;
    successCount: number;
    failureCount: number;
    averageDuration: number;
  };
}

export class PerformanceMonitor {
  private metrics: PerformanceMetrics[] = [];
  private readonly maxMetrics = 10000; // Keep last 10k metrics
  private readonly aggregationWindow = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Record a performance metric
   */
  record(metric: PerformanceMetrics): void {
    this.metrics.push(metric);

    // Trim old metrics if we exceed max
    if (this.metrics.length > this.maxMetrics) {
      this.metrics = this.metrics.slice(-this.maxMetrics);
    }

    // Log important metrics
    this.logMetric(metric);

    // Persist to database (non-blocking)
    logPerformanceMetric({
      operation: metric.operation,
      duration: metric.duration,
      success: metric.success,
      errorType: metric.errorType,
      apiKeyId: metric.apiKeyId,
      requestId: metric.requestId,
      priority: metric.priority,
    }).catch((error) => {
      // Silently fail - database logging should not break the app
      console.error('[PerformanceMonitor] Failed to persist metric:', error);
    });
  }

  /**
   * Log metric with appropriate level
   */
  private logMetric(metric: PerformanceMetrics): void {
    const durationStr = `${metric.duration}ms`;
    const status = metric.success ? '✅' : '❌';
    const errorInfo = metric.errorType ? ` | Error: ${metric.errorType}` : '';
    const keyInfo = metric.apiKeyId
      ? ` | Key: ${metric.apiKeyId.substring(0, 8)}...`
      : '';
    const priorityInfo = metric.priority ? ` | Priority: ${metric.priority}` : '';

    const logMessage = `[PerformanceMonitor] ${status} ${metric.operation} | Duration: ${durationStr}${keyInfo}${priorityInfo}${errorInfo}`;

    if (metric.success) {
      // Log slow requests as warnings
      if (metric.duration > 10000) {
        console.warn(`${logMessage} | ⚠️ Slow request`);
      } else if (metric.duration > 5000) {
        console.warn(`${logMessage} | ⚠️ Moderate latency`);
      } else {
        console.log(logMessage);
      }
    } else {
      console.error(logMessage);
    }

    // Log performance warnings for very slow requests
    if (metric.duration > 30000) {
      console.error(
        `[PerformanceMonitor] 🐌 Very slow request detected: ${metric.operation} took ${durationStr}`
      );
    }
  }

  /**
   * Get metrics for a specific time period
   */
  getMetricsForPeriod(startTime: number, endTime: number): PerformanceMetrics[] {
    return this.metrics.filter(
      (metric) => metric.timestamp >= startTime && metric.timestamp <= endTime
    );
  }

  /**
   * Get aggregated metrics for an operation
   */
  getMetrics(operation: string): AggregatedMetrics | null {
    const operationMetrics = this.metrics.filter(
      (m) => m.operation === operation
    );

    if (operationMetrics.length === 0) {
      return null;
    }

    const durations = operationMetrics
      .map((m) => m.duration)
      .sort((a, b) => a - b);
    const successCount = operationMetrics.filter((m) => m.success).length;
    const failureCount = operationMetrics.length - successCount;

    // Calculate percentiles
    const p50 = this.percentile(durations, 50);
    const p95 = this.percentile(durations, 95);
    const p99 = this.percentile(durations, 99);

    // Last 24 hours
    const now = Date.now();
    const last24HoursMetrics = operationMetrics.filter(
      (m) => now - m.timestamp < this.aggregationWindow
    );
    const last24HoursSuccess = last24HoursMetrics.filter((m) => m.success)
      .length;
    const last24HoursFailure =
      last24HoursMetrics.length - last24HoursSuccess;
    const last24HoursAvg =
      last24HoursMetrics.length > 0
        ? last24HoursMetrics.reduce((sum, m) => sum + m.duration, 0) /
          last24HoursMetrics.length
        : 0;

    return {
      operation,
      totalCalls: operationMetrics.length,
      successCount,
      failureCount,
      averageDuration:
        durations.reduce((sum, d) => sum + d, 0) / durations.length,
      p50Duration: p50,
      p95Duration: p95,
      p99Duration: p99,
      minDuration: durations[0] || 0,
      maxDuration: durations[durations.length - 1] || 0,
      errorRate: (failureCount / operationMetrics.length) * 100,
      last24Hours: {
        totalCalls: last24HoursMetrics.length,
        successCount: last24HoursSuccess,
        failureCount: last24HoursFailure,
        averageDuration: last24HoursAvg,
      },
    };
  }

  /**
   * Get all operations with metrics
   */
  getOperations(): string[] {
    const operations = new Set(this.metrics.map((m) => m.operation));
    return Array.from(operations);
  }

  /**
   * Get summary of all metrics
   */
  getSummary(): {
    totalCalls: number;
    successRate: number;
    averageDuration: number;
    operations: Record<string, AggregatedMetrics>;
  } {
    const operations = this.getOperations();
    const operationMetrics: Record<string, AggregatedMetrics> = {};

    operations.forEach((op) => {
      const metrics = this.getMetrics(op);
      if (metrics) {
        operationMetrics[op] = metrics;
      }
    });

    const totalCalls = this.metrics.length;
    const successCount = this.metrics.filter((m) => m.success).length;
    const avgDuration =
      this.metrics.length > 0
        ? this.metrics.reduce((sum, m) => sum + m.duration, 0) /
          this.metrics.length
        : 0;

    return {
      totalCalls,
      successRate: totalCalls > 0 ? (successCount / totalCalls) * 100 : 0,
      averageDuration: avgDuration,
      operations: operationMetrics,
    };
  }

  /**
   * Calculate percentile
   */
  private percentile(sortedArray: number[], percentile: number): number {
    if (sortedArray.length === 0) return 0;
    const index = Math.ceil((percentile / 100) * sortedArray.length) - 1;
    return sortedArray[Math.max(0, index)] || 0;
  }

  /**
   * Clear old metrics (older than specified time)
   */
  clearOldMetrics(olderThanMs: number = 7 * 24 * 60 * 60 * 1000): void {
    const cutoff = Date.now() - olderThanMs;
    const before = this.metrics.length;
    this.metrics = this.metrics.filter((m) => m.timestamp >= cutoff);
    const after = this.metrics.length;
    if (before !== after) {
      console.log(
        `[PerformanceMonitor] Cleared ${before - after} old metrics (older than ${olderThanMs}ms)`
      );
    }
  }
}

// Singleton instance
export const performanceMonitor = new PerformanceMonitor();

// Periodically clear old metrics (every hour)
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    performanceMonitor.clearOldMetrics();
  }, 60 * 60 * 1000);
}

