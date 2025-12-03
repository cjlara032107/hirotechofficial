/**
 * System Monitoring Module
 * 
 * Tracks:
 * - Database query performance
 * - Memory usage
 * - Error rates by type
 * - CPU usage
 * - Network I/O
 */

import * as os from 'os';

export interface DatabaseQueryMetric {
  query: string;
  duration: number;
  model?: string;
  action?: string;
  timestamp: number;
  success: boolean;
  errorCode?: string;
  errorMessage?: string;
}

export interface MemoryMetric {
  heapUsed: number;
  heapTotal: number;
  rss: number;
  external: number;
  heapUsedMB: number;
  heapTotalMB: number;
  rssMB: number;
  usagePercent: number;
  timestamp: number;
}

export interface ErrorMetric {
  errorType: string;
  errorCode?: string;
  errorMessage: string;
  stack?: string;
  context?: Record<string, unknown>;
  timestamp: number;
  endpoint?: string;
  userId?: string;
}

export interface DatabaseQueryStats {
  totalQueries: number;
  averageDuration: number;
  p50Duration: number;
  p95Duration: number;
  p99Duration: number;
  minDuration: number;
  maxDuration: number;
  slowQueries: number; // queries > 1000ms
  errorCount: number;
  errorRate: number;
  queriesByModel: Record<string, number>;
  last24Hours: {
    totalQueries: number;
    averageDuration: number;
    errorCount: number;
  };
}

export interface MemoryStats {
  current: MemoryMetric | null;
  average: {
    heapUsedMB: number;
    heapTotalMB: number;
    rssMB: number;
    usagePercent: number;
  };
  peak: {
    heapUsedMB: number;
    heapTotalMB: number;
    rssMB: number;
    usagePercent: number;
    timestamp: number;
  };
  samples: number;
  last24Hours: {
    averageHeapUsedMB: number;
    averageRssMB: number;
    averageUsagePercent: number;
    peakHeapUsedMB: number;
    peakRssMB: number;
    peakUsagePercent: number;
  };
}

export interface ErrorStats {
  totalErrors: number;
  errorsByType: Record<string, number>;
  errorsByCode: Record<string, number>;
  errorRate: number; // errors per hour
  recentErrors: ErrorMetric[];
  last24Hours: {
    totalErrors: number;
    errorsByType: Record<string, number>;
    errorsByCode: Record<string, number>;
  };
}

export interface CpuMetric {
  user: number;
  system: number;
  total: number;
  timestamp: number;
}

export interface NetworkMetric {
  bytesReceived: number;
  bytesSent: number;
  requests: number;
  timestamp: number;
}

export interface ResourceUsageStats {
  cpu: {
    current: CpuMetric | null;
    average: {
      user: number;
      system: number;
      total: number;
    };
    peak: {
      user: number;
      system: number;
      total: number;
      timestamp: number;
    };
    samples: number;
    last24Hours: {
      averageUser: number;
      averageSystem: number;
      averageTotal: number;
      peakUser: number;
      peakSystem: number;
      peakTotal: number;
    };
  };
  network: {
    current: NetworkMetric | null;
    total: {
      bytesReceived: number;
      bytesSent: number;
      requests: number;
    };
    last24Hours: {
      bytesReceived: number;
      bytesSent: number;
      requests: number;
      bytesReceivedPerHour: number;
      bytesSentPerHour: number;
      requestsPerHour: number;
    };
  };
}

export interface SystemMetrics {
  database: DatabaseQueryStats;
  memory: MemoryStats;
  errors: ErrorStats;
  resources: ResourceUsageStats;
  timestamp: number;
}

export class SystemMonitor {
  private databaseQueries: DatabaseQueryMetric[] = [];
  private memorySamples: MemoryMetric[] = [];
  private errors: ErrorMetric[] = [];
  private cpuSamples: CpuMetric[] = [];
  private networkSamples: NetworkMetric[] = [];
  
  private readonly maxDatabaseQueries = 10000;
  private readonly maxMemorySamples = 1000;
  private readonly maxErrors = 5000;
  private readonly maxCpuSamples = 1000;
  private readonly maxNetworkSamples = 1000;
  private readonly aggregationWindow = 24 * 60 * 60 * 1000; // 24 hours
  
  private memorySamplingInterval: NodeJS.Timeout | null = null;
  private readonly memorySamplingIntervalMs = 30000; // Sample every 30 seconds
  
  private previousCpuUsage: NodeJS.CpuUsage | null = null;
  private networkStartTime: number = Date.now();
  private networkStartBytes: { received: number; sent: number } = { received: 0, sent: 0 };

  constructor() {
    // Start memory sampling if on server side
    if (typeof window === 'undefined') {
      this.startMemorySampling();
      this.startCpuSampling();
      this.initializeNetworkTracking();
    }
  }

  /**
   * Record a database query
   */
  recordDatabaseQuery(metric: DatabaseQueryMetric): void {
    this.databaseQueries.push(metric);
    
    // Trim old queries
    if (this.databaseQueries.length > this.maxDatabaseQueries) {
      this.databaseQueries = this.databaseQueries.slice(-this.maxDatabaseQueries);
    }

    // Log slow queries
    if (metric.duration > 1000) {
      console.warn(
        `[SystemMonitor] ⚠️ Slow database query (${metric.duration}ms):`,
        metric.model || 'unknown',
        metric.action || 'unknown',
        metric.query?.substring(0, 100) || 'N/A'
      );
    }

    // Log errors
    if (!metric.success) {
      console.error(
        `[SystemMonitor] ❌ Database query error:`,
        metric.errorCode || 'unknown',
        metric.errorMessage || 'unknown error'
      );
    }
  }

  /**
   * Record memory usage
   */
  recordMemoryUsage(metric: MemoryMetric): void {
    this.memorySamples.push(metric);
    
    // Trim old samples
    if (this.memorySamples.length > this.maxMemorySamples) {
      this.memorySamples = this.memorySamples.slice(-this.maxMemorySamples);
    }

    // Log high memory usage (with throttling to reduce log noise)
    // Only log once per minute when above threshold to avoid spam
    const now = Date.now();
    const lastLogTime = (this as any).lastMemoryLogTime || 0;
    const logInterval = 60000; // Log at most once per minute
    
    if (metric.usagePercent > 85 && (now - lastLogTime) > logInterval) {
      console.warn(
        `[SystemMonitor] 🚨 High memory usage: ${metric.usagePercent.toFixed(1)}% ` +
        `(${metric.heapUsedMB.toFixed(1)}MB / ${metric.heapTotalMB.toFixed(1)}MB)`
      );
      (this as any).lastMemoryLogTime = now;
    }
  }

  /**
   * Record an error
   */
  recordError(metric: ErrorMetric): void {
    this.errors.push(metric);
    
    // Trim old errors
    if (this.errors.length > this.maxErrors) {
      this.errors = this.errors.slice(-this.maxErrors);
    }

    // Log error
    console.error(
      `[SystemMonitor] ❌ Error [${metric.errorType}]:`,
      metric.errorMessage,
      metric.endpoint ? `(endpoint: ${metric.endpoint})` : ''
    );
  }

  /**
   * Get database query statistics
   */
  getDatabaseStats(): DatabaseQueryStats {
    if (this.databaseQueries.length === 0) {
      return {
        totalQueries: 0,
        averageDuration: 0,
        p50Duration: 0,
        p95Duration: 0,
        p99Duration: 0,
        minDuration: 0,
        maxDuration: 0,
        slowQueries: 0,
        errorCount: 0,
        errorRate: 0,
        queriesByModel: {},
        last24Hours: {
          totalQueries: 0,
          averageDuration: 0,
          errorCount: 0,
        },
      };
    }

    const durations = this.databaseQueries
      .map((q) => q.duration)
      .sort((a, b) => a - b);
    
    const errorCount = this.databaseQueries.filter((q) => !q.success).length;
    const slowQueries = this.databaseQueries.filter((q) => q.duration > 1000).length;

    // Calculate percentiles
    const p50 = this.percentile(durations, 50);
    const p95 = this.percentile(durations, 95);
    const p99 = this.percentile(durations, 99);

    // Group by model
    const queriesByModel: Record<string, number> = {};
    this.databaseQueries.forEach((q) => {
      const model = q.model || 'unknown';
      queriesByModel[model] = (queriesByModel[model] || 0) + 1;
    });

    // Last 24 hours
    const now = Date.now();
    const last24HoursQueries = this.databaseQueries.filter(
      (q) => now - q.timestamp < this.aggregationWindow
    );
    const last24HoursDurations = last24HoursQueries.map((q) => q.duration);
    const last24HoursErrors = last24HoursQueries.filter((q) => !q.success).length;

    return {
      totalQueries: this.databaseQueries.length,
      averageDuration: durations.reduce((sum, d) => sum + d, 0) / durations.length,
      p50Duration: p50,
      p95Duration: p95,
      p99Duration: p99,
      minDuration: durations[0] || 0,
      maxDuration: durations[durations.length - 1] || 0,
      slowQueries,
      errorCount,
      errorRate: (errorCount / this.databaseQueries.length) * 100,
      queriesByModel,
      last24Hours: {
        totalQueries: last24HoursQueries.length,
        averageDuration: last24HoursDurations.length > 0
          ? last24HoursDurations.reduce((sum, d) => sum + d, 0) / last24HoursDurations.length
          : 0,
        errorCount: last24HoursErrors,
      },
    };
  }

  /**
   * Get memory statistics
   */
  getMemoryStats(): MemoryStats {
    if (this.memorySamples.length === 0) {
      // Get current memory if no samples
      const usage = process.memoryUsage();
      const current: MemoryMetric = {
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        rss: usage.rss,
        external: usage.external,
        heapUsedMB: usage.heapUsed / 1024 / 1024,
        heapTotalMB: usage.heapTotal / 1024 / 1024,
        rssMB: usage.rss / 1024 / 1024,
        usagePercent: (usage.heapUsed / usage.heapTotal) * 100,
        timestamp: Date.now(),
      };

      return {
        current,
        average: {
          heapUsedMB: current.heapUsedMB,
          heapTotalMB: current.heapTotalMB,
          rssMB: current.rssMB,
          usagePercent: current.usagePercent,
        },
        peak: {
          heapUsedMB: current.heapUsedMB,
          heapTotalMB: current.heapTotalMB,
          rssMB: current.rssMB,
          usagePercent: current.usagePercent,
          timestamp: current.timestamp,
        },
        samples: 1,
        last24Hours: {
          averageHeapUsedMB: current.heapUsedMB,
          averageRssMB: current.rssMB,
          averageUsagePercent: current.usagePercent,
          peakHeapUsedMB: current.heapUsedMB,
          peakRssMB: current.rssMB,
          peakUsagePercent: current.usagePercent,
        },
      };
    }

    const current = this.memorySamples[this.memorySamples.length - 1];
    
    // Calculate averages
    const avgHeapUsedMB = this.memorySamples.reduce((sum, m) => sum + m.heapUsedMB, 0) / this.memorySamples.length;
    const avgHeapTotalMB = this.memorySamples.reduce((sum, m) => sum + m.heapTotalMB, 0) / this.memorySamples.length;
    const avgRssMB = this.memorySamples.reduce((sum, m) => sum + m.rssMB, 0) / this.memorySamples.length;
    const avgUsagePercent = this.memorySamples.reduce((sum, m) => sum + m.usagePercent, 0) / this.memorySamples.length;

    // Find peak
    const peak = this.memorySamples.reduce((max, m) => 
      m.heapUsedMB > max.heapUsedMB ? m : max
    );

    // Last 24 hours
    const now = Date.now();
    const last24HoursSamples = this.memorySamples.filter(
      (m) => now - m.timestamp < this.aggregationWindow
    );

    let last24HoursAvg = {
      averageHeapUsedMB: avgHeapUsedMB,
      averageRssMB: avgRssMB,
      averageUsagePercent: avgUsagePercent,
      peakHeapUsedMB: peak.heapUsedMB,
      peakRssMB: peak.rssMB,
      peakUsagePercent: peak.usagePercent,
    };

    if (last24HoursSamples.length > 0) {
      const last24HoursAvgHeapUsedMB = last24HoursSamples.reduce((sum, m) => sum + m.heapUsedMB, 0) / last24HoursSamples.length;
      const last24HoursAvgRssMB = last24HoursSamples.reduce((sum, m) => sum + m.rssMB, 0) / last24HoursSamples.length;
      const last24HoursAvgUsagePercent = last24HoursSamples.reduce((sum, m) => sum + m.usagePercent, 0) / last24HoursSamples.length;
      const last24HoursPeak = last24HoursSamples.reduce((max, m) => 
        m.heapUsedMB > max.heapUsedMB ? m : max
      );

      last24HoursAvg = {
        averageHeapUsedMB: last24HoursAvgHeapUsedMB,
        averageRssMB: last24HoursAvgRssMB,
        averageUsagePercent: last24HoursAvgUsagePercent,
        peakHeapUsedMB: last24HoursPeak.heapUsedMB,
        peakRssMB: last24HoursPeak.rssMB,
        peakUsagePercent: last24HoursPeak.usagePercent,
      };
    }

    return {
      current,
      average: {
        heapUsedMB: avgHeapUsedMB,
        heapTotalMB: avgHeapTotalMB,
        rssMB: avgRssMB,
        usagePercent: avgUsagePercent,
      },
      peak: {
        heapUsedMB: peak.heapUsedMB,
        heapTotalMB: peak.heapTotalMB,
        rssMB: peak.rssMB,
        usagePercent: peak.usagePercent,
        timestamp: peak.timestamp,
      },
      samples: this.memorySamples.length,
      last24Hours: last24HoursAvg,
    };
  }

  /**
   * Get error statistics
   */
  getErrorStats(): ErrorStats {
    if (this.errors.length === 0) {
      return {
        totalErrors: 0,
        errorsByType: {},
        errorsByCode: {},
        errorRate: 0,
        recentErrors: [],
        last24Hours: {
          totalErrors: 0,
          errorsByType: {},
          errorsByCode: {},
        },
      };
    }

    // Group by type
    const errorsByType: Record<string, number> = {};
    const errorsByCode: Record<string, number> = {};
    
    this.errors.forEach((e) => {
      errorsByType[e.errorType] = (errorsByType[e.errorType] || 0) + 1;
      if (e.errorCode) {
        errorsByCode[e.errorCode] = (errorsByCode[e.errorCode] || 0) + 1;
      }
    });

    // Calculate error rate (errors per hour)
    // Use last 24 hours window for more accurate rate calculation
    const now = Date.now();
    const last24HoursErrors = this.errors.filter(
      (e) => now - e.timestamp < this.aggregationWindow
    );
    
    let errorRate = 0;
    if (last24HoursErrors.length > 0) {
      // Calculate rate based on last 24 hours
      errorRate = last24HoursErrors.length / 24; // errors per hour
    } else if (this.errors.length > 1) {
      // Fallback: use all errors if no errors in last 24 hours
      const oldestError = this.errors[0];
      const newestError = this.errors[this.errors.length - 1];
      const timeSpanHours = (newestError.timestamp - oldestError.timestamp) / (1000 * 60 * 60);
      errorRate = timeSpanHours > 0 ? this.errors.length / timeSpanHours : 0;
    }

    // Recent errors (last 50)
    const recentErrors = this.errors.slice(-50).reverse();

    const last24HoursByType: Record<string, number> = {};
    const last24HoursByCode: Record<string, number> = {};
    
    last24HoursErrors.forEach((e) => {
      last24HoursByType[e.errorType] = (last24HoursByType[e.errorType] || 0) + 1;
      if (e.errorCode) {
        last24HoursByCode[e.errorCode] = (last24HoursByCode[e.errorCode] || 0) + 1;
      }
    });

    return {
      totalErrors: this.errors.length,
      errorsByType,
      errorsByCode,
      errorRate,
      recentErrors,
      last24Hours: {
        totalErrors: last24HoursErrors.length,
        errorsByType: last24HoursByType,
        errorsByCode: last24HoursByCode,
      },
    };
  }

  /**
   * Record CPU usage
   */
  recordCpuUsage(metric: CpuMetric): void {
    this.cpuSamples.push(metric);
    
    // Trim old samples
    if (this.cpuSamples.length > this.maxCpuSamples) {
      this.cpuSamples = this.cpuSamples.slice(-this.maxCpuSamples);
    }

    // Log high CPU usage
    if (metric.total > 80) {
      console.warn(
        `[SystemMonitor] 🚨 High CPU usage: ${metric.total.toFixed(1)}% ` +
        `(user: ${metric.user.toFixed(1)}%, system: ${metric.system.toFixed(1)}%)`
      );
    }
  }

  /**
   * Record network usage
   */
  recordNetworkUsage(metric: NetworkMetric): void {
    this.networkSamples.push(metric);
    
    // Trim old samples
    if (this.networkSamples.length > this.maxNetworkSamples) {
      this.networkSamples = this.networkSamples.slice(-this.maxNetworkSamples);
    }
  }

  /**
   * Get CPU statistics
   */
  getCpuStats(): ResourceUsageStats['cpu'] {
    if (this.cpuSamples.length === 0) {
      const usage = process.cpuUsage();
      const current: CpuMetric = {
        user: 0,
        system: 0,
        total: 0,
        timestamp: Date.now(),
      };

      return {
        current,
        average: {
          user: 0,
          system: 0,
          total: 0,
        },
        peak: {
          user: 0,
          system: 0,
          total: 0,
          timestamp: current.timestamp,
        },
        samples: 1,
        last24Hours: {
          averageUser: 0,
          averageSystem: 0,
          averageTotal: 0,
          peakUser: 0,
          peakSystem: 0,
          peakTotal: 0,
        },
      };
    }

    const current = this.cpuSamples[this.cpuSamples.length - 1];
    
    // Calculate averages
    const avgUser = this.cpuSamples.reduce((sum, m) => sum + m.user, 0) / this.cpuSamples.length;
    const avgSystem = this.cpuSamples.reduce((sum, m) => sum + m.system, 0) / this.cpuSamples.length;
    const avgTotal = this.cpuSamples.reduce((sum, m) => sum + m.total, 0) / this.cpuSamples.length;

    // Find peak
    const peak = this.cpuSamples.reduce((max, m) => 
      m.total > max.total ? m : max
    );

    // Last 24 hours
    const now = Date.now();
    const last24HoursSamples = this.cpuSamples.filter(
      (m) => now - m.timestamp < this.aggregationWindow
    );

    let last24HoursAvg = {
      averageUser: avgUser,
      averageSystem: avgSystem,
      averageTotal: avgTotal,
      peakUser: peak.user,
      peakSystem: peak.system,
      peakTotal: peak.total,
    };

    if (last24HoursSamples.length > 0) {
      const last24HoursAvgUser = last24HoursSamples.reduce((sum, m) => sum + m.user, 0) / last24HoursSamples.length;
      const last24HoursAvgSystem = last24HoursSamples.reduce((sum, m) => sum + m.system, 0) / last24HoursSamples.length;
      const last24HoursAvgTotal = last24HoursSamples.reduce((sum, m) => sum + m.total, 0) / last24HoursSamples.length;
      const last24HoursPeak = last24HoursSamples.reduce((max, m) => 
        m.total > max.total ? m : max
      );

      last24HoursAvg = {
        averageUser: last24HoursAvgUser,
        averageSystem: last24HoursAvgSystem,
        averageTotal: last24HoursAvgTotal,
        peakUser: last24HoursPeak.user,
        peakSystem: last24HoursPeak.system,
        peakTotal: last24HoursPeak.total,
      };
    }

    return {
      current,
      average: {
        user: avgUser,
        system: avgSystem,
        total: avgTotal,
      },
      peak: {
        user: peak.user,
        system: peak.system,
        total: peak.total,
        timestamp: peak.timestamp,
      },
      samples: this.cpuSamples.length,
      last24Hours: last24HoursAvg,
    };
  }

  /**
   * Get network statistics
   */
  getNetworkStats(): ResourceUsageStats['network'] {
    if (this.networkSamples.length === 0) {
      return {
        current: null,
        total: {
          bytesReceived: 0,
          bytesSent: 0,
          requests: 0,
        },
        last24Hours: {
          bytesReceived: 0,
          bytesSent: 0,
          requests: 0,
          bytesReceivedPerHour: 0,
          bytesSentPerHour: 0,
          requestsPerHour: 0,
        },
      };
    }

    const current = this.networkSamples[this.networkSamples.length - 1];
    
    // Calculate totals
    const totalBytesReceived = this.networkSamples.reduce((sum, m) => sum + m.bytesReceived, 0);
    const totalBytesSent = this.networkSamples.reduce((sum, m) => sum + m.bytesSent, 0);
    const totalRequests = this.networkSamples.reduce((sum, m) => sum + m.requests, 0);

    // Last 24 hours
    const now = Date.now();
    const last24HoursSamples = this.networkSamples.filter(
      (m) => now - m.timestamp < this.aggregationWindow
    );

    const last24HoursBytesReceived = last24HoursSamples.reduce((sum, m) => sum + m.bytesReceived, 0);
    const last24HoursBytesSent = last24HoursSamples.reduce((sum, m) => sum + m.bytesSent, 0);
    const last24HoursRequests = last24HoursSamples.reduce((sum, m) => sum + m.requests, 0);

    const hoursInWindow = (now - (now - this.aggregationWindow)) / (1000 * 60 * 60);
    const hours = hoursInWindow > 0 ? hoursInWindow : 24;

    return {
      current,
      total: {
        bytesReceived: totalBytesReceived,
        bytesSent: totalBytesSent,
        requests: totalRequests,
      },
      last24Hours: {
        bytesReceived: last24HoursBytesReceived,
        bytesSent: last24HoursBytesSent,
        requests: last24HoursRequests,
        bytesReceivedPerHour: last24HoursBytesReceived / hours,
        bytesSentPerHour: last24HoursBytesSent / hours,
        requestsPerHour: last24HoursRequests / hours,
      },
    };
  }

  /**
   * Get resource usage statistics
   */
  getResourceUsageStats(): ResourceUsageStats {
    return {
      cpu: this.getCpuStats(),
      network: this.getNetworkStats(),
    };
  }

  /**
   * Start CPU sampling
   */
  private startCpuSampling(): void {
    this.previousCpuUsage = process.cpuUsage();
    let previousTimestamp = Date.now();
    
    setInterval(() => {
      const currentTimestamp = Date.now();
      const elapsedMs = currentTimestamp - previousTimestamp;
      const elapsedSeconds = elapsedMs / 1000;
      
      const currentUsage = process.cpuUsage(this.previousCpuUsage || undefined);
      this.previousCpuUsage = process.cpuUsage();
      previousTimestamp = currentTimestamp;

      // Calculate CPU percentage based on elapsed time
      // CPU usage = (CPU time used / elapsed time) * 100
      // Since we have multiple cores, we need to account for that
      const cpuCount = os.cpus().length;
      const maxCpuTime = elapsedSeconds * cpuCount * 1000000; // microseconds
      
      const userPercent = Math.min(100, (currentUsage.user / maxCpuTime) * 100);
      const systemPercent = Math.min(100, (currentUsage.system / maxCpuTime) * 100);
      const totalPercent = Math.min(100, userPercent + systemPercent);

      this.recordCpuUsage({
        user: userPercent,
        system: systemPercent,
        total: totalPercent,
        timestamp: currentTimestamp,
      });
    }, this.memorySamplingIntervalMs);
  }

  /**
   * Initialize network tracking
   */
  private initializeNetworkTracking(): void {
    this.networkStartTime = Date.now();
    // Note: Node.js doesn't provide built-in network stats
    // This is a placeholder that can be enhanced with actual network monitoring
    // For now, we'll track API request counts as a proxy
  }

  /**
   * Get all system metrics
   */
  getSystemMetrics(): SystemMetrics {
    return {
      database: this.getDatabaseStats(),
      memory: this.getMemoryStats(),
      errors: this.getErrorStats(),
      resources: this.getResourceUsageStats(),
      timestamp: Date.now(),
    };
  }

  /**
   * Start memory sampling
   */
  private startMemorySampling(): void {
    if (this.memorySamplingInterval) {
      return;
    }

    this.memorySamplingInterval = setInterval(() => {
      const usage = process.memoryUsage();
      this.recordMemoryUsage({
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        rss: usage.rss,
        external: usage.external,
        heapUsedMB: usage.heapUsed / 1024 / 1024,
        heapTotalMB: usage.heapTotal / 1024 / 1024,
        rssMB: usage.rss / 1024 / 1024,
        usagePercent: (usage.heapUsed / usage.heapTotal) * 100,
        timestamp: Date.now(),
      });
    }, this.memorySamplingIntervalMs);
  }

  /**
   * Stop memory sampling
   */
  stopMemorySampling(): void {
    if (this.memorySamplingInterval) {
      clearInterval(this.memorySamplingInterval);
      this.memorySamplingInterval = null;
    }
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
   * Clear old metrics
   */
  clearOldMetrics(olderThanMs: number = 7 * 24 * 60 * 60 * 1000): void {
    const cutoff = Date.now() - olderThanMs;
    
    const beforeQueries = this.databaseQueries.length;
    const beforeMemory = this.memorySamples.length;
    const beforeErrors = this.errors.length;
    const beforeCpu = this.cpuSamples.length;
    const beforeNetwork = this.networkSamples.length;
    
    this.databaseQueries = this.databaseQueries.filter((q) => q.timestamp >= cutoff);
    this.memorySamples = this.memorySamples.filter((m) => m.timestamp >= cutoff);
    this.errors = this.errors.filter((e) => e.timestamp >= cutoff);
    this.cpuSamples = this.cpuSamples.filter((c) => c.timestamp >= cutoff);
    this.networkSamples = this.networkSamples.filter((n) => n.timestamp >= cutoff);
    
    const afterQueries = this.databaseQueries.length;
    const afterMemory = this.memorySamples.length;
    const afterErrors = this.errors.length;
    const afterCpu = this.cpuSamples.length;
    const afterNetwork = this.networkSamples.length;
    
    if (beforeQueries !== afterQueries || beforeMemory !== afterMemory || beforeErrors !== afterErrors || beforeCpu !== afterCpu || beforeNetwork !== afterNetwork) {
      console.log(
        `[SystemMonitor] Cleared old metrics: ` +
        `${beforeQueries - afterQueries} queries, ` +
        `${beforeMemory - afterMemory} memory samples, ` +
        `${beforeErrors - afterErrors} errors, ` +
        `${beforeCpu - afterCpu} CPU samples, ` +
        `${beforeNetwork - afterNetwork} network samples`
      );
    }
  }
}

// Singleton instance
export const systemMonitor = new SystemMonitor();

// Periodically clear old metrics (every hour)
if (typeof window === 'undefined' && typeof setInterval !== 'undefined') {
  setInterval(() => {
    systemMonitor.clearOldMetrics();
  }, 60 * 60 * 1000);
}

