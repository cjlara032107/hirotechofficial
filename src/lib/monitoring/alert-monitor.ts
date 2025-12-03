/**
 * Alert Monitoring Service
 * 
 * Monitors system health and creates alerts for:
 * - Job failures
 * - High error rates
 * - Performance degradation
 */

import { prisma } from '@/lib/db';
import { safePrismaOperation } from '@/lib/prisma-error-handler';
import { 
  alertJobFailure, 
  alertHighErrorRate, 
  alertPerformanceDegradation 
} from '@/lib/alerts/alert-service';
import { AlertType } from '@prisma/client';
import { logger } from '@/lib/utils/logger';

export interface MonitoringConfig {
  // Job failure thresholds
  jobFailureThreshold: number; // Number of failures to trigger alert
  jobFailureTimeWindowMinutes: number; // Time window to check for failures
  
  // Error rate thresholds
  errorRateThreshold: number; // Errors per minute to trigger alert
  errorRateTimeWindowMinutes: number; // Time window to check error rate
  
  // Performance degradation thresholds
  performanceDegradationPercent: number; // % slower than baseline to trigger alert
  performanceBaselineWindowDays: number; // Days to look back for baseline
  performanceCheckWindowMinutes: number; // Time window to check recent performance
}

const DEFAULT_CONFIG: MonitoringConfig = {
  jobFailureThreshold: 3, // Alert if 3+ failures in time window
  jobFailureTimeWindowMinutes: 15, // Check last 15 minutes
  
  errorRateThreshold: 10, // Alert if 10+ errors per minute
  errorRateTimeWindowMinutes: 5, // Check last 5 minutes
  
  performanceDegradationPercent: 50, // Alert if 50% slower than baseline
  performanceBaselineWindowDays: 7, // Use last 7 days as baseline
  performanceCheckWindowMinutes: 30, // Check last 30 minutes
};

/**
 * Check for job failures and create alerts if threshold is exceeded
 */
export async function checkJobFailures(config: MonitoringConfig = DEFAULT_CONFIG): Promise<void> {
  try {
    const timeWindowStart = new Date();
    timeWindowStart.setMinutes(timeWindowStart.getMinutes() - config.jobFailureTimeWindowMinutes);

    // Get failed jobs in the time window
    const failedJobs = await safePrismaOperation(
      async () => {
        return await prisma.jobLog.findMany({
          where: {
            status: 'failed',
            createdAt: {
              gte: timeWindowStart,
            },
          },
          orderBy: {
            createdAt: 'desc',
          },
        });
      },
      { operationName: 'check job failures' }
    );

    if (failedJobs.length === 0) {
      return;
    }

    // Group failures by job type
    const failuresByType = new Map<string, typeof failedJobs>();
    for (const job of failedJobs) {
      const existing = failuresByType.get(job.jobType) || [];
      existing.push(job);
      failuresByType.set(job.jobType, existing);
    }

    // Check each job type for threshold violations
    for (const [jobType, failures] of Array.from(failuresByType.entries())) {
      if (failures.length >= config.jobFailureThreshold) {
        const mostRecentFailure = failures[0];
        await alertJobFailure(
          jobType,
          mostRecentFailure.jobId || null,
          mostRecentFailure.error || 'Unknown error',
          failures.length,
          config.jobFailureTimeWindowMinutes
        );
      }
    }
  } catch (error) {
    logger.error('Error checking job failures', error as Error, { operation: 'alert-monitor' });
  }
}

/**
 * Check for high error rates and create alerts if threshold is exceeded
 */
export async function checkErrorRates(config: MonitoringConfig = DEFAULT_CONFIG): Promise<void> {
  try {
    const timeWindowStart = new Date();
    timeWindowStart.setMinutes(timeWindowStart.getMinutes() - config.errorRateTimeWindowMinutes);

    // Get error logs in the time window
    const errorLogs = await safePrismaOperation(
      async () => {
        return await prisma.errorLog.findMany({
          where: {
            level: 'error',
            createdAt: {
              gte: timeWindowStart,
            },
          },
          select: {
            id: true,
            createdAt: true,
          },
        });
      },
      { operationName: 'check error rates' }
    );

    if (errorLogs.length === 0) {
      return;
    }

    // Calculate error rate (errors per minute)
    const errorRate = errorLogs.length / config.errorRateTimeWindowMinutes;

    if (errorRate >= config.errorRateThreshold) {
      await alertHighErrorRate(
        errorLogs.length,
        config.errorRateTimeWindowMinutes,
        errorRate,
        config.errorRateThreshold
      );
    }
  } catch (error) {
    logger.error('Error checking error rates', error as Error, { operation: 'alert-monitor' });
  }
}

/**
 * Check for performance degradation and create alerts if threshold is exceeded
 */
export async function checkPerformanceDegradation(config: MonitoringConfig = DEFAULT_CONFIG): Promise<void> {
  try {
    const checkWindowStart = new Date();
    checkWindowStart.setMinutes(checkWindowStart.getMinutes() - config.performanceCheckWindowMinutes);

    const baselineWindowStart = new Date();
    baselineWindowStart.setDate(baselineWindowStart.getDate() - config.performanceBaselineWindowDays);

    // Get completed jobs in recent window (for current performance)
    const recentJobs = await safePrismaOperation(
      async () => {
        return await prisma.jobLog.findMany({
          where: {
            status: 'completed',
            duration: {
              not: null,
            },
            createdAt: {
              gte: checkWindowStart,
            },
          },
          select: {
            jobType: true,
            duration: true,
            createdAt: true,
          },
        });
      },
      { operationName: 'check performance degradation - recent' }
    );

    if (recentJobs.length === 0) {
      return;
    }

    // Get baseline jobs (for comparison)
    const baselineJobs = await safePrismaOperation(
      async () => {
        return await prisma.jobLog.findMany({
          where: {
            status: 'completed',
            duration: {
              not: null,
            },
            createdAt: {
              gte: baselineWindowStart,
              lt: checkWindowStart, // Only baseline, not recent
            },
          },
          select: {
            jobType: true,
            duration: true,
          },
        });
      },
      { operationName: 'check performance degradation - baseline' }
    );

    if (baselineJobs.length === 0) {
      // No baseline data, skip check
      return;
    }

    // Group by job type
    const recentByType = new Map<string, number[]>();
    for (const job of recentJobs) {
      if (job.duration) {
        const existing = recentByType.get(job.jobType) || [];
        existing.push(job.duration);
        recentByType.set(job.jobType, existing);
      }
    }

    const baselineByType = new Map<string, number[]>();
    for (const job of baselineJobs) {
      if (job.duration) {
        const existing = baselineByType.get(job.jobType) || [];
        existing.push(job.duration);
        baselineByType.set(job.jobType, existing);
      }
    }

    // Check each job type for performance degradation
    for (const [jobType, recentDurations] of Array.from(recentByType.entries())) {
      const baselineDurations = baselineByType.get(jobType);
      if (!baselineDurations || baselineDurations.length === 0) {
        continue; // No baseline for this job type
      }

      // Calculate averages
      const recentAverage = recentDurations.reduce((a, b) => a + b, 0) / recentDurations.length;
      const baselineAverage = baselineDurations.reduce((a, b) => a + b, 0) / baselineDurations.length;

      // Calculate degradation percentage
      const degradationPercent = ((recentAverage - baselineAverage) / baselineAverage) * 100;

      if (degradationPercent >= config.performanceDegradationPercent) {
        await alertPerformanceDegradation(
          jobType,
          recentAverage,
          baselineAverage,
          degradationPercent,
          recentDurations.length
        );
      }
    }
  } catch (error) {
    logger.error('Error checking performance degradation', error as Error, { operation: 'alert-monitor' });
  }
}

/**
 * Run all monitoring checks
 */
export async function runMonitoringChecks(config?: Partial<MonitoringConfig>): Promise<{
  jobFailures: number;
  errorRate: number;
  performanceIssues: number;
}> {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };
  
  const startTime = Date.now();
  logger.info('Starting monitoring checks', { operation: 'alert-monitor' });

  // Run all checks in parallel
  await Promise.allSettled([
    checkJobFailures(fullConfig),
    checkErrorRates(fullConfig),
    checkPerformanceDegradation(fullConfig),
  ]);

  const duration = Date.now() - startTime;
  logger.info('Monitoring checks completed', { operation: 'alert-monitor', duration });

  // Return summary (for testing/debugging)
  const timeWindowStart = new Date();
  timeWindowStart.setMinutes(timeWindowStart.getMinutes() - fullConfig.jobFailureTimeWindowMinutes);

  const [failedJobs, errorLogs] = await Promise.all([
    safePrismaOperation(
      async () => {
        return await prisma.jobLog.count({
          where: {
            status: 'failed',
            createdAt: { gte: timeWindowStart },
          },
        });
      },
      { operationName: 'count job failures' }
    ),
    safePrismaOperation(
      async () => {
        const errorWindowStart = new Date();
        errorWindowStart.setMinutes(errorWindowStart.getMinutes() - fullConfig.errorRateTimeWindowMinutes);
        return await prisma.errorLog.count({
          where: {
            level: 'error',
            createdAt: { gte: errorWindowStart },
          },
        });
      },
      { operationName: 'count errors' }
    ),
  ]);

  const errorRate = errorLogs / fullConfig.errorRateTimeWindowMinutes;

  return {
    jobFailures: failedJobs,
    errorRate,
    performanceIssues: 0, // Would need to calculate this separately
  };
}

/**
 * Auto-resolve alerts when conditions improve
 */
export async function autoResolveAlerts(): Promise<void> {
  try {
    // Check if job failure alerts should be resolved
    const jobFailureAlerts = await prisma.systemAlert.findMany({
      where: {
        type: AlertType.JOB_FAILURE,
        status: 'ACTIVE',
      },
    });

    for (const alert of jobFailureAlerts) {
      const metadata = alert.metadata as { jobType?: string; timeWindowMinutes?: number } | null;
      if (!metadata?.jobType || !metadata?.timeWindowMinutes) continue;

      const timeWindowStart = new Date();
      timeWindowStart.setMinutes(timeWindowStart.getMinutes() - (metadata.timeWindowMinutes || 15));

      const recentFailures = await prisma.jobLog.count({
        where: {
          jobType: metadata.jobType,
          status: 'failed',
          createdAt: { gte: timeWindowStart },
        },
      });

      // If failures dropped below threshold, resolve alert
      if (recentFailures < DEFAULT_CONFIG.jobFailureThreshold) {
        await prisma.systemAlert.update({
          where: { id: alert.id },
          data: {
            status: 'RESOLVED',
            resolvedAt: new Date(),
          },
        });
        logger.info('Auto-resolved job failure alert', { alertId: alert.id, operation: 'alert-monitor' });
      }
    }

    // Check if error rate alerts should be resolved
    const errorRateAlerts = await prisma.systemAlert.findMany({
      where: {
        type: AlertType.HIGH_ERROR_RATE,
        status: 'ACTIVE',
      },
    });

    for (const alert of errorRateAlerts) {
      const metadata = alert.metadata as { timeWindowMinutes?: number; threshold?: number } | null;
      if (!metadata?.timeWindowMinutes || !metadata?.threshold) continue;

      const timeWindowStart = new Date();
      timeWindowStart.setMinutes(timeWindowStart.getMinutes() - (metadata.timeWindowMinutes || 5));

      const recentErrors = await prisma.errorLog.count({
        where: {
          level: 'error',
          createdAt: { gte: timeWindowStart },
        },
      });

      const currentErrorRate = recentErrors / (metadata.timeWindowMinutes || 5);

      // If error rate dropped below threshold, resolve alert
      if (currentErrorRate < metadata.threshold) {
        await prisma.systemAlert.update({
          where: { id: alert.id },
          data: {
            status: 'RESOLVED',
            resolvedAt: new Date(),
          },
        });
        logger.info('Auto-resolved error rate alert', { alertId: alert.id, operation: 'alert-monitor' });
      }
    }
  } catch (error) {
    logger.error('Error auto-resolving alerts', error as Error, { operation: 'alert-monitor' });
  }
}

