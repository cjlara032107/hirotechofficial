import { prisma } from '@/lib/db';
import { AlertType, AlertSeverity, AlertStatus, Prisma } from '@prisma/client';
import { logger } from '@/lib/utils/logger';

export interface CreateAlertInput {
  type: AlertType;
  severity?: AlertSeverity;
  title: string;
  message: string;
  metadata?: Record<string, unknown>;
}

/**
 * System-wide alerting service
 * Tracks critical system issues like API rate limits, database connections, and memory leaks
 */
export class AlertService {
  private static readonly ALERT_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes cooldown between same-type alerts
  private static lastAlertTimes = new Map<AlertType, number>();

  /**
   * Create a new system alert
   * Prevents duplicate alerts within cooldown period
   */
  static async createAlert(input: CreateAlertInput): Promise<void> {
    const { type, severity = AlertSeverity.WARNING, title, message, metadata } = input;

    // Check cooldown to prevent alert spam
    const lastAlertTime = this.lastAlertTimes.get(type);
    const now = Date.now();
    
    if (lastAlertTime && (now - lastAlertTime) < this.ALERT_COOLDOWN_MS) {
      // Still in cooldown, skip creating duplicate alert
      logger.debug(`Skipping duplicate ${type} alert (cooldown active)`, { alertType: type });
      return;
    }

    try {
      // Check if there's already an active alert of this type
      const existingAlert = await prisma.systemAlert.findFirst({
        where: {
          type,
          status: AlertStatus.ACTIVE,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      // If there's an active alert within the last hour, don't create a new one
      if (existingAlert) {
        const oneHourAgo = new Date(now - 60 * 60 * 1000);
        if (existingAlert.createdAt > oneHourAgo) {
          logger.debug(`Active ${type} alert already exists, skipping duplicate`, { alertType: type, alertId: existingAlert.id });
          return;
        }
      }

      // Create new alert
      await prisma.systemAlert.create({
        data: {
          type,
          severity,
          title,
          message,
          metadata: (metadata || {}) as Prisma.InputJsonValue,
          status: AlertStatus.ACTIVE,
        },
      });

      // Update last alert time
      this.lastAlertTimes.set(type, now);

      // Log alert creation
      logger.error(`Alert Created: ${title}`, undefined, { 
        severity, 
        alertType: type, 
        message,
        metadata 
      });
    } catch (error) {
      // Don't throw - alerting failures shouldn't break the app
      logger.error('Failed to create alert', error as Error, { alertType: type });
    }
  }

  /**
   * Resolve an alert (mark as resolved)
   */
  static async resolveAlert(alertId: string): Promise<void> {
    try {
      await prisma.systemAlert.update({
        where: { id: alertId },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: new Date(),
        },
      });
      logger.info(`Alert resolved`, { alertId });
    } catch (error) {
      logger.error('Failed to resolve alert', error as Error, { alertId });
    }
  }

  /**
   * Resolve all active alerts of a specific type
   */
  static async resolveAlertsByType(type: AlertType): Promise<void> {
    try {
      const result = await prisma.systemAlert.updateMany({
        where: {
          type,
          status: AlertStatus.ACTIVE,
        },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: new Date(),
        },
      });
      logger.info(`Resolved alerts by type`, { alertType: type, count: result.count });
    } catch (error) {
      logger.error('Failed to resolve alerts by type', error as Error, { alertType: type });
    }
  }

  /**
   * Get active alerts
   */
  static async getActiveAlerts(limit = 50) {
    try {
      return await prisma.systemAlert.findMany({
        where: {
          status: AlertStatus.ACTIVE,
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: limit,
      });
    } catch (error) {
      logger.error('Failed to get active alerts', error as Error);
      return [];
    }
  }

  /**
   * Acknowledge an alert (mark as acknowledged by a user)
   */
  static async acknowledgeAlert(alertId: string, userId: string): Promise<void> {
    try {
      await prisma.systemAlert.update({
        where: { id: alertId },
        data: {
          status: AlertStatus.ACKNOWLEDGED,
          acknowledgedAt: new Date(),
          acknowledgedBy: userId,
        },
      });
    } catch (error) {
      logger.error('Failed to acknowledge alert', error as Error, { alertId, userId });
    }
  }
}

// Convenience functions for common alert types
export async function alertApiRateLimitExhaustion(
  rateLimitedCount: number,
  totalKeys: number,
  earliestAvailableAt: Date | null
): Promise<void> {
  const minutesUntilAvailable = earliestAvailableAt
    ? Math.ceil((earliestAvailableAt.getTime() - Date.now()) / 60000)
    : null;

  await AlertService.createAlert({
    type: AlertType.API_RATE_LIMIT_EXHAUSTION,
    severity: AlertSeverity.CRITICAL,
    title: 'All API Keys Rate Limited',
    message: `All ${totalKeys} API keys are currently rate-limited. ` +
      (minutesUntilAvailable
        ? `Earliest key will be available in approximately ${minutesUntilAvailable} minute(s). `
        : '') +
      'AI analysis and other features requiring API keys will be unavailable until keys reset.',
    metadata: {
      rateLimitedCount,
      totalKeys,
      earliestAvailableAt: earliestAvailableAt?.toISOString() || null,
      minutesUntilAvailable,
    },
  });
}

export async function alertDatabaseConnectionIssue(
  error: Error,
  retryAttempt: number,
  maxRetries: number
): Promise<void> {
  await AlertService.createAlert({
    type: AlertType.DATABASE_CONNECTION_ISSUE,
    severity: retryAttempt >= maxRetries ? AlertSeverity.CRITICAL : AlertSeverity.ERROR,
    title: 'Database Connection Failure',
    message: `Failed to connect to database after ${retryAttempt} attempt(s). ` +
      `Error: ${error.message}. ` +
      (retryAttempt >= maxRetries
        ? 'All retry attempts exhausted. System may be experiencing database connectivity issues.'
        : 'Retrying...'),
    metadata: {
      errorMessage: error.message,
      errorCode: (error as { code?: string }).code,
      retryAttempt,
      maxRetries,
      timestamp: new Date().toISOString(),
    },
  });
}

export async function alertDatabasePoolExhaustion(
  connectionLimit: number,
  activeConnections: number
): Promise<void> {
  await AlertService.createAlert({
    type: AlertType.DATABASE_POOL_EXHAUSTION,
    severity: AlertSeverity.CRITICAL,
    title: 'Database Connection Pool Exhausted',
    message: `Database connection pool is exhausted. ` +
      `All ${connectionLimit} connections are in use. ` +
      `This may cause request timeouts and degraded performance. ` +
      `Consider increasing connection_limit or reducing concurrent operations.`,
    metadata: {
      connectionLimit,
      activeConnections,
      timestamp: new Date().toISOString(),
    },
  });
}

export async function alertJobFailure(
  jobType: string,
  jobId: string | null,
  errorMessage: string,
  failureCount: number,
  timeWindowMinutes: number
): Promise<void> {
  const severity = failureCount >= 5 ? AlertSeverity.CRITICAL : AlertSeverity.ERROR;
  
  await AlertService.createAlert({
    type: AlertType.JOB_FAILURE,
    severity,
    title: `Job Failures Detected: ${jobType}`,
    message: `${failureCount} job failure(s) detected for "${jobType}" in the last ${timeWindowMinutes} minute(s). ` +
      `Most recent error: ${errorMessage}. ` +
      `This may indicate a systemic issue requiring attention.`,
    metadata: {
      jobType,
      jobId,
      failureCount,
      timeWindowMinutes,
      errorMessage,
      timestamp: new Date().toISOString(),
    },
  });
}

export async function alertHighErrorRate(
  errorCount: number,
  timeWindowMinutes: number,
  errorRate: number,
  threshold: number
): Promise<void> {
  const severity = errorRate >= threshold * 2 ? AlertSeverity.CRITICAL : AlertSeverity.ERROR;
  
  await AlertService.createAlert({
    type: AlertType.HIGH_ERROR_RATE,
    severity,
    title: 'High Error Rate Detected',
    message: `Error rate of ${errorRate.toFixed(2)} errors/minute detected (threshold: ${threshold}/min). ` +
      `${errorCount} error(s) occurred in the last ${timeWindowMinutes} minute(s). ` +
      `This may indicate a systemic issue requiring immediate attention.`,
    metadata: {
      errorCount,
      timeWindowMinutes,
      errorRate,
      threshold,
      timestamp: new Date().toISOString(),
    },
  });
}

export async function alertPerformanceDegradation(
  jobType: string,
  averageDuration: number,
  baselineDuration: number,
  degradationPercent: number,
  affectedJobs: number
): Promise<void> {
  const severity = degradationPercent >= 200 ? AlertSeverity.CRITICAL : 
                   degradationPercent >= 100 ? AlertSeverity.ERROR : 
                   AlertSeverity.WARNING;
  
  await AlertService.createAlert({
    type: AlertType.PERFORMANCE_DEGRADATION,
    severity,
    title: `Performance Degradation: ${jobType}`,
    message: `Job "${jobType}" is running ${degradationPercent.toFixed(0)}% slower than baseline. ` +
      `Average duration: ${(averageDuration / 1000).toFixed(1)}s (baseline: ${(baselineDuration / 1000).toFixed(1)}s). ` +
      `Affected ${affectedJobs} job(s). This may indicate resource constraints or system issues.`,
    metadata: {
      jobType,
      averageDuration,
      baselineDuration,
      degradationPercent,
      affectedJobs,
      timestamp: new Date().toISOString(),
    },
  });
}

