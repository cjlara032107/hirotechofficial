/**
 * Performance Metrics Logger
 * 
 * Persists performance metrics to the database for analysis and monitoring.
 * Works alongside the in-memory PerformanceMonitor for long-term storage.
 */

import { prisma } from '@/lib/db';
import { safePrismaOperation } from '@/lib/prisma-error-handler';
import type { PerformanceMetrics } from '@/lib/ai/performance-monitor';

export interface PerformanceMetricInput {
  operation: string;
  duration: number;
  success: boolean;
  errorType?: string;
  apiKeyId?: string;
  requestId?: string;
  priority?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Logs a performance metric to the database
 * Non-blocking: errors are caught and logged but don't throw
 */
export async function logPerformanceMetric(
  metric: PerformanceMetricInput
): Promise<void> {
  try {
    await safePrismaOperation(
      async () => {
        await prisma.performanceMetric.create({
          data: {
            operation: metric.operation,
            duration: Math.round(metric.duration),
            success: metric.success,
            errorType: metric.errorType,
            apiKeyId: metric.apiKeyId,
            requestId: metric.requestId,
            priority: metric.priority,
            metadata: metric.metadata ? JSON.parse(JSON.stringify(metric.metadata)) : null,
          },
        });
      },
      {
        operationName: 'log performance metric',
        maxRetries: 2, // Fewer retries for logging operations
      }
    );
  } catch (error) {
    // Non-blocking: log error but don't throw
    console.error('[PerformanceLogger] Failed to log metric:', error);
  }
}

/**
 * Batch logs multiple performance metrics
 * More efficient for high-volume logging
 */
export async function logPerformanceMetricsBatch(
  metrics: PerformanceMetricInput[]
): Promise<void> {
  if (metrics.length === 0) return;

  try {
    await safePrismaOperation(
      async () => {
        await prisma.performanceMetric.createMany({
          data: metrics.map((metric) => ({
            operation: metric.operation,
            duration: Math.round(metric.duration),
            success: metric.success,
            errorType: metric.errorType,
            apiKeyId: metric.apiKeyId,
            requestId: metric.requestId,
            priority: metric.priority,
            metadata: metric.metadata ? JSON.parse(JSON.stringify(metric.metadata)) : null,
          })),
          skipDuplicates: true,
        });
      },
      {
        operationName: 'log performance metrics batch',
        maxRetries: 2,
      }
    );
  } catch (error) {
    // Non-blocking: log error but don't throw
    console.error('[PerformanceLogger] Failed to log metrics batch:', error);
  }
}

/**
 * Gets performance metrics for a specific operation within a time range
 */
export async function getPerformanceMetrics(
  operation: string,
  startDate: Date,
  endDate: Date
): Promise<Array<{
  id: string;
  duration: number;
  success: boolean;
  errorType: string | null;
  createdAt: Date;
}>> {
  try {
    return await safePrismaOperation(
      async () => {
        return await prisma.performanceMetric.findMany({
          where: {
            operation,
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          },
          select: {
            id: true,
            duration: true,
            success: true,
            errorType: true,
            createdAt: true,
          },
          orderBy: {
            createdAt: 'desc',
          },
          take: 1000, // Limit to prevent excessive data
        });
      },
      {
        operationName: 'get performance metrics',
        maxRetries: 2,
      }
    );
  } catch (error) {
    console.error('[PerformanceLogger] Failed to get metrics:', error);
    return [];
  }
}

/**
 * Cleans up old performance metrics (older than specified days)
 * Should be run periodically via cron job
 */
export async function cleanupOldPerformanceMetrics(
  olderThanDays: number = 30
): Promise<number> {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const result = await safePrismaOperation(
      async () => {
        return await prisma.performanceMetric.deleteMany({
          where: {
            createdAt: {
              lt: cutoffDate,
            },
          },
        });
      },
      {
        operationName: 'cleanup old performance metrics',
        maxRetries: 2,
      }
    );

    return result.count;
  } catch (error) {
    console.error('[PerformanceLogger] Failed to cleanup old metrics:', error);
    return 0;
  }
}









