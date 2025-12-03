/**
 * Job Lifecycle Logger
 * 
 * Logs the complete lifecycle of background jobs and cron jobs:
 * - Job start
 * - Progress updates
 * - Completion
 * - Failures with stack traces
 */

import { prisma } from '@/lib/db';
import { safePrismaOperation } from '@/lib/prisma-error-handler';

export type JobStatus = 'started' | 'progress' | 'completed' | 'failed' | 'cancelled';

export interface JobLogInput {
  jobType: string; // e.g., "cron-send-scheduled", "background-sync", "ai-automations"
  jobId?: string; // Related job ID (e.g., SyncJob.id, Campaign.id)
  status: JobStatus;
  message: string;
  progress?: number; // Progress percentage (0-100)
  metadata?: Record<string, unknown>;
  error?: Error | unknown;
  duration?: number; // Duration in milliseconds (for completed jobs)
}

/**
 * Gets error message and stack from an error
 */
function getErrorDetails(error: unknown): { message: string; stack: string | null } {
  if (error instanceof Error) {
    return {
      message: error.message,
      stack: error.stack || null,
    };
  }
  return {
    message: String(error),
    stack: null,
  };
}

/**
 * Logs a job lifecycle event
 * Non-blocking: errors are caught and logged but don't throw
 */
export async function logJobEvent(input: JobLogInput): Promise<void> {
  try {
    const errorDetails = input.error ? getErrorDetails(input.error) : null;

    await safePrismaOperation(
      async () => {
        await prisma.jobLog.create({
          data: {
            jobType: input.jobType,
            jobId: input.jobId,
            status: input.status,
            message: input.message,
            progress: input.progress,
            metadata: input.metadata ? JSON.parse(JSON.stringify(input.metadata)) : null,
            error: errorDetails?.message,
            stack: errorDetails?.stack,
            duration: input.duration,
          },
        });
      },
      {
        operationName: 'log job event',
        maxRetries: 2,
      }
    );

    // Also log to console for immediate visibility
    const statusEmoji = {
      started: '🚀',
      progress: '⏳',
      completed: '✅',
      failed: '❌',
      cancelled: '⚠️',
    }[input.status] || '📝';

    const progressStr = input.progress !== undefined ? ` (${input.progress}%)` : '';
    const durationStr = input.duration !== undefined ? ` [${input.duration}ms]` : '';
    const logMessage = `[JobLogger] ${statusEmoji} [${input.jobType}]${input.jobId ? ` [${input.jobId}]` : ''} ${input.status}${progressStr}${durationStr}: ${input.message}`;

    if (input.status === 'failed') {
      console.error(logMessage, input.error);
    } else if (input.status === 'completed') {
      console.log(logMessage);
    } else {
      console.log(logMessage);
    }
  } catch (error) {
    // Non-blocking: log error but don't throw
    console.error('[JobLogger] Failed to log job event to database:', error);
    console.error('[JobLogger] Original job event:', input);
  }
}

/**
 * Convenience functions for common job lifecycle events
 */

export async function logJobStart(
  jobType: string,
  jobId: string | undefined,
  message: string,
  metadata?: Record<string, unknown>
): Promise<void> {
  await logJobEvent({
    jobType,
    jobId,
    status: 'started',
    message,
    metadata,
  });
}

export async function logJobProgress(
  jobType: string,
  jobId: string | undefined,
  message: string,
  progress: number,
  metadata?: Record<string, unknown>
): Promise<void> {
  await logJobEvent({
    jobType,
    jobId,
    status: 'progress',
    message,
    progress: Math.max(0, Math.min(100, progress)), // Clamp to 0-100
    metadata,
  });
}

export async function logJobComplete(
  jobType: string,
  jobId: string | undefined,
  message: string,
  duration: number,
  metadata?: Record<string, unknown>
): Promise<void> {
  await logJobEvent({
    jobType,
    jobId,
    status: 'completed',
    message,
    duration,
    metadata,
  });
}

export async function logJobFailure(
  jobType: string,
  jobId: string | undefined,
  message: string,
  error: Error | unknown,
  metadata?: Record<string, unknown>
): Promise<void> {
  await logJobEvent({
    jobType,
    jobId,
    status: 'failed',
    message,
    error,
    metadata,
  });
}

export async function logJobCancel(
  jobType: string,
  jobId: string | undefined,
  message: string,
  metadata?: Record<string, unknown>
): Promise<void> {
  await logJobEvent({
    jobType,
    jobId,
    status: 'cancelled',
    message,
    metadata,
  });
}

/**
 * Gets job logs for a specific job or job type
 */
export async function getJobLogs(
  options: {
    jobType?: string;
    jobId?: string;
    status?: JobStatus;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }
): Promise<Array<{
  id: string;
  jobType: string;
  jobId: string | null;
  status: string;
  message: string;
  progress: number | null;
  error: string | null;
  stack: string | null;
  duration: number | null;
  metadata: unknown;
  createdAt: Date;
}>> {
  try {
    const startDate = options.startDate || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // Default: last 7 days
    const endDate = options.endDate || new Date();

    return await safePrismaOperation(
      async () => {
        return await prisma.jobLog.findMany({
          where: {
            ...(options.jobType && { jobType: options.jobType }),
            ...(options.jobId && { jobId: options.jobId }),
            ...(options.status && { status: options.status }),
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          },
          select: {
            id: true,
            jobType: true,
            jobId: true,
            status: true,
            message: true,
            progress: true,
            error: true,
            stack: true,
            duration: true,
            metadata: true,
            createdAt: true,
          },
          orderBy: {
            createdAt: 'desc',
          },
          take: options.limit || 1000,
        });
      },
      {
        operationName: 'get job logs',
        maxRetries: 2,
      }
    );
  } catch (error) {
    console.error('[JobLogger] Failed to get job logs:', error);
    return [];
  }
}

/**
 * Cleans up old job logs (older than specified days)
 * Should be run periodically via cron job
 */
export async function cleanupOldJobLogs(
  olderThanDays: number = 30
): Promise<number> {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const result = await safePrismaOperation(
      async () => {
        return await prisma.jobLog.deleteMany({
          where: {
            createdAt: {
              lt: cutoffDate,
            },
          },
        });
      },
      {
        operationName: 'cleanup old job logs',
        maxRetries: 2,
      }
    );

    return result.count;
  } catch (error) {
    console.error('[JobLogger] Failed to cleanup old job logs:', error);
    return 0;
  }
}









