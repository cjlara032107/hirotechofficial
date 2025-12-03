/**
 * Error Logger with Stack Traces
 * 
 * Logs errors with full stack traces and context to the database.
 * Ensures all errors are captured with complete debugging information.
 */

import { prisma } from '@/lib/db';
import { safePrismaOperation } from '@/lib/prisma-error-handler';

export type ErrorLevel = 'error' | 'warn' | 'info';

export interface ErrorLogInput {
  level?: ErrorLevel;
  message: string;
  error?: Error | unknown;
  errorType?: string;
  errorCode?: string;
  context?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Extracts stack trace from an error
 */
function getStackTrace(error: unknown): string | null {
  if (error instanceof Error) {
    return error.stack || null;
  }
  return null;
}

/**
 * Gets error type name from an error
 */
function getErrorType(error: unknown): string | null {
  if (error instanceof Error) {
    return error.constructor.name;
  }
  if (typeof error === 'object' && error !== null) {
    return (error as any).constructor?.name || 'Unknown';
  }
  return typeof error;
}

/**
 * Gets error message from an error
 */
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

/**
 * Check if database is ready to accept operations
 */
async function isDatabaseReady(): Promise<boolean> {
  try {
    // Quick health check with timeout
    const timeoutPromise = new Promise<boolean>((_, reject) => 
      setTimeout(() => reject(new Error('Health check timeout')), 2000)
    );
    
    const checkPromise = prisma.$queryRaw`SELECT 1 as check`
      .then(() => true)
      .catch(() => false);
    
    return await Promise.race([checkPromise, timeoutPromise]);
  } catch {
    return false;
  }
}

/**
 * Logs an error with full stack trace and context
 * Non-blocking: errors are caught and logged but don't throw
 * Gracefully falls back to console-only logging if database is not ready
 */
export async function logError(input: ErrorLogInput): Promise<void> {
  try {
    const level = input.level || 'error';
    const errorMessage = input.error ? getErrorMessage(input.error) : input.message;
    const stack = input.error ? getStackTrace(input.error) : null;
    const errorType = input.errorType || (input.error ? getErrorType(input.error) : null);

    // Always log to console first for immediate visibility
    const logMessage = `[ErrorLogger] [${level.toUpperCase()}] ${errorMessage}`;
    if (level === 'error') {
      console.error(logMessage, input.error);
    } else if (level === 'warn') {
      console.warn(logMessage, input.error);
    } else {
      console.log(logMessage, input.error);
    }

    // Check if database is ready before attempting to log
    const dbReady = await isDatabaseReady();
    
    if (!dbReady) {
      // Database not ready, console logging is sufficient
      // Don't try to write to database to avoid circular dependency
      return;
    }

    // Database is ready, attempt to log to database
    await safePrismaOperation(
      async () => {
        await prisma.errorLog.create({
          data: {
            level,
            message: errorMessage,
            stack,
            errorType,
            errorCode: input.errorCode,
            context: input.context ? JSON.parse(JSON.stringify(input.context)) : null,
            metadata: input.metadata ? JSON.parse(JSON.stringify(input.metadata)) : null,
          },
        });
      },
      {
        operationName: 'log error',
        maxRetries: 1, // Reduced from 2 to avoid long delays
        skipLogging: true, // Prevent circular logging of logging errors
      }
    );
  } catch (error) {
    // Non-blocking: log error but don't throw
    // Use console.error directly to ensure it's always logged
    console.error('[ErrorLogger] Failed to log error to database (non-critical):', 
      error instanceof Error ? error.message : String(error));
    // Don't log the full error object to avoid noise
  }
}

/**
 * Logs an error with automatic context extraction
 * Convenience wrapper that extracts common context automatically
 */
export async function logErrorWithContext(
  error: Error | unknown,
  context?: {
    operation?: string;
    requestId?: string;
    userId?: string;
    organizationId?: string;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  await logError({
    level: 'error',
    message: error instanceof Error ? error.message : String(error),
    error,
    context: {
      operation: context?.operation,
      requestId: context?.requestId,
      userId: context?.userId,
      organizationId: context?.organizationId,
      ...context?.metadata,
    },
  });
}

/**
 * Gets error logs within a time range
 */
export async function getErrorLogs(
  startDate: Date,
  endDate: Date,
  options?: {
    level?: ErrorLevel;
    errorType?: string;
    errorCode?: string;
    limit?: number;
  }
): Promise<Array<{
  id: string;
  level: string;
  message: string;
  stack: string | null;
  errorType: string | null;
  errorCode: string | null;
  context: unknown;
  createdAt: Date;
}>> {
  try {
    return await safePrismaOperation(
      async () => {
        return await prisma.errorLog.findMany({
          where: {
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
            ...(options?.level && { level: options.level }),
            ...(options?.errorType && { errorType: options.errorType }),
            ...(options?.errorCode && { errorCode: options.errorCode }),
          },
          select: {
            id: true,
            level: true,
            message: true,
            stack: true,
            errorType: true,
            errorCode: true,
            context: true,
            createdAt: true,
          },
          orderBy: {
            createdAt: 'desc',
          },
          take: options?.limit || 1000,
        });
      },
      {
        operationName: 'get error logs',
        maxRetries: 2,
      }
    );
  } catch (error) {
    console.error('[ErrorLogger] Failed to get error logs:', error);
    return [];
  }
}

/**
 * Cleans up old error logs (older than specified days)
 * Should be run periodically via cron job
 */
export async function cleanupOldErrorLogs(
  olderThanDays: number = 90
): Promise<number> {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

    const result = await safePrismaOperation(
      async () => {
        return await prisma.errorLog.deleteMany({
          where: {
            createdAt: {
              lt: cutoffDate,
            },
          },
        });
      },
      {
        operationName: 'cleanup old error logs',
        maxRetries: 2,
      }
    );

    return result.count;
  } catch (error) {
    console.error('[ErrorLogger] Failed to cleanup old error logs:', error);
    return 0;
  }
}









