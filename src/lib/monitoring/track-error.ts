/**
 * Utility function to track errors in API routes and other parts of the application
 */

import { systemMonitor } from './system-monitor';

export interface ErrorTrackingContext {
  endpoint?: string;
  userId?: string;
  requestId?: string;
  [key: string]: unknown;
}

/**
 * Track an error in the system monitor
 */
export function trackError(
  error: unknown,
  context?: ErrorTrackingContext
): void {
  const errorObj = error instanceof Error ? error : new Error(String(error));
  
  // Determine error type
  let errorType = 'Unknown';
  let errorCode: string | undefined;
  
  // Check for Prisma errors
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const errorAny = error as any;
  if (errorAny?.code) {
    errorCode = errorAny.code;
    errorType = `Prisma.${errorCode}`;
  } else if (errorObj.name) {
    errorType = errorObj.name;
  }
  
  // Check for HTTP errors
  if (errorAny?.status) {
    errorCode = String(errorAny.status);
    errorType = `HTTP.${errorCode}`;
  }
  
  // Check for Axios errors
  if (errorAny?.isAxiosError) {
    errorCode = String(errorAny?.response?.status || 'UNKNOWN');
    errorType = `Axios.${errorCode}`;
  }
  
  systemMonitor.recordError({
    errorType,
    errorCode,
    errorMessage: errorObj.message || String(error),
    stack: errorObj.stack,
    context: {
      ...context,
      errorName: errorObj.name,
    },
    timestamp: Date.now(),
    endpoint: context?.endpoint,
    userId: context?.userId,
  });
}

/**
 * Track a database query error
 */
export function trackDatabaseError(
  error: unknown,
  query?: string,
  context?: ErrorTrackingContext
): void {
  const errorObj = error instanceof Error ? error : new Error(String(error));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const prismaError = error as any;
  
  systemMonitor.recordError({
    errorType: prismaError?.code ? `Prisma.${prismaError.code}` : 'Database.Unknown',
    errorCode: prismaError?.code || 'UNKNOWN',
    errorMessage: errorObj.message || String(error),
    stack: errorObj.stack,
    context: {
      ...context,
      query: query?.substring(0, 200), // Limit query length
    },
    timestamp: Date.now(),
    endpoint: context?.endpoint,
    userId: context?.userId,
  });
}

