import { Prisma } from '@prisma/client';
import { connectPrisma } from './db';
import { withRetry } from './db-retry';
import { systemMonitor } from './monitoring/system-monitor';
import { logger } from './utils/logger';

/**
 * Prisma error types that should be retried
 */
const RETRYABLE_ERRORS = [
  'Unable to check out process from the pool',
  'connection pool',
  'P2024', // Prisma connection pool timeout
  'P1001', // Can't reach database
  'P2034', // Database deadlock detected
  'timeout',
  'Connection closed',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'Engine is not yet connected', // Prisma engine not ready
  'Response from the Engine was empty', // Prisma engine error
  'deadlock', // Deadlock errors (case-insensitive matching)
  'Deadlock',
];

/**
 * Determines if a Prisma error is retryable (connection/pool errors)
 * 
 * Checks for common retryable error patterns including:
 * - Connection pool exhaustion (P2024)
 * - Database unreachable (P1001)
 * - Deadlocks (P2034)
 * - Connection timeouts
 * - Engine not ready errors
 * 
 * @param error - The error to check (can be Error, Prisma error, or unknown)
 * @returns True if the error is retryable, false otherwise
 */
export function isRetryablePrismaError(error: unknown): boolean {
  if (!error) return false;
  
  const errorMessage = error instanceof Error ? error.message : String(error);
  const errorCode = (error as any)?.code;
  
  return RETRYABLE_ERRORS.some(pattern => 
    errorMessage.includes(pattern) || 
    errorCode === pattern ||
    (error as any)?.meta?.code === pattern
  );
}

/**
 * Converts a Prisma error into a user-friendly error message
 * 
 * Maps Prisma error codes and messages to human-readable messages:
 * - P2024: Connection pool busy
 * - P1001: Database unreachable
 * - P2002: Unique constraint violation
 * - P2025: Record not found
 * - P2003: Invalid foreign key
 * - P2034: Deadlock
 * 
 * @param error - The error to convert (can be Error, Prisma error, or unknown)
 * @returns User-friendly error message string
 */
export function getPrismaErrorMessage(error: unknown): string {
  if (!error) return 'An unexpected error occurred';
  
  const errorMessage = error instanceof Error ? error.message : String(error);
  const errorCode = (error as any)?.code;
  
  // Connection pool errors
  if (errorMessage.includes('Unable to check out process from the pool') || errorCode === 'P2024') {
    return 'The database is temporarily busy. Please try again in a moment.';
  }
  
  // Connection errors
  if (errorMessage.includes("Can't reach database") || errorCode === 'P1001') {
    return 'Unable to connect to the database. Please try again.';
  }
  
  // Engine not connected errors
  if (errorMessage.includes('Engine is not yet connected') || errorMessage.includes('Response from the Engine was empty')) {
    return 'Database connection is initializing. Please try again in a moment.';
  }
  
  // Timeout errors
  if (errorMessage.includes('timeout') || errorMessage.includes('ETIMEDOUT')) {
    return 'The request took too long. Please try again.';
  }
  
  // Connection closed
  if (errorMessage.includes('Connection closed') || errorMessage.includes('kind: Closed')) {
    return 'Database connection was lost. Please try again.';
  }
  
  // Deadlock errors
  if (errorCode === 'P2034' || errorMessage.toLowerCase().includes('deadlock')) {
    return 'A database conflict occurred. The operation will be retried automatically.';
  }
  
  // Generic Prisma errors
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    switch (error.code) {
      case 'P2002':
        return 'A record with this information already exists.';
      case 'P2025':
        return 'The record you are looking for does not exist.';
      case 'P2003':
        return 'Invalid reference to a related record.';
      case 'P2034':
        return 'A database conflict occurred. The operation will be retried automatically.';
      default:
        return 'A database error occurred. Please try again.';
    }
  }
  
  // Default message
  return 'An error occurred while processing your request. Please try again.';
}

/**
 * Executes a Prisma operation with automatic retry and connection management
 * 
 * This is the recommended way to call Prisma in API routes. It provides:
 * - Automatic retry for transient errors (connection pool, deadlocks, timeouts)
 * - Connection management (ensures connection before operation, reconnects on failure)
 * - Deadlock handling with shorter backoff
 * - Error logging with context
 * - User-friendly error messages
 * 
 * @template T - The return type of the operation
 * @param operation - The Prisma operation to execute (async function)
 * @param options - Retry and operation configuration
 * @param options.maxRetries - Maximum number of retry attempts (default: 3)
 * @param options.initialDelay - Initial delay between retries in ms (default: 1000)
 * @param options.maxDelay - Maximum delay between retries in ms (default: 10000)
 * @param options.operationName - Name of the operation for logging (default: 'database operation')
 * @returns Promise resolving to the operation result
 * @throws Error with user-friendly message if all retries fail
 * 
 * @example
 * ```typescript
 * const user = await safePrismaOperation(
 *   () => prisma.user.findUnique({ where: { id } }),
 *   { operationName: 'findUser', maxRetries: 5 }
 * );
 * ```
 */
export async function safePrismaOperation<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    initialDelay?: number;
    maxDelay?: number;
    operationName?: string;
    skipLogging?: boolean;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 10000,
    operationName = 'database operation',
    skipLogging = false,
  } = options;

  try {
    // Ensure connection is established before operation
    await connectPrisma();
    
    // Execute with retry logic
    return await withRetry(
      async () => {
        try {
          return await operation();
        } catch (error) {
          // Check if it's a deadlock - use shorter backoff for deadlocks
          const prismaError = error as any;
          const isDeadlock = prismaError?.code === 'P2034' || 
                            prismaError?.message?.toLowerCase().includes('deadlock');
          
          if (isDeadlock) {
            // For deadlocks, use shorter initial delay with jitter
            const jitter = Math.random() * 100;
            await new Promise(resolve => setTimeout(resolve, 50 + jitter));
          }
          
          // If it's a connection error, try to reconnect
          if (isRetryablePrismaError(error)) {
            // Reset connection state to force reconnection
            const { prisma } = await import('./db');
            try {
              await prisma.$disconnect();
            } catch {
              // Ignore disconnect errors
            }
            // Wait a bit before reconnecting
            await new Promise(resolve => setTimeout(resolve, 500));
            // Reconnect with retry
            await connectPrisma();
          }
          throw error;
        }
      },
      {
        maxRetries,
        initialDelay,
        maxDelay,
        retryableErrors: RETRYABLE_ERRORS,
      }
    );
  } catch (error) {
    // Log the error with context and stack trace
    logger.error(`Safe Prisma operation failed after ${maxRetries} retries`, error as Error, { operationName, maxRetries });
    
    // Track error in system monitor
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const errorObj = error as any;
    const errorType = errorObj?.code ? `Prisma.${errorObj.code}` : 'Prisma.Unknown';
    const errorCode = errorObj?.code || 'UNKNOWN';
    const errorMessage = errorObj?.message || String(error);
    
    systemMonitor.recordError({
      errorType,
      errorCode,
      errorMessage,
      stack: error instanceof Error ? error.stack : undefined,
      context: {
        operationName,
        maxRetries,
        initialDelay: options.initialDelay,
        maxDelay: options.maxDelay,
      },
      timestamp: Date.now(),
    });
    
    // Log to database with full stack trace (non-blocking)
    // Skip if skipLogging is true to prevent circular dependency
    if (!skipLogging) {
      // Use dynamic import to avoid circular dependency (error-logger uses safePrismaOperation)
      import('@/lib/logging/error-logger').then(({ logErrorWithContext }) => {
        return logErrorWithContext(error, {
          operation: operationName,
          metadata: {
            maxRetries,
            initialDelay: options.initialDelay,
            maxDelay: options.maxDelay,
          },
        });
      }).catch(() => {
        // Silently fail - error logging should not break the app
        // This catch handles both the import and the logErrorWithContext call
      });
    }
    
    // Re-throw with user-friendly message
    const friendlyMessage = getPrismaErrorMessage(error);
    const enhancedError = new Error(friendlyMessage);
    (enhancedError as any).originalError = error;
    (enhancedError as any).isPrismaError = true;
    throw enhancedError;
  }
}

/**
 * Handles Prisma errors for API routes and returns appropriate HTTP response details
 * 
 * Analyzes the error and returns:
 * - User-friendly error message
 * - Appropriate HTTP status code (503 for retryable, 500 for permanent)
 * - Whether the client should retry the request
 * 
 * @param error - The error to handle (can be Error, Prisma error, or unknown)
 * @param defaultMessage - Default message if error cannot be categorized (default: generic message)
 * @returns Object with message, HTTP status code, and retry recommendation
 * 
 * @example
 * ```typescript
 * try {
 *   await prisma.user.create({ data });
 * } catch (error) {
 *   const { message, status, shouldRetry } = handlePrismaError(error);
 *   return NextResponse.json({ error: message }, { status });
 * }
 * ```
 */
export function handlePrismaError(error: unknown, defaultMessage = 'An error occurred while processing your request.'): {
  message: string;
  status: number;
  shouldRetry: boolean;
} {
  const isRetryable = isRetryablePrismaError(error);
  const message = getPrismaErrorMessage(error);
  
  // For retryable errors, return 503 (Service Unavailable) to indicate temporary issue
  // For non-retryable errors, return 500 (Internal Server Error)
  const status = isRetryable ? 503 : 500;
  
  return {
    message,
    status,
    shouldRetry: isRetryable,
  };
}

