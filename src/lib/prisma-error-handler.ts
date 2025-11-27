import { Prisma } from '@prisma/client';
import { connectPrisma } from './db';
import { withRetry } from './db-retry';

/**
 * Prisma error types that should be retried
 */
const RETRYABLE_ERRORS = [
  'Unable to check out process from the pool',
  'connection pool',
  'P2024', // Prisma connection pool timeout
  'P1001', // Can't reach database
  'timeout',
  'Connection closed',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'Engine is not yet connected', // Prisma engine not ready
  'Response from the Engine was empty', // Prisma engine error
];

/**
 * Checks if an error is a Prisma connection/pool error that should be retried
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
 * Gets a user-friendly error message from a Prisma error
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
  
  // Generic Prisma errors
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    switch (error.code) {
      case 'P2002':
        return 'A record with this information already exists.';
      case 'P2025':
        return 'The record you are looking for does not exist.';
      case 'P2003':
        return 'Invalid reference to a related record.';
      default:
        return 'A database error occurred. Please try again.';
    }
  }
  
  // Default message
  return 'An error occurred while processing your request. Please try again.';
}

/**
 * Executes a Prisma operation with automatic retry and connection management
 * This is the recommended way to call Prisma in API routes
 */
export async function safePrismaOperation<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    initialDelay?: number;
    maxDelay?: number;
    operationName?: string;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 10000,
    operationName = 'database operation',
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
    // Log the error with context
    console.error(`[Safe Prisma] ${operationName} failed after ${maxRetries} retries:`, error);
    
    // Re-throw with user-friendly message
    const friendlyMessage = getPrismaErrorMessage(error);
    const enhancedError = new Error(friendlyMessage);
    (enhancedError as any).originalError = error;
    (enhancedError as any).isPrismaError = true;
    throw enhancedError;
  }
}

/**
 * Wrapper for API routes that handles Prisma errors gracefully
 * Returns a NextResponse with appropriate error message
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

