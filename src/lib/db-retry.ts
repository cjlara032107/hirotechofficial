import { prisma } from '@/lib/db';

/**
 * Retry wrapper for Prisma operations that may fail due to connection pool exhaustion
 * Uses exponential backoff to handle temporary pool exhaustion
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    initialDelay?: number;
    maxDelay?: number;
    retryableErrors?: string[];
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000, // 1 second
    maxDelay = 10000, // 10 seconds
    retryableErrors = [
      'Unable to check out process from the pool',
      'connection pool',
      'P2024', // Prisma connection pool timeout
      'P1001', // Can't reach database
      'timeout',
    ],
  } = options;

  let lastError: unknown;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error: unknown) {
      lastError = error;
      const errorMessage = error instanceof Error ? error.message : String(error);
      const errorCode = (error as any)?.code;
      
      // Check if error is retryable
      const isRetryable = retryableErrors.some(pattern => 
        errorMessage.includes(pattern) || errorCode === pattern
      );
      
      // If not retryable or last attempt, throw immediately
      if (!isRetryable || attempt === maxRetries) {
        throw error;
      }
      
      // Calculate delay with exponential backoff
      const delay = Math.min(initialDelay * Math.pow(2, attempt - 1), maxDelay);
      
      console.warn(
        `[DB Retry] Attempt ${attempt}/${maxRetries} failed (${errorMessage}), retrying in ${delay}ms...`
      );
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  // Should never reach here, but TypeScript needs it
  throw lastError;
}

/**
 * Helper to wrap Prisma queries with retry logic
 */
export function prismaWithRetry<T>(
  operation: () => Promise<T>,
  options?: Parameters<typeof withRetry>[1]
): Promise<T> {
  return withRetry(operation, options);
}

