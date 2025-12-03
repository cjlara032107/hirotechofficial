/**
 * AI Request Wrapper
 * 
 * Integrates request queuing, timeout handling, circuit breaker,
 * and performance monitoring for all AI API calls.
 */

import { requestQueue, RequestPriority } from './request-queue';
import { aiCircuitBreakers } from './circuit-breaker';
import { performanceMonitor } from './performance-monitor';

export interface AIRequestOptions {
  priority?: RequestPriority;
  timeout?: number; // Request timeout in ms
  operation: string; // Operation name for logging
  circuitBreaker?: keyof typeof aiCircuitBreakers;
  apiKeyId?: string;
  requestId?: string;
}

const DEFAULT_TIMEOUT = 60000; // 60 seconds default timeout
const DEFAULT_PRIORITY = RequestPriority.NORMAL;

/**
 * Execute an AI request with all resilience features
 */
export async function executeAIRequest<T>(
  fn: () => Promise<T>,
  options: AIRequestOptions
): Promise<T> {
  const {
    priority = DEFAULT_PRIORITY,
    timeout = DEFAULT_TIMEOUT,
    operation,
    circuitBreaker,
    apiKeyId,
    requestId,
  } = options;

  const startTime = Date.now();
  let success = false;
  let errorType: string | undefined;

  try {
    // Get circuit breaker if specified
    const breaker = circuitBreaker
      ? aiCircuitBreakers[circuitBreaker]
      : undefined;

    // Execute with circuit breaker protection
    const executeWithBreaker = async (): Promise<T> => {
      if (breaker) {
        return breaker.execute(fn);
      }
      return fn();
    };

    // Queue the request
    const result = await requestQueue.enqueue(
      executeWithBreaker,
      priority,
      timeout
    );

    success = true;
    const duration = Date.now() - startTime;

    // Record success metric
    performanceMonitor.record({
      operation,
      duration,
      success: true,
      timestamp: Date.now(),
      apiKeyId,
      requestId,
      priority: RequestPriority[priority],
    });

    return result;
  } catch (error) {
    success = false;
    const duration = Date.now() - startTime;
    const errorMessage =
      error instanceof Error ? error.message : String(error);

    // Determine error type
    if (errorMessage.includes('timeout') || errorMessage.includes('timed out')) {
      errorType = 'TIMEOUT';
    } else if (errorMessage.includes('429') || errorMessage.includes('rate limit')) {
      errorType = 'RATE_LIMIT';
    } else if (
      errorMessage.includes('401') ||
      errorMessage.includes('403') ||
      errorMessage.includes('Unauthorized')
    ) {
      errorType = 'AUTH_ERROR';
    } else if (errorMessage.includes('Circuit breaker')) {
      errorType = 'CIRCUIT_OPEN';
    } else {
      errorType = 'OTHER';
    }

    // Record failure metric
    performanceMonitor.record({
      operation,
      duration,
      success: false,
      errorType,
      timestamp: Date.now(),
      apiKeyId,
      requestId,
      priority: RequestPriority[priority],
    });

    // Re-throw the error
    throw error;
  }
}

/**
 * Helper to get timeout based on operation type
 */
export function getTimeoutForOperation(operation: string): number {
  // Longer operations get more time
  if (operation.includes('analyze') || operation.includes('conversation')) {
    return 120000; // 2 minutes for analysis
  }
  if (operation.includes('assistant') || operation.includes('message')) {
    return 90000; // 90 seconds for assistant
  }
  if (operation.includes('personalize') || operation.includes('follow-up')) {
    return 60000; // 60 seconds for personalization
  }
  return DEFAULT_TIMEOUT;
}

/**
 * Helper to get priority based on operation context
 */
export function getPriorityForOperation(
  operation: string,
  isUserInitiated: boolean = false
): RequestPriority {
  if (isUserInitiated) {
    return RequestPriority.HIGH;
  }
  if (operation.includes('assistant') || operation.includes('message')) {
    return RequestPriority.HIGH; // User-facing operations
  }
  if (operation.includes('background') || operation.includes('batch')) {
    return RequestPriority.LOW; // Background tasks
  }
  return RequestPriority.NORMAL;
}









