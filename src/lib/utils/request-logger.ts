/**
 * Request/Response logging utility for API routes
 */

import { NextRequest, NextResponse } from 'next/server';
import { logger } from './logger';

export interface RequestLogContext extends Record<string, unknown> {
  method: string;
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  userId?: string;
  organizationId?: string;
  ip?: string;
  userAgent?: string;
}

export interface ResponseLogContext extends Record<string, unknown> {
  status: number;
  duration: number;
  responseSize?: number;
}

/**
 * Extract relevant headers for logging (excluding sensitive data)
 */
function extractHeaders(request: NextRequest): Record<string, string> {
  const headers: Record<string, string> = {};
  const relevantHeaders = [
    'content-type',
    'content-length',
    'user-agent',
    'referer',
    'origin',
    'x-forwarded-for',
    'x-real-ip',
  ];

  relevantHeaders.forEach((headerName) => {
    const value = request.headers.get(headerName);
    if (value) {
      headers[headerName] = value;
    }
  });

  return headers;
}

/**
 * Extract IP address from request
 */
function extractIp(request: NextRequest): string | undefined {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    undefined
  );
}

/**
 * Get response body size (approximate)
 */
function getResponseBodySize(response: NextResponse): number | undefined {
  try {
    const contentLength = response.headers.get('content-length');
    if (contentLength) {
      return parseInt(contentLength, 10);
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Logs an incoming HTTP request with context information
 * 
 * Extracts and logs relevant request information including:
 * - HTTP method and path
 * - Query parameters
 * - Headers (excluding sensitive data)
 * - Client IP address
 * - User agent
 * - User and organization context (if provided)
 * 
 * @param request - Next.js request object
 * @param context - Optional context with user and organization information
 * @param context.userId - User ID making the request
 * @param context.organizationId - Organization ID for the request
 */
export function logRequest(
  request: NextRequest,
  context?: {
    userId?: string;
    organizationId?: string;
  }
): void {
  const url = new URL(request.url);
  const queryParams: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    queryParams[key] = value;
  });

  const logContext: RequestLogContext = {
    method: request.method,
    path: url.pathname,
    query: Object.keys(queryParams).length > 0 ? queryParams : undefined,
    headers: extractHeaders(request),
    ip: extractIp(request),
    userAgent: request.headers.get('user-agent') || undefined,
    userId: context?.userId,
    organizationId: context?.organizationId,
  };

  logger.info('Incoming request', logContext);
}

/**
 * Logs an outgoing HTTP response with performance metrics
 * 
 * Logs response information including:
 * - HTTP status code
 * - Request duration
 * - Response size
 * - Log level based on status and duration:
 *   - Error (500+): Server errors
 *   - Warn (400-499): Client errors or slow requests (>5s)
 *   - Info: Successful requests
 * 
 * @param request - Next.js request object
 * @param response - Next.js response object
 * @param startTime - Timestamp when request started (from Date.now())
 * @param context - Optional context with user and organization information
 * @param context.userId - User ID making the request
 * @param context.organizationId - Organization ID for the request
 */
export function logResponse(
  request: NextRequest,
  response: NextResponse,
  startTime: number,
  context?: {
    userId?: string;
    organizationId?: string;
  }
): void {
  const duration = Date.now() - startTime;
  const url = new URL(request.url);
  
  const responseContext: ResponseLogContext = {
    status: response.status,
    duration,
    responseSize: getResponseBodySize(response),
  };

  const logContext: RequestLogContext & ResponseLogContext = {
    method: request.method,
    path: url.pathname,
    status: response.status,
    duration,
    responseSize: responseContext.responseSize,
    userId: context?.userId,
    organizationId: context?.organizationId,
    ip: extractIp(request),
  };

  // Log level based on status code
  if (response.status >= 500) {
    logger.error('Request failed with server error', undefined, logContext);
  } else if (response.status >= 400) {
    logger.warn('Request failed with client error', logContext);
  } else if (duration > 5000) {
    logger.warn('Slow request detected', logContext);
  } else {
    logger.info('Request completed', logContext);
  }
}

/**
 * Wraps an API route handler with automatic request/response logging
 * 
 * This higher-order function adds logging to API route handlers:
 * - Logs incoming requests with context
 * - Logs outgoing responses with status and duration
 * - Logs errors with full context
 * - Supports optional context extraction and logging skip conditions
 * 
 * @template T - The handler function type
 * @param handler - The API route handler function to wrap
 * @param options - Optional configuration
 * @param options.skipLogging - Function to determine if logging should be skipped for a request
 * @param options.extractContext - Async function to extract user/org context from request
 * @returns Wrapped handler function with logging
 * 
 * @example
 * ```typescript
 * export const GET = withRequestLogging(
 *   async (request: NextRequest) => {
 *     const data = await fetchData();
 *     return NextResponse.json(data);
 *   },
 *   {
 *     extractContext: async (req) => {
 *       const session = await getSession(req);
 *       return {
 *         userId: session?.user?.id,
 *         organizationId: session?.user?.organizationId
 *       };
 *     }
 *   }
 * );
 * ```
 */
export function withRequestLogging<T extends (...args: unknown[]) => Promise<NextResponse>>(
  handler: T,
  options?: {
    skipLogging?: (request: NextRequest) => boolean;
    extractContext?: (request: NextRequest) => Promise<{
      userId?: string;
      organizationId?: string;
    }>;
  }
): T {
  return (async (...args: Parameters<T>) => {
    const request = args[0] as NextRequest;
    const startTime = Date.now();

    // Skip logging if requested
    if (options?.skipLogging?.(request)) {
      return handler(...args);
    }

    // Extract context (user info, etc.)
    let context: { userId?: string; organizationId?: string } = {};
    if (options?.extractContext) {
      try {
        context = await options.extractContext(request);
      } catch (error) {
        logger.warn('Failed to extract request context', { error });
      }
    }

    // Log incoming request
    logRequest(request, context);

    try {
      // Execute handler
      const response = await handler(...args);

      // Log response
      logResponse(request, response, startTime, context);

      return response;
    } catch (error) {
      // Log error
      const duration = Date.now() - startTime;
      const url = new URL(request.url);
      
      logger.error(
        'Request handler threw error',
        error instanceof Error ? error : new Error(String(error)),
        {
          method: request.method,
          path: url.pathname,
          duration,
          userId: context?.userId,
          organizationId: context?.organizationId,
        }
      );

      // Re-throw to let Next.js handle it
      throw error;
    }
  }) as T;
}

