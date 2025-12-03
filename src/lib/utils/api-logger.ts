/**
 * Helper utility for consistent API route logging
 * Provides a simple wrapper for common API logging patterns
 */

import { NextRequest, NextResponse } from 'next/server';
import { logger } from './logger';
import { logRequest, logResponse } from './request-logger';

export interface ApiLoggerContext {
  userId?: string;
  organizationId?: string;
  [key: string]: unknown;
}

/**
 * Create a logger context from a request
 * Extracts user information from session if available
 */
export async function createLoggerContext(
  request: NextRequest,
  session?: { user?: { id?: string; organizationId?: string } } | null
): Promise<ApiLoggerContext> {
  const context: ApiLoggerContext = {};

  if (session?.user) {
    context.userId = session.user.id;
    context.organizationId = session.user.organizationId;
  }

  return context;
}

/**
 * Log API route execution with automatic request/response logging
 * 
 * Usage:
 * ```typescript
 * export async function GET(request: NextRequest) {
 *   return withApiLogging(request, async (ctx) => {
 *     // Your route handler code
 *     return NextResponse.json({ data: 'result' });
 *   });
 * }
 * ```
 */
export async function withApiLogging<T>(
  request: NextRequest,
  handler: (context: ApiLoggerContext) => Promise<NextResponse<T>>,
  options?: {
    skipLogging?: boolean;
    extractSession?: (request: NextRequest) => Promise<{ user?: { id?: string; organizationId?: string } } | null>;
  }
): Promise<NextResponse<T>> {
  const startTime = Date.now();

  // Skip logging if requested
  if (options?.skipLogging) {
    return handler({});
  }

  // Extract session if provided
  let session: { user?: { id?: string; organizationId?: string } } | null = null;
  if (options?.extractSession) {
    try {
      session = await options.extractSession(request);
    } catch (error) {
      logger.warn('Failed to extract session for logging', { error });
    }
  }

  // Create logger context
  const context = await createLoggerContext(request, session);

  // Log incoming request
  logRequest(request, context);

  try {
    // Execute handler
    const response = await handler(context);

    // Log response
    logResponse(request, response, startTime, context);

    return response;
  } catch (error) {
    // Log error
    const duration = Date.now() - startTime;
    const url = new URL(request.url);

    logger.error(
      'API route handler error',
      error instanceof Error ? error : new Error(String(error)),
      {
        method: request.method,
        path: url.pathname,
        duration,
        ...context,
      }
    );

    // Create error response
    const errorResponse = NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    );

    logResponse(request, errorResponse, startTime, context);

    return errorResponse as NextResponse<T>;
  }
}









