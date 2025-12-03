/**
 * Wrapper utility for API routes to automatically track errors
 */

import { NextRequest, NextResponse } from 'next/server';
import { trackError } from './track-error';
import { auth } from '@/auth';

/**
 * Wraps an API route handler to automatically track errors
 */
export function withErrorTracking<T extends (...args: unknown[]) => Promise<NextResponse>>(
  handler: T,
  options?: {
    endpoint?: string;
    extractUserId?: (request: NextRequest) => Promise<string | undefined>;
  }
): T {
  return (async (...args: Parameters<T>) => {
    const request = args[0] as NextRequest;
    const endpoint = options?.endpoint || new URL(request.url).pathname;
    
    try {
      // Extract user ID if available
      let userId: string | undefined;
      if (options?.extractUserId) {
        try {
          userId = await options.extractUserId(request);
        } catch {
          // Ignore errors in user extraction
        }
      } else {
        // Try to get user from session
        try {
          const session = await auth();
          userId = session?.user?.id;
        } catch {
          // Ignore auth errors
        }
      }

      // Execute handler
      const response = await handler(...args);

      // Track non-2xx responses as errors
      if (response.status >= 400) {
        const errorData = await response.clone().json().catch(() => ({}));
        trackError(
          new Error(`API error: ${response.status} - ${errorData.error || 'Unknown error'}`),
          {
            endpoint,
            userId,
            status: response.status,
            errorData,
          }
        );
      }

      return response;
    } catch (error) {
      // Track the error
      let userId: string | undefined;
      try {
        const session = await auth();
        userId = session?.user?.id;
      } catch {
        // Ignore auth errors
      }

      trackError(error, {
        endpoint,
        userId,
      });

      // Re-throw to let Next.js handle it
      throw error;
    }
  }) as T;
}









