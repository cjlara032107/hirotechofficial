/**
 * API Middleware Utilities
 * Helper functions to apply validation, rate limiting, and body size checks to API routes
 */

import { NextRequest, NextResponse } from 'next/server';
import { validateBodySize, BodySizeLimits } from './validate-body-size';
import { rateLimit, RateLimitPresets, RateLimitOptions } from './rate-limit';

export interface ApiMiddlewareOptions {
  rateLimit?: RateLimitOptions | 'strict' | 'standard' | 'generous' | 'auth' | 'fileUpload';
  bodySizeLimit?: number;
  requireAuth?: boolean;
}

/**
 * Apply common API middleware (rate limiting, body size validation)
 * Returns null if all checks pass, or a NextResponse with error if any check fails
 */
export async function applyApiMiddleware(
  request: NextRequest,
  options: ApiMiddlewareOptions = {}
): Promise<NextResponse | null> {
  const { rateLimit: rateLimitOption, bodySizeLimit, requireAuth } = options;

  // Apply rate limiting
  if (rateLimitOption) {
    let rateLimitResponse: NextResponse | null = null;

    if (typeof rateLimitOption === 'string') {
      // Use preset
      switch (rateLimitOption) {
        case 'strict':
          rateLimitResponse = await RateLimitPresets.strict(request);
          break;
        case 'standard':
          rateLimitResponse = await RateLimitPresets.standard(request);
          break;
        case 'generous':
          rateLimitResponse = await RateLimitPresets.generous(request);
          break;
        case 'auth':
          rateLimitResponse = await RateLimitPresets.auth(request);
          break;
        case 'fileUpload':
          rateLimitResponse = await RateLimitPresets.fileUpload(request);
          break;
        default:
          rateLimitResponse = await RateLimitPresets.standard(request);
      }
    } else {
      // Use custom options
      rateLimitResponse = await rateLimit(request, rateLimitOption);
    }

    if (rateLimitResponse) {
      return rateLimitResponse;
    }
  }

  // Apply body size validation (only for POST, PUT, PATCH)
  if (bodySizeLimit !== undefined) {
    const method = request.method.toUpperCase();
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      const bodySizeResponse = await validateBodySize(request, {
        maxSizeBytes: bodySizeLimit,
      });
      if (bodySizeResponse) {
        return bodySizeResponse;
      }
    }
  }

  // All checks passed
  return null;
}

/**
 * Create a middleware function with preset options
 */
export function createApiMiddleware(options: ApiMiddlewareOptions) {
  return async (request: NextRequest): Promise<NextResponse | null> => {
    return applyApiMiddleware(request, options);
  };
}

/**
 * Common middleware presets
 */
export const ApiMiddlewarePresets = {
  /**
   * Standard API endpoint middleware
   */
  standard: createApiMiddleware({
    rateLimit: 'standard',
    bodySizeLimit: BodySizeLimits.MEDIUM,
  }),

  /**
   * Strict API endpoint middleware (for sensitive operations)
   */
  strict: createApiMiddleware({
    rateLimit: 'strict',
    bodySizeLimit: BodySizeLimits.SMALL,
  }),

  /**
   * Auth endpoint middleware
   */
  auth: createApiMiddleware({
    rateLimit: 'auth',
    bodySizeLimit: BodySizeLimits.SMALL,
  }),

  /**
   * File upload endpoint middleware
   */
  fileUpload: createApiMiddleware({
    rateLimit: 'fileUpload',
    bodySizeLimit: BodySizeLimits.VERY_LARGE,
  }),

  /**
   * Large payload endpoint middleware
   */
  largePayload: createApiMiddleware({
    rateLimit: 'standard',
    bodySizeLimit: BodySizeLimits.LARGE,
  }),
};









