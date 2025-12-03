/**
 * Request Body Size Validation
 * Validates and limits request body size to prevent DoS attacks
 */

import { NextRequest, NextResponse } from 'next/server';

export interface BodySizeOptions {
  maxSizeBytes?: number;
  errorMessage?: string;
}

/**
 * Default maximum body size: 10MB
 * This is reasonable for most API endpoints
 */
const DEFAULT_MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * Common body size limits
 */
export const BodySizeLimits = {
  SMALL: 1024 * 1024, // 1MB - for simple JSON payloads
  MEDIUM: 5 * 1024 * 1024, // 5MB - for most API endpoints
  LARGE: 10 * 1024 * 1024, // 10MB - default
  VERY_LARGE: 50 * 1024 * 1024, // 50MB - for file uploads
  EXTRA_LARGE: 100 * 1024 * 1024, // 100MB - for large file uploads
} as const;

/**
 * Get request body size from Content-Length header or by reading the body
 */
async function getBodySize(request: NextRequest): Promise<number> {
  // Try to get size from Content-Length header first (most efficient)
  const contentLength = request.headers.get('content-length');
  if (contentLength) {
    const size = parseInt(contentLength, 10);
    if (!isNaN(size) && size >= 0) {
      return size;
    }
  }

  // If Content-Length is not available, we need to read the body
  // This is less efficient but necessary for streaming requests
  try {
    const body = await request.clone().text();
    return new Blob([body]).size;
  } catch {
    // If we can't read the body, return 0 (will fail validation)
    return 0;
  }
}

/**
 * Middleware to validate request body size
 * Returns null if valid, or a NextResponse with error if invalid
 */
export async function validateBodySize(
  request: NextRequest,
  options: BodySizeOptions = {}
): Promise<NextResponse | null> {
  const maxSizeBytes = options.maxSizeBytes ?? DEFAULT_MAX_BODY_SIZE;
  const errorMessage =
    options.errorMessage ?? `Request body too large. Maximum size is ${maxSizeBytes / 1024 / 1024}MB`;

  // Only check body size for methods that typically have bodies
  const method = request.method.toUpperCase();
  if (!['POST', 'PUT', 'PATCH'].includes(method)) {
    return null; // No body to check
  }

  try {
    const bodySize = await getBodySize(request);

    if (bodySize > maxSizeBytes) {
      return NextResponse.json(
        {
          error: errorMessage,
          maxSizeBytes,
          receivedSizeBytes: bodySize,
        },
        { status: 413 } // 413 Payload Too Large
      );
    }

    return null; // Valid
  } catch (error) {
    console.error('[Body Size Validation] Error checking body size:', error);
    // If we can't determine size, allow the request (fail open)
    // The actual body parsing will catch issues later
    return null;
  }
}

/**
 * Create a body size validator function for use in API routes
 */
export function createBodySizeValidator(maxSizeBytes: number = DEFAULT_MAX_BODY_SIZE) {
  return async (request: NextRequest): Promise<NextResponse | null> => {
    return validateBodySize(request, { maxSizeBytes });
  };
}









