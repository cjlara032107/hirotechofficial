/**
 * Rate Limiting Middleware
 * Provides rate limiting for API endpoints using in-memory store or Redis
 */

import { NextRequest, NextResponse } from 'next/server';

export interface RateLimitOptions {
  windowMs: number; // Time window in milliseconds
  max: number; // Maximum number of requests per window
  message?: string;
  keyGenerator?: (request: NextRequest) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number; // Unix timestamp in seconds
}

/**
 * In-memory rate limit store
 * For production, consider using Redis for distributed rate limiting
 */
class MemoryRateLimitStore {
  private store = new Map<string, { count: number; resetTime: number }>();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    // Clean up expired entries every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, value] of this.store.entries()) {
      if (now > value.resetTime) {
        this.store.delete(key);
      }
    }
  }

  async get(key: string): Promise<{ count: number; resetTime: number } | null> {
    const entry = this.store.get(key);
    if (!entry) {
      return null;
    }

    // Check if expired
    if (Date.now() > entry.resetTime) {
      this.store.delete(key);
      return null;
    }

    return entry;
  }

  async set(key: string, count: number, resetTime: number): Promise<void> {
    this.store.set(key, { count, resetTime });
  }

  async increment(key: string, windowMs: number): Promise<{ count: number; resetTime: number }> {
    const now = Date.now();
    const entry = await this.get(key);

    if (!entry || now > entry.resetTime) {
      // Create new entry
      const resetTime = now + windowMs;
      await this.set(key, 1, resetTime);
      return { count: 1, resetTime };
    }

    // Increment existing entry
    const newCount = entry.count + 1;
    await this.set(key, newCount, entry.resetTime);
    return { count: newCount, resetTime: entry.resetTime };
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }
}

// Singleton instance
const memoryStore = new MemoryRateLimitStore();

// Cleanup on process exit (graceful shutdown)
// Note: In Next.js Edge Runtime, process events may not be available
if (typeof process !== 'undefined' && process.on) {
  const cleanup = () => {
    memoryStore.destroy();
  };
  
  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);
  // For Next.js, also cleanup on exit
  if (typeof process.once === 'function') {
    process.once('exit', cleanup);
  }
}

/**
 * Default key generator: uses IP address + pathname
 */
function defaultKeyGenerator(request: NextRequest): string {
  // Get IP address from headers (respects proxies)
  const forwardedFor = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const ip = forwardedFor?.split(',')[0]?.trim() || realIp || 'unknown';

  // Include pathname to rate limit per endpoint
  const pathname = request.nextUrl.pathname;

  return `${ip}:${pathname}`;
}

/**
 * Rate limit middleware
 * Returns null if request is allowed, or NextResponse with 429 if rate limited
 */
export async function rateLimit(
  request: NextRequest,
  options: RateLimitOptions
): Promise<NextResponse | null> {
  const {
    windowMs,
    max,
    message = 'Too many requests, please try again later',
    keyGenerator = defaultKeyGenerator,
  } = options;

  const key = keyGenerator(request);
  const result = await memoryStore.increment(key, windowMs);

  // Set rate limit headers
  const resetTimeSeconds = Math.ceil(result.resetTime / 1000);
  const remaining = Math.max(0, max - result.count);

  // Check if limit exceeded
  if (result.count > max) {
    return NextResponse.json(
      {
        error: message,
        retryAfter: Math.ceil((result.resetTime - Date.now()) / 1000),
      },
      {
        status: 429, // Too Many Requests
        headers: {
          'Retry-After': Math.ceil((result.resetTime - Date.now()) / 1000).toString(),
          'X-RateLimit-Limit': max.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': resetTimeSeconds.toString(),
        },
      }
    );
  }

  // Request is allowed, but we return null to indicate no error
  // The headers will be set by the caller if needed
  return null;
}

/**
 * Create a rate limiter function with preset options
 */
export function createRateLimiter(options: RateLimitOptions) {
  return async (request: NextRequest): Promise<NextResponse | null> => {
    return rateLimit(request, options);
  };
}

/**
 * Common rate limit presets
 */
export const RateLimitPresets = {
  /**
   * Strict rate limit: 10 requests per minute
   */
  strict: createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 10,
    message: 'Too many requests. Please limit to 10 requests per minute.',
  }),

  /**
   * Standard rate limit: 100 requests per minute
   */
  standard: createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    message: 'Too many requests. Please limit to 100 requests per minute.',
  }),

  /**
   * Generous rate limit: 1000 requests per minute
   */
  generous: createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 1000,
    message: 'Too many requests. Please limit to 1000 requests per minute.',
  }),

  /**
   * Per-hour rate limit: 1000 requests per hour
   */
  perHour: createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1000,
    message: 'Too many requests. Please limit to 1000 requests per hour.',
  }),

  /**
   * Per-day rate limit: 10000 requests per day
   */
  perDay: createRateLimiter({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 10000,
    message: 'Too many requests. Please limit to 10000 requests per day.',
  }),

  /**
   * Auth endpoints: 5 requests per minute
   */
  auth: createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 5,
    message: 'Too many authentication attempts. Please try again in a minute.',
  }),

  /**
   * File upload endpoints: 10 requests per minute
   */
  fileUpload: createRateLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 10,
    message: 'Too many file uploads. Please limit to 10 uploads per minute.',
  }),
};

/**
 * Get rate limit info without blocking the request
 */
export async function getRateLimitInfo(
  request: NextRequest,
  options: RateLimitOptions
): Promise<RateLimitInfo> {
  const keyGenerator = options.keyGenerator || defaultKeyGenerator;
  const key = keyGenerator(request);
  const entry = await memoryStore.get(key);

  if (!entry) {
    return {
      limit: options.max,
      remaining: options.max,
      reset: Math.ceil((Date.now() + options.windowMs) / 1000),
    };
  }

  return {
    limit: options.max,
    remaining: Math.max(0, options.max - entry.count),
    reset: Math.ceil(entry.resetTime / 1000),
  };
}

