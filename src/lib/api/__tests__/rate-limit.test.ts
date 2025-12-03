/**
 * Tests for rate limiting
 */

import { NextRequest } from 'next/server';
import { rateLimit, RateLimitPresets } from '../rate-limit';

// Mock NextRequest
function createMockRequest(pathname = '/api/test'): NextRequest {
  const headers = new Headers();
  headers.set('x-forwarded-for', '127.0.0.1');

  return {
    method: 'GET',
    headers,
    nextUrl: {
      pathname,
    },
  } as unknown as NextRequest;
}

describe('rateLimit', () => {
  beforeEach(() => {
    // Clear any existing rate limit state between tests
    // Note: In a real implementation, you'd want to reset the store
  });

  it('should allow requests within limit', async () => {
    const request = createMockRequest();
    const result = await rateLimit(request, {
      windowMs: 60000, // 1 minute
      max: 10,
    });
    expect(result).toBeNull(); // Null means allowed
  });

  it('should reject requests exceeding limit', async () => {
    const request = createMockRequest();
    const options = {
      windowMs: 60000, // 1 minute
      max: 2, // Very low limit for testing
    };

    // Make requests up to the limit
    for (let i = 0; i < 2; i++) {
      const result = await rateLimit(request, options);
      expect(result).toBeNull(); // Should be allowed
    }

    // This one should be rate limited
    const result = await rateLimit(request, options);
    expect(result).not.toBeNull();
    expect(result?.status).toBe(429);
  });

  it('should include Retry-After header', async () => {
    const request = createMockRequest();
    const options = {
      windowMs: 60000,
      max: 1,
    };

    // First request should be allowed
    await rateLimit(request, options);

    // Second request should be rate limited
    const result = await rateLimit(request, options);
    expect(result).not.toBeNull();
    expect(result?.headers.get('Retry-After')).toBeTruthy();
  });

  it('should use different keys for different IPs', async () => {
    const request1 = createMockRequest();
    request1.headers.set('x-forwarded-for', '127.0.0.1');

    const request2 = createMockRequest();
    request2.headers.set('x-forwarded-for', '192.168.1.1');

    const options = {
      windowMs: 60000,
      max: 1,
    };

    // Both should be allowed (different IPs)
    const result1 = await rateLimit(request1, options);
    const result2 = await rateLimit(request2, options);

    expect(result1).toBeNull();
    expect(result2).toBeNull();
  });

  it('should use different keys for different paths', async () => {
    const request1 = createMockRequest('/api/endpoint1');
    const request2 = createMockRequest('/api/endpoint2');

    const options = {
      windowMs: 60000,
      max: 1,
    };

    // Both should be allowed (different paths)
    const result1 = await rateLimit(request1, options);
    const result2 = await rateLimit(request2, options);

    expect(result1).toBeNull();
    expect(result2).toBeNull();
  });
});

describe('RateLimitPresets', () => {
  it('should have strict preset', async () => {
    const request = createMockRequest();
    const result = await RateLimitPresets.strict(request);
    expect(result).toBeNull(); // First request should be allowed
  });

  it('should have standard preset', async () => {
    const request = createMockRequest();
    const result = await RateLimitPresets.standard(request);
    expect(result).toBeNull();
  });

  it('should have auth preset', async () => {
    const request = createMockRequest();
    const result = await RateLimitPresets.auth(request);
    expect(result).toBeNull();
  });
});









