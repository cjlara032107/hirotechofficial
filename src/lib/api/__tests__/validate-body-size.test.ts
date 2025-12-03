/**
 * Tests for body size validation
 */

import { NextRequest } from 'next/server';
import { validateBodySize, BodySizeLimits } from '../validate-body-size';

// Mock NextRequest
function createMockRequest(body: string, contentLength?: string): NextRequest {
  const headers = new Headers();
  if (contentLength) {
    headers.set('content-length', contentLength);
  }

  return {
    method: 'POST',
    headers,
    json: async () => JSON.parse(body),
    text: async () => body,
    clone: function () {
      return this;
    },
    nextUrl: {
      pathname: '/api/test',
    },
  } as unknown as NextRequest;
}

describe('validateBodySize', () => {
  describe('GET requests', () => {
    it('should skip validation for GET requests', async () => {
      const request = createMockRequest('', '0');
      request.method = 'GET';
      const result = await validateBodySize(request);
      expect(result).toBeNull();
    });
  });

  describe('POST requests', () => {
    it('should accept requests within size limit', async () => {
      const smallBody = 'a'.repeat(1000); // 1KB
      const request = createMockRequest(smallBody, '1000');
      const result = await validateBodySize(request, {
        maxSizeBytes: BodySizeLimits.SMALL,
      });
      expect(result).toBeNull();
    });

    it('should reject requests exceeding size limit', async () => {
      const largeBody = 'a'.repeat(2 * 1024 * 1024); // 2MB
      const request = createMockRequest(largeBody, String(2 * 1024 * 1024));
      const result = await validateBodySize(request, {
        maxSizeBytes: BodySizeLimits.SMALL, // 1MB limit
      });
      expect(result).not.toBeNull();
      expect(result?.status).toBe(413);
    });

    it('should use Content-Length header when available', async () => {
      const request = createMockRequest('', String(2 * 1024 * 1024));
      const result = await validateBodySize(request, {
        maxSizeBytes: BodySizeLimits.SMALL,
      });
      expect(result).not.toBeNull();
    });

    it('should read body when Content-Length is not available', async () => {
      const body = 'a'.repeat(2 * 1024 * 1024);
      const request = createMockRequest(body); // No content-length header
      const result = await validateBodySize(request, {
        maxSizeBytes: BodySizeLimits.SMALL,
      });
      expect(result).not.toBeNull();
    });
  });

  describe('BodySizeLimits', () => {
    it('should have correct size values', () => {
      expect(BodySizeLimits.SMALL).toBe(1024 * 1024); // 1MB
      expect(BodySizeLimits.MEDIUM).toBe(5 * 1024 * 1024); // 5MB
      expect(BodySizeLimits.LARGE).toBe(10 * 1024 * 1024); // 10MB
      expect(BodySizeLimits.VERY_LARGE).toBe(50 * 1024 * 1024); // 50MB
    });
  });
});









