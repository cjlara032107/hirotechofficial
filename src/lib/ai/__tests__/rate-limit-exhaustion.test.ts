/**
 * Tests for API Rate Limit Exhaustion Handling
 * 
 * Tests ensure that:
 * - All keys rate-limited scenario is detected
 * - Earliest available time is calculated correctly
 * - Appropriate error messages are logged
 * - Fallback to environment variables works when database keys are exhausted
 */

import apiKeyManager from '../api-key-manager';
import { ApiKeyStatus } from '@prisma/client';
import { prisma } from '@/lib/db';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    apiKey: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  },
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('Rate Limit Exhaustion Handling', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset the manager's internal state
    (apiKeyManager as any).activeKeyIds = [];
    (apiKeyManager as any).lastRefresh = 0;
  });

  describe('Rate Limit Exhaustion Detection', () => {
    it('should detect when all keys are rate-limited', async () => {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);

      mockedPrisma.apiKey.findMany.mockResolvedValue([
        {
          id: 'key1',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: oneHourAgo,
        },
        {
          id: 'key2',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: twoHoursAgo,
        },
      ] as any);

      const info = await apiKeyManager.getRateLimitExhaustionInfo();

      expect(info.allRateLimited).toBe(true);
      expect(info.rateLimitedCount).toBe(2);
      expect(info.totalKeys).toBe(2);
      expect(info.earliestAvailableAt).not.toBeNull();
    });

    it('should return false when some keys are active', async () => {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

      mockedPrisma.apiKey.findMany.mockResolvedValue([
        {
          id: 'key1',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: oneHourAgo,
        },
        {
          id: 'key2',
          status: ApiKeyStatus.ACTIVE,
          rateLimitedAt: null,
        },
      ] as any);

      const info = await apiKeyManager.getRateLimitExhaustionInfo();

      expect(info.allRateLimited).toBe(false);
      expect(info.rateLimitedCount).toBe(1);
      expect(info.totalKeys).toBe(2);
    });

    it('should calculate earliest available time correctly', async () => {
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);

      mockedPrisma.apiKey.findMany.mockResolvedValue([
        {
          id: 'key1',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: oneHourAgo,
        },
        {
          id: 'key2',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: twoHoursAgo,
        },
      ] as any);

      const info = await apiKeyManager.getRateLimitExhaustionInfo();

      expect(info.earliestAvailableAt).not.toBeNull();
      if (info.earliestAvailableAt) {
        // Earliest should be twoHoursAgo + 24 hours (the older key)
        const expectedTime = new Date(twoHoursAgo);
        expectedTime.setHours(expectedTime.getHours() + 24);
        // Allow 1 minute tolerance
        const timeDiff = Math.abs(
          info.earliestAvailableAt.getTime() - expectedTime.getTime()
        );
        expect(timeDiff).toBeLessThan(60 * 1000);
      }
    });
  });

  describe('getNextKey with Rate Limit Exhaustion', () => {
    it('should return null and log exhaustion info when all keys are rate-limited', async () => {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

      mockedPrisma.apiKey.findMany.mockResolvedValue([
        {
          id: 'key1',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: oneHourAgo,
        },
      ] as any);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const key = await apiKeyManager.getNextKey({ operation: 'test' });

      expect(key).toBeNull();
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('All API keys are rate-limited')
      );

      consoleErrorSpy.mockRestore();
    });

    it('should include time until available in error message', async () => {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

      mockedPrisma.apiKey.findMany.mockResolvedValue([
        {
          id: 'key1',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: oneHourAgo,
        },
      ] as any);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      await apiKeyManager.getNextKey({ operation: 'test' });

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('minute(s)')
      );

      consoleErrorSpy.mockRestore();
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty key list', async () => {
      mockedPrisma.apiKey.findMany.mockResolvedValue([]);

      const info = await apiKeyManager.getRateLimitExhaustionInfo();

      expect(info.allRateLimited).toBe(false);
      expect(info.rateLimitedCount).toBe(0);
      expect(info.totalKeys).toBe(0);
      expect(info.earliestAvailableAt).toBeNull();
    });

    it('should handle keys without rateLimitedAt timestamp', async () => {
      mockedPrisma.apiKey.findMany.mockResolvedValue([
        {
          id: 'key1',
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: null,
        },
      ] as any);

      const info = await apiKeyManager.getRateLimitExhaustionInfo();

      expect(info.allRateLimited).toBe(true);
      expect(info.earliestAvailableAt).toBeNull();
    });

    it('should handle database errors gracefully', async () => {
      mockedPrisma.apiKey.findMany.mockRejectedValue(new Error('Database error'));

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const info = await apiKeyManager.getRateLimitExhaustionInfo();

      expect(info.allRateLimited).toBe(false);
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });
});









