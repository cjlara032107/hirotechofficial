/**
 * Tests for updateSyncJobProgress function
 * 
 * Test coverage:
 * - Updates timestamp (lastProgressAt)
 * - Uses retry logic for resilience
 * - Updates syncedContacts and failedContacts correctly
 * - Appends errors without overwriting existing errors
 * - Handles database errors gracefully
 */

import { updateSyncJobProgress } from '../update-progress';
import { prisma } from '@/lib/db';
import { withRetry } from '@/lib/db-retry';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  },
}));

jest.mock('@/lib/db-retry', () => ({
  withRetry: jest.fn((fn) => fn()),
}));

describe('updateSyncJobProgress', () => {
  const mockJobId = 'test-job-id';
  
  beforeEach(() => {
    jest.clearAllMocks();
    (prisma.syncJob.findUnique as jest.Mock).mockResolvedValue({
      errors: [],
    });
    (prisma.syncJob.update as jest.Mock).mockResolvedValue({
      id: mockJobId,
      lastProgressAt: new Date(),
    });
  });

  describe('Test: Updates timestamp (lastProgressAt)', () => {
    it('should update lastProgressAt timestamp when updating progress', async () => {
      const beforeUpdate = new Date();
      
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 10,
        failedContacts: 2,
      });

      const afterUpdate = new Date();
      
      // Verify update was called
      expect(prisma.syncJob.update).toHaveBeenCalled();
      
      // Verify lastProgressAt is included in the update
      const updateCall = (prisma.syncJob.update as jest.Mock).mock.calls[0];
      const updateData = updateCall[0].data;
      
      expect(updateData).toHaveProperty('lastProgressAt');
      expect(updateData.lastProgressAt).toBeInstanceOf(Date);
      
      // Verify timestamp is recent (within 1 second of now)
      const timestamp = updateData.lastProgressAt as Date;
      expect(timestamp.getTime()).toBeGreaterThanOrEqual(beforeUpdate.getTime());
      expect(timestamp.getTime()).toBeLessThanOrEqual(afterUpdate.getTime());
    });

    it('should update lastProgressAt even when only updating errors', async () => {
      await updateSyncJobProgress(mockJobId, {
        errors: [{ platform: 'Messenger', id: '123', error: 'Test error' }],
      });

      const updateCall = (prisma.syncJob.update as jest.Mock).mock.calls[0];
      const updateData = updateCall[0].data;
      
      expect(updateData).toHaveProperty('lastProgressAt');
      expect(updateData.lastProgressAt).toBeInstanceOf(Date);
    });

    it('should update lastProgressAt on every call, even with same counts', async () => {
      const firstCallTime = new Date('2024-01-01T10:00:00Z');
      const secondCallTime = new Date('2024-01-01T10:00:01Z');
      
      // Mock Date to return specific times
      jest.spyOn(global, 'Date').mockReturnValueOnce(firstCallTime as unknown as Date);
      
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 10,
        failedContacts: 2,
      });

      jest.spyOn(global, 'Date').mockReturnValueOnce(secondCallTime as unknown as Date);
      
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 10,
        failedContacts: 2,
      });

      // Verify both calls included lastProgressAt
      const firstUpdate = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      const secondUpdate = (prisma.syncJob.update as jest.Mock).mock.calls[1][0].data;
      
      expect(firstUpdate.lastProgressAt).toEqual(firstCallTime);
      expect(secondUpdate.lastProgressAt).toEqual(secondCallTime);
      
      jest.restoreAllMocks();
    });
  });

  describe('Test: Uses retry logic for resilience', () => {
    it('should use withRetry wrapper for database operations', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 10,
        failedContacts: 2,
      });

      // Verify withRetry was called
      expect(withRetry).toHaveBeenCalled();
      
      // Verify withRetry was called with correct options
      const withRetryCall = (withRetry as jest.Mock).mock.calls[0];
      const retryOptions = withRetryCall[1];
      
      expect(retryOptions).toMatchObject({
        maxRetries: 3,
        initialDelay: 1000,
        maxDelay: 10000,
        retryableErrors: expect.arrayContaining([
          'Unable to check out process from the pool',
          'connection pool',
          'P2024',
          'P1001',
          'timeout',
        ]),
      });
    });

    it('should retry on connection pool errors', async () => {
      let attemptCount = 0;
      (prisma.syncJob.findUnique as jest.Mock).mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 3) {
          const error = new Error('Unable to check out process from the pool');
          (error as any).code = 'P2024';
          throw error;
        }
        return Promise.resolve({ errors: [] });
      });

      // Mock withRetry to actually retry
      (withRetry as jest.Mock).mockImplementation(async (fn, options) => {
        let lastError;
        for (let attempt = 1; attempt <= (options.maxRetries || 3); attempt++) {
          try {
            return await fn();
          } catch (error) {
            lastError = error;
            const errorMessage = error instanceof Error ? error.message : String(error);
            const isRetryable = (options.retryableErrors || []).some((pattern: string) =>
              errorMessage.includes(pattern)
            );
            if (!isRetryable || attempt === (options.maxRetries || 3)) {
              throw error;
            }
            // Wait a bit before retry (simulated)
            await new Promise(resolve => setTimeout(resolve, 10));
          }
        }
        throw lastError;
      });

      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 10,
      });

      // Verify retry logic was used (findUnique was called multiple times)
      expect(prisma.syncJob.findUnique).toHaveBeenCalledTimes(3);
    });

    it('should handle retry failures gracefully without throwing', async () => {
      // Mock withRetry to throw after all retries exhausted
      (withRetry as jest.Mock).mockRejectedValue(new Error('All retries exhausted'));

      // Should not throw - errors are caught and logged
      await expect(
        updateSyncJobProgress(mockJobId, {
          syncedContacts: 10,
        })
      ).resolves.not.toThrow();
    });

    it('should use exponential backoff in retry options', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 10,
      });

      const retryOptions = (withRetry as jest.Mock).mock.calls[0][1];
      
      // Verify exponential backoff configuration
      expect(retryOptions.initialDelay).toBe(1000);
      expect(retryOptions.maxDelay).toBe(10000);
      expect(retryOptions.maxRetries).toBe(3);
    });
  });

  describe('Additional functionality tests', () => {
    it('should update syncedContacts correctly', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: 42,
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.syncedContacts).toBe(42);
    });

    it('should update failedContacts correctly', async () => {
      await updateSyncJobProgress(mockJobId, {
        failedContacts: 5,
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.failedContacts).toBe(5);
    });

    it('should append errors without overwriting existing errors', async () => {
      (prisma.syncJob.findUnique as jest.Mock).mockResolvedValue({
        errors: [
          { platform: 'Messenger', id: '1', error: 'Existing error' },
        ],
      });

      await updateSyncJobProgress(mockJobId, {
        errors: [
          { platform: 'Instagram', id: '2', error: 'New error' },
        ],
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.errors).toEqual([
        { platform: 'Messenger', id: '1', error: 'Existing error' },
        { platform: 'Instagram', id: '2', error: 'New error' },
      ]);
    });

    it('should handle null/undefined errors gracefully', async () => {
      (prisma.syncJob.findUnique as jest.Mock).mockResolvedValue({
        errors: null,
      });

      await updateSyncJobProgress(mockJobId, {
        errors: [{ platform: 'Messenger', id: '1', error: 'New error' }],
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.errors).toEqual([
        { platform: 'Messenger', id: '1', error: 'New error' },
      ]);
    });

    it('should not update counts if not provided', async () => {
      await updateSyncJobProgress(mockJobId, {
        errors: [{ platform: 'Messenger', id: '1', error: 'Error' }],
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData).not.toHaveProperty('syncedContacts');
      expect(updateData).not.toHaveProperty('failedContacts');
      expect(updateData).toHaveProperty('lastProgressAt');
    });

    it('should use atomic increment when syncedIncrement is provided', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedIncrement: 5,
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.syncedContacts).toEqual({ increment: 5 });
      expect(updateData).toHaveProperty('lastProgressAt');
    });

    it('should use atomic increment when failedIncrement is provided', async () => {
      await updateSyncJobProgress(mockJobId, {
        failedIncrement: 3,
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.failedContacts).toEqual({ increment: 3 });
      expect(updateData).toHaveProperty('lastProgressAt');
    });

    it('should prioritize increment over direct assignment', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedIncrement: 5,
        syncedContacts: 10, // Should be ignored
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.syncedContacts).toEqual({ increment: 5 });
      expect(updateData).not.toHaveProperty('syncedContacts', 10);
    });

    it('should handle null values correctly', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedContacts: null,
        failedContacts: null,
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData.syncedContacts).toBe(0);
      expect(updateData.failedContacts).toBe(0);
    });

    it('should not increment when increment value is 0', async () => {
      await updateSyncJobProgress(mockJobId, {
        syncedIncrement: 0,
        failedIncrement: 0,
      });

      const updateData = (prisma.syncJob.update as jest.Mock).mock.calls[0][0].data;
      expect(updateData).not.toHaveProperty('syncedContacts');
      expect(updateData).not.toHaveProperty('failedContacts');
      expect(updateData).toHaveProperty('lastProgressAt');
    });
  });
});

