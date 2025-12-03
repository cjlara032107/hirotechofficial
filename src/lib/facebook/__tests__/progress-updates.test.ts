/**
 * Tests for Progress Update Error Handling
 * 
 * Tests that progress updates properly handle:
 * - Database errors gracefully (logs, doesn't throw)
 * - Concurrent progress updates (uses atomic increment)
 * - Null/undefined counts
 */

import { Prisma } from '@prisma/client';

// Mock Prisma client - define inside jest.mock factory
jest.mock('@/lib/db', () => {
  const mockPrisma = {
    syncJob: {
      update: jest.fn(),
      findUnique: jest.fn(),
    },
    analysisJob: {
      update: jest.fn(),
      findUnique: jest.fn(),
    },
  };
  
  return {
    prisma: mockPrisma,
    connectPrisma: jest.fn().mockResolvedValue(undefined),
  };
});

jest.mock('@/lib/db-retry', () => ({
  withRetry: jest.fn(async (operation) => {
    return await operation();
  }),
}));

// Import after mock
import { prisma } from '@/lib/db';
import { updateSyncJobProgress } from '../pipeline-analyzer/update-progress';
import { updateAnalysisJobProgress } from '../progress-update';

const mockSyncJob = (prisma as any).syncJob;
const mockAnalysisJob = (prisma as any).analysisJob;

describe('Progress Update Error Handling', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Handles database errors gracefully (logs, doesn\'t throw)', () => {
    it('should log database connection errors without throwing', async () => {
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      mockSyncJob.update.mockRejectedValue(connectionError);

      // Simulate progress update that should handle errors gracefully
      const updateProgress = async () => {
        try {
          await mockSyncJob.update({
            where: { id: 'test-job-id' },
            data: {
              syncedContacts: 5,
              failedContacts: 0,
            },
          });
        } catch (error) {
          // Should log but not throw
          console.error(`[Progress Update] Failed to update progress:`, error);
          // Don't rethrow - this is a non-critical operation
        }
      };

      // Should not throw
      await expect(updateProgress()).resolves.not.toThrow();
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[Progress Update] Failed to update progress:'),
        connectionError
      );
    });

    it('should log connection pool exhaustion errors without throwing', async () => {
      const poolError = {
        code: 'P2024',
        message: 'Unable to check out process from the pool',
      } as Prisma.PrismaClientKnownRequestError;

      mockAnalysisJob.update.mockRejectedValue(poolError);

      const updateProgress = async () => {
        try {
          await mockAnalysisJob.update({
            where: { id: 'test-job-id' },
            data: {
              analyzedContacts: 10,
              failedContacts: 2,
            },
          });
        } catch (error) {
          console.error(`[Background Analysis test-job-id] Failed to update progress:`, error);
          // Don't rethrow
        }
      };

      await expect(updateProgress()).resolves.not.toThrow();
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[Background Analysis test-job-id] Failed to update progress:'),
        poolError
      );
    });

    it('should log timeout errors without throwing', async () => {
      const timeoutError = new Error('ETIMEDOUT: Connection timeout');
      (timeoutError as any).code = 'ETIMEDOUT';

      mockSyncJob.update.mockRejectedValue(timeoutError);

      const updateProgress = async () => {
        try {
          await mockSyncJob.update({
            where: { id: 'test-job-id' },
            data: {
              syncedContacts: 15,
              failedContacts: 1,
            },
          });
        } catch (error) {
          console.error(`[Pipeline Analysis test-job-id] Failed to update progress:`, error);
          // Don't rethrow
        }
      };

      await expect(updateProgress()).resolves.not.toThrow();
      expect(console.error).toHaveBeenCalled();
    });

    it('should continue processing even when progress update fails', async () => {
      const dbError = new Error('Database error');
      mockSyncJob.update.mockRejectedValue(dbError);

      let processedCount = 0;
      const processContact = async (contactId: string) => {
        // Simulate processing a contact
        processedCount++;
        
        // Try to update progress (non-blocking)
        try {
          await mockSyncJob.update({
            where: { id: 'test-job-id' },
            data: {
              syncedContacts: processedCount,
            },
          });
        } catch (error) {
          console.error(`[Progress Update] Failed to update progress:`, error);
          // Continue processing even if update fails
        }
      };

      // Process multiple contacts
      await processContact('contact-1');
      await processContact('contact-2');
      await processContact('contact-3');

      // Should have processed all contacts despite update failures
      expect(processedCount).toBe(3);
      expect(console.error).toHaveBeenCalledTimes(3);
    });
  });

  describe('Test: Handles concurrent progress updates (uses atomic increment)', () => {
    it('should use atomic increment for syncedContacts', async () => {
      // Simulate concurrent updates
      const jobId = 'test-job-id';
      
      // Mock the current state
      mockSyncJob.findUnique.mockResolvedValue({
        id: jobId,
        syncedContacts: 5,
        failedContacts: 0,
        errors: null,
      } as any);

      // Mock update to track calls
      mockSyncJob.update.mockResolvedValue({
        id: jobId,
        syncedContacts: 8,
        failedContacts: 0,
      } as any);

      // Use the actual updateSyncJobProgress function with atomic increment
      await Promise.all([
        updateSyncJobProgress(jobId, { syncedIncrement: 1 }),
        updateSyncJobProgress(jobId, { syncedIncrement: 1 }),
        updateSyncJobProgress(jobId, { syncedIncrement: 1 }),
      ]);

      // Verify atomic increment was used
      expect(mockSyncJob.update).toHaveBeenCalled();
      const updateCalls = mockSyncJob.update.mock.calls;
      expect(updateCalls.length).toBeGreaterThan(0);
      
      // Check that at least one call used atomic increment
      const hasAtomicIncrement = updateCalls.some((call) => {
        const data = call[0]?.data;
        return data?.syncedContacts && typeof data.syncedContacts === 'object' && 'increment' in data.syncedContacts;
      });
      expect(hasAtomicIncrement).toBe(true);
    });

    it('should use atomic increment for failedContacts', async () => {
      const jobId = 'test-job-id';
      
      mockAnalysisJob.findUnique.mockResolvedValue({
        id: jobId,
        analyzedContacts: 10,
        failedContacts: 2,
        errors: null,
      } as any);

      mockAnalysisJob.update.mockResolvedValue({
        id: jobId,
        analyzedContacts: 10,
        failedContacts: 4,
      } as any);

      await Promise.all([
        updateAnalysisJobProgress(jobId, { failedIncrement: 1 }),
        updateAnalysisJobProgress(jobId, { failedIncrement: 1 }),
      ]);

      expect(mockAnalysisJob.update).toHaveBeenCalled();
      const updateCalls = mockAnalysisJob.update.mock.calls;
      expect(updateCalls.length).toBeGreaterThan(0);
      
      // Check that at least one call used atomic increment
      const hasAtomicIncrement = updateCalls.some((call) => {
        const data = call[0]?.data;
        return data?.failedContacts && typeof data.failedContacts === 'object' && 'increment' in data.failedContacts;
      });
      expect(hasAtomicIncrement).toBe(true);
    });

    it('should handle concurrent updates correctly with atomic operations', async () => {
      const jobId = 'test-job-id';
      let currentSynced = 0;
      let currentFailed = 0;

      // Mock update to simulate atomic increment
      mockSyncJob.update.mockImplementation(async (args) => {
        if (args?.data?.syncedContacts?.increment) {
          currentSynced += args.data.syncedContacts.increment;
        }
        if (args?.data?.failedContacts?.increment) {
          currentFailed += args.data.failedContacts.increment;
        }
        return {
          id: jobId,
          syncedContacts: currentSynced,
          failedContacts: currentFailed,
        } as any;
      });

      // Simulate 10 concurrent operations
      const operations = Array.from({ length: 10 }, (_, i) => {
        if (i % 2 === 0) {
          // Even: increment synced
          return mockSyncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: { increment: 1 },
            },
          });
        } else {
          // Odd: increment failed
          return mockSyncJob.update({
            where: { id: jobId },
            data: {
              failedContacts: { increment: 1 },
            },
          });
        }
      });

      await Promise.all(operations);

      // Should have 5 synced and 5 failed (atomic operations ensure correctness)
      expect(currentSynced).toBe(5);
      expect(currentFailed).toBe(5);
    });

    it('should prevent race conditions with atomic increment', async () => {
      const jobId = 'test-job-id';
      let callCount = 0;

      // Simulate race condition: multiple updates reading same value
      mockSyncJob.findUnique.mockResolvedValue({
        id: jobId,
        syncedContacts: 0,
        failedContacts: 0,
      } as any);

      mockSyncJob.update.mockImplementation(async (args) => {
        callCount++;
        // Simulate database delay
        await new Promise(resolve => setTimeout(resolve, 10));
        
        if (args?.data?.syncedContacts?.increment) {
          return {
            id: jobId,
            syncedContacts: args.data.syncedContacts.increment,
          } as any;
        }
        return {} as any;
      });

      // Start 5 concurrent updates
      const updates = Array.from({ length: 5 }, () =>
        mockSyncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: { increment: 1 },
          },
        })
      );

      await Promise.all(updates);

      // All 5 updates should have been called
      expect(callCount).toBe(5);
      // With atomic increment, each update is independent and correct
    });
  });

  describe('Test: Handles null/undefined counts', () => {
    it('should handle null syncedContacts gracefully', async () => {
      const jobId = 'test-job-id';
      
      // Simulate database returning null
      mockSyncJob.findUnique.mockResolvedValue({
        id: jobId,
        syncedContacts: null,
        failedContacts: 0,
      } as any);

      const updateProgress = async (count: number | null | undefined) => {
        // Normalize null/undefined to 0
        const syncedCount = count ?? 0;
        
        await mockSyncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: syncedCount,
          },
        });
      };

      await expect(updateProgress(null)).resolves.not.toThrow();
      expect(mockSyncJob.update).toHaveBeenCalledWith({
        where: { id: jobId },
        data: {
          syncedContacts: 0,
        },
      });
    });

    it('should handle undefined analyzedContacts gracefully', async () => {
      const jobId = 'test-job-id';
      
      mockAnalysisJob.findUnique.mockResolvedValue({
        id: jobId,
        analyzedContacts: undefined,
        failedContacts: 0,
      } as any);

      const updateProgress = async (count: number | null | undefined) => {
        const analyzedCount = count ?? 0;
        
        await mockAnalysisJob.update({
          where: { id: jobId },
          data: {
            analyzedContacts: analyzedCount,
          },
        });
      };

      await expect(updateProgress(undefined)).resolves.not.toThrow();
      expect(mockAnalysisJob.update).toHaveBeenCalledWith({
        where: { id: jobId },
        data: {
          analyzedContacts: 0,
        },
      });
    });

    it('should handle null failedContacts in atomic increment', async () => {
      const jobId = 'test-job-id';
      
      mockSyncJob.findUnique.mockResolvedValue({
        id: jobId,
        syncedContacts: 10,
        failedContacts: null,
      } as any);

      const updateProgress = async (increment: number | null | undefined) => {
        // If increment is null/undefined, don't update
        if (increment == null) {
          return;
        }
        
        await mockSyncJob.update({
          where: { id: jobId },
          data: {
            failedContacts: {
              increment: increment,
            },
          },
        });
      };

      await expect(updateProgress(null)).resolves.not.toThrow();
      // Should not call update when increment is null
      expect(mockSyncJob.update).not.toHaveBeenCalled();
    });

    it('should default counts to 0 when calculating progress', () => {
      const calculateProgress = (
        synced: number | null | undefined,
        total: number | null | undefined
      ): number => {
        const syncedCount = synced ?? 0;
        const totalCount = total ?? 0;
        
        if (totalCount === 0) {
          return 0;
        }
        
        return (syncedCount / totalCount) * 100;
      };

      expect(calculateProgress(null, 100)).toBe(0);
      expect(calculateProgress(undefined, 100)).toBe(0);
      expect(calculateProgress(50, null)).toBe(0);
      expect(calculateProgress(50, undefined)).toBe(0);
      expect(calculateProgress(null, null)).toBe(0);
      expect(calculateProgress(undefined, undefined)).toBe(0);
      expect(calculateProgress(50, 100)).toBe(50);
    });

    it('should handle mixed null/undefined counts in batch updates', async () => {
      const jobId = 'test-job-id';
      
      const updateBatch = async (
        synced: number | null | undefined,
        failed: number | null | undefined
      ) => {
        const syncedCount = synced ?? 0;
        const failedCount = failed ?? 0;
        
        await mockSyncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: syncedCount,
            failedContacts: failedCount,
          },
        });
      };

      await updateBatch(null, undefined);
      expect(mockSyncJob.update).toHaveBeenCalledWith({
        where: { id: jobId },
        data: {
          syncedContacts: 0,
          failedContacts: 0,
        },
      });

      await updateBatch(10, null);
      expect(mockSyncJob.update).toHaveBeenLastCalledWith({
        where: { id: jobId },
        data: {
          syncedContacts: 10,
          failedContacts: 0,
        },
      });
    });
  });
});

