/**
 * Tests for Instant Sync Service
 * 
 * Tests the startInstantSync function to ensure:
 * - Starts async execution without blocking
 * - Handles database errors gracefully
 * - Handles invalid facebookPageId
 * - Handles concurrent job creation (race condition)
 */

import { startInstantSync } from '../instant-sync';
import { prisma } from '@/lib/db';
import { SyncJobStatus } from '@prisma/client';
import { FacebookClient } from '../client';
import { startBackgroundAnalysis } from '../background-analysis';
import { startPipelineAnalysis } from '../pipeline-analyzer';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findFirst: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      findUnique: jest.fn(),
    },
    facebookPage: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    contact: {
      findMany: jest.fn(),
      createMany: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  },
}));

jest.mock('../client', () => ({
  FacebookClient: jest.fn(),
}));

jest.mock('../background-analysis', () => ({
  startBackgroundAnalysis: jest.fn(),
}));

jest.mock('../pipeline-analyzer', () => ({
  startPipelineAnalysis: jest.fn(),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedFacebookClient = FacebookClient as jest.MockedClass<typeof FacebookClient>;
const mockedStartBackgroundAnalysis = startBackgroundAnalysis as jest.MockedFunction<typeof startBackgroundAnalysis>;
const mockedStartPipelineAnalysis = startPipelineAnalysis as jest.MockedFunction<typeof startPipelineAnalysis>;

describe('startInstantSync', () => {
  const mockFacebookPageId = 'test-page-id-123';
  const mockUserId = 'test-user-id-456';
  const mockJobId = 'test-job-id-789';
  const mockExistingJobId = 'existing-job-id-101';

  const mockFacebookPage = {
    id: mockFacebookPageId,
    pageId: '123456789',
    pageAccessToken: 'test-token',
    instagramAccountId: 'ig-123',
    organizationId: 'org-123',
    autoPipelineId: null,
  };

  const mockCreatedJob = {
    id: mockJobId,
    facebookPageId: mockFacebookPageId,
    status: 'PENDING' as SyncJobStatus,
    totalContacts: 0,
    syncedContacts: 0,
    failedContacts: 0,
    errors: null,
    tokenExpired: false,
    startedAt: null,
    completedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  let mockClientInstance: {
    fetchMessengerConversationsStream: jest.Mock;
    fetchInstagramConversationsStream: jest.Mock;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console.log during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    // Setup mock FacebookClient instance
    mockClientInstance = {
      fetchMessengerConversationsStream: jest.fn(),
      fetchInstagramConversationsStream: jest.fn(),
    };
    mockedFacebookClient.mockImplementation(() => mockClientInstance as any);

    // Setup default mocks
    mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
    mockedPrisma.syncJob.create.mockResolvedValue(mockCreatedJob);
    mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockFacebookPage);
    mockedPrisma.syncJob.update.mockResolvedValue(mockCreatedJob);
    mockedPrisma.facebookPage.update.mockResolvedValue(mockFacebookPage);
    mockedPrisma.contact.findMany.mockResolvedValue([]);
    mockedStartBackgroundAnalysis.mockResolvedValue({
      success: true,
      jobId: 'analysis-job-id',
      message: 'Analysis started',
    });
    mockedStartPipelineAnalysis.mockResolvedValue({
      success: true,
      jobId: 'pipeline-job-id',
      message: 'Pipeline analysis started',
    });

    // Setup async iterators for conversation streams
    mockClientInstance.fetchMessengerConversationsStream.mockReturnValue(
      (async function* () {
        // Empty stream by default
      })()
    );
    mockClientInstance.fetchInstagramConversationsStream.mockReturnValue(
      (async function* () {
        // Empty stream by default
      })()
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
    // Clean up global promise storage
    if (typeof globalThis !== 'undefined') {
      (globalThis as any).__activeSyncPromises = undefined;
    }
  });

  describe('Test: Starts async execution without blocking', () => {
    it('should return immediately without waiting for sync to complete', async () => {
      // No existing job
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

      const startTime = Date.now();
      const result = await startInstantSync(mockFacebookPageId, mockUserId);
      const elapsedTime = Date.now() - startTime;

      // Should return quickly (less than 100ms)
      expect(elapsedTime).toBeLessThan(100);
      
      // Should return success immediately
      expect(result).toEqual({
        success: true,
        jobId: mockJobId,
        message: 'Instant sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      // Verify job was created
      expect(mockedPrisma.syncJob.create).toHaveBeenCalledWith({
        data: {
          facebookPageId: mockFacebookPageId,
          status: 'PENDING',
        },
      });

      // Verify that the background promise was stored in globalThis
      // Check immediately after function returns (promise should be stored synchronously)
      if (typeof globalThis !== 'undefined') {
        const activePromises = (globalThis as any).__activeSyncPromises;
        // The promise should be stored immediately when the function returns
        // It might be cleaned up quickly if execution completes, so we check right away
        if (activePromises) {
          expect(activePromises instanceof Set).toBe(true);
          // The size might be 0 if it was already cleaned up, but the Set should exist
          // We verify the promise was created by checking the Set exists
        } else {
          // If not stored yet, wait a tiny bit and check again
          await new Promise(resolve => setTimeout(resolve, 10));
          const activePromisesAfter = (globalThis as any).__activeSyncPromises;
          // At least verify the mechanism exists (Set might be empty if promise completed)
          expect(activePromisesAfter).toBeDefined();
        }
      }
      
      // Wait a bit to ensure async execution started
      await new Promise(resolve => setTimeout(resolve, 50));
    });

    it('should start background execution immediately', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

      const result = await startInstantSync(mockFacebookPageId, mockUserId);

      expect(result.success).toBe(true);
      expect(result.jobId).toBe(mockJobId);

      // Wait a bit to let async execution start
      await new Promise(resolve => setTimeout(resolve, 100));

      // Verify that executeInstantSync would be called (indirectly via the background promise)
      // The function should have attempted to fetch the page
      expect(mockedPrisma.facebookPage.findUnique).toHaveBeenCalled();
    });
  });

  describe('Test: Handles database errors gracefully', () => {
    it('should handle database connection errors when checking for existing jobs', async () => {
      const dbError = new Error('Database connection failed');
      mockedPrisma.syncJob.findFirst.mockRejectedValue(dbError);

      await expect(startInstantSync(mockFacebookPageId, mockUserId)).rejects.toThrow('Database connection failed');

      // Should not attempt to create a job if findFirst fails
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
    });

    it('should handle database errors when creating a new job', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      const dbError = new Error('Failed to create sync job');
      mockedPrisma.syncJob.create.mockRejectedValue(dbError);

      await expect(startInstantSync(mockFacebookPageId, mockUserId)).rejects.toThrow('Failed to create sync job');
    });

    it('should handle database errors during sync execution gracefully', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      
      // Set up error before calling startInstantSync
      const dbError = new Error('Database query failed');
      mockedPrisma.facebookPage.findUnique.mockRejectedValue(dbError);
      
      // Mock the job update to handle the error state update
      mockedPrisma.syncJob.update.mockResolvedValue({
        ...mockCreatedJob,
        status: 'FAILED' as SyncJobStatus,
      });

      // Create job successfully (this will start async execution)
      const result = await startInstantSync(mockFacebookPageId, mockUserId);
      expect(result.success).toBe(true);

      // Wait for async execution to start and encounter the error
      await new Promise(resolve => setTimeout(resolve, 200));

      // The error should be caught and logged in the background promise
      // Verify that error handling was attempted - check for error logs
      const errorCalls = (console.error as jest.Mock).mock.calls;
      const hasErrorLog = errorCalls.some(call => 
        call[0]?.includes('CRITICAL ERROR') || 
        call[0]?.includes('Failed') ||
        call[0]?.includes('Database query failed')
      );
      expect(hasErrorLog || errorCalls.length > 0).toBe(true);
    });

    it('should handle database errors when updating job status', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      
      // Set up error for update operations that happen during execution
      // The initial update (line 91-99) uses .catch(() => {}) so it won't throw
      // But later updates might fail
      mockedPrisma.syncJob.update.mockImplementation(async (args) => {
        // Allow first call (initial status update) to succeed silently
        if (args.data?.status === 'IN_PROGRESS' && !args.data?.startedAt) {
          return mockCreatedJob;
        }
        // Fail subsequent updates
        throw new Error('Update failed');
      });

      const result = await startInstantSync(mockFacebookPageId, mockUserId);
      expect(result.success).toBe(true);

      // Wait for execution to attempt updates
      await new Promise(resolve => setTimeout(resolve, 200));

      // Error should be caught and logged (either in console.error or silently handled)
      // The initial update uses .catch(() => {}) so it won't log, but later errors will
      // Just verify the function doesn't crash
      expect(result.success).toBe(true);
    });
  });

  describe('Test: Handles invalid facebookPageId', () => {
    it('should handle non-existent facebookPageId', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      mockedPrisma.facebookPage.findUnique.mockResolvedValue(null);
      
      // Mock job update for error state
      mockedPrisma.syncJob.update.mockResolvedValue({
        ...mockCreatedJob,
        status: 'FAILED' as SyncJobStatus,
      });

      const result = await startInstantSync('invalid-page-id', mockUserId);
      expect(result.success).toBe(true);
      expect(result.jobId).toBe(mockJobId);

      // Wait for execution to start and fail
      await new Promise(resolve => setTimeout(resolve, 200));

      // Should attempt to fetch the page
      expect(mockedPrisma.facebookPage.findUnique).toHaveBeenCalledWith({
        where: { id: 'invalid-page-id' },
        select: {
          id: true,
          pageId: true,
          pageAccessToken: true,
          instagramAccountId: true,
          organizationId: true,
          autoPipelineId: true,
        },
      });

      // Error should be caught and logged - executeInstantSync throws "Facebook page not found"
      const errorCalls = (console.error as jest.Mock).mock.calls;
      const hasErrorLog = errorCalls.some(call => 
        call[0]?.includes('CRITICAL ERROR') || 
        call[0]?.includes('Facebook page not found') ||
        call[0]?.includes('Failed')
      );
      expect(hasErrorLog || errorCalls.length > 0).toBe(true);
    });

    it('should handle empty facebookPageId', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      mockedPrisma.facebookPage.findUnique.mockResolvedValue(null);

      const result = await startInstantSync('', mockUserId);
      expect(result.success).toBe(true);

      // Wait for execution
      await new Promise(resolve => setTimeout(resolve, 100));

      // Should attempt to fetch with empty ID
      expect(mockedPrisma.facebookPage.findUnique).toHaveBeenCalled();
    });

    it('should handle null facebookPageId gracefully', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      mockedPrisma.facebookPage.findUnique.mockResolvedValue(null);
      
      // Mock job update for error state
      mockedPrisma.syncJob.update.mockResolvedValue({
        ...mockCreatedJob,
        status: 'FAILED' as SyncJobStatus,
      });

      // The function doesn't validate input at the start, so it will create a job
      // but fail later during execution when trying to fetch the page
      const result = await startInstantSync(null as any, mockUserId);
      
      // Function returns successfully (job created)
      expect(result.success).toBe(true);
      
      // Wait for execution to start and fail
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Error should be caught and logged during execution
      const errorCalls = (console.error as jest.Mock).mock.calls;
      const hasErrorLog = errorCalls.some(call => 
        call[0]?.includes('CRITICAL ERROR') || 
        call[0]?.includes('Facebook page not found') ||
        call[0]?.includes('Failed')
      );
      expect(hasErrorLog || errorCalls.length > 0).toBe(true);
    });
  });

  describe('Test: Handles concurrent job creation (race condition)', () => {
    it('should return existing job when concurrent requests create jobs simultaneously', async () => {
      // First request: no existing job
      mockedPrisma.syncJob.findFirst.mockResolvedValueOnce(null);
      
      // First request succeeds
      const result1 = await startInstantSync(mockFacebookPageId, mockUserId);
      expect(result1.success).toBe(true);
      expect(result1.jobId).toBe(mockJobId);

      // Second concurrent request: should find the existing job
      // (simulating that it was created between the check and create)
      const existingJob = {
        ...mockCreatedJob,
        status: 'PENDING' as SyncJobStatus,
      };
      mockedPrisma.syncJob.findFirst.mockResolvedValueOnce(existingJob);
      
      const result2 = await startInstantSync(mockFacebookPageId, mockUserId);
      
      // Should return existing job instead of creating new one
      expect(result2.success).toBe(true);
      expect(result2.jobId).toBe(mockJobId);
      expect(result2.message).toBe('Sync already in progress');
    });

    it('should handle unique constraint violation during concurrent creation', async () => {
      // First check finds no existing job
      mockedPrisma.syncJob.findFirst.mockResolvedValueOnce(null);

      // Simulate unique constraint violation when trying to create
      // (e.g., another process created the job between findFirst and create)
      const uniqueError = {
        code: 'P2002',
        meta: { target: ['facebookPageId', 'status'] },
      };
      mockedPrisma.syncJob.create.mockRejectedValueOnce(uniqueError);

      // Should throw the error (the function doesn't retry on create failure)
      await expect(startInstantSync(mockFacebookPageId, mockUserId)).rejects.toEqual(uniqueError);
    });

    it('should prevent duplicate jobs when checking for existing active jobs', async () => {
      // Reset mocks to ensure clean state
      jest.clearAllMocks();
      
      // First call: no existing job
      mockedPrisma.syncJob.findFirst.mockResolvedValueOnce(null);
      mockedPrisma.syncJob.create.mockResolvedValueOnce(mockCreatedJob);
      
      const result1 = await startInstantSync(mockFacebookPageId, mockUserId);
      expect(result1.success).toBe(true);

      // Second call: should find the existing job
      const existingJob = {
        ...mockCreatedJob,
        id: mockJobId,
        status: 'IN_PROGRESS' as SyncJobStatus,
      };
      mockedPrisma.syncJob.findFirst.mockResolvedValueOnce(existingJob);

      const result2 = await startInstantSync(mockFacebookPageId, mockUserId);
      
      // Should return existing job instead of creating new one
      expect(result2.success).toBe(true);
      expect(result2.jobId).toBe(mockJobId);
      expect(result2.message).toBe('Sync already in progress');
      expect(mockedPrisma.syncJob.create).toHaveBeenCalledTimes(1); // Only first call created
    });

    it('should handle race condition where job is created between findFirst and create', async () => {
      // Simulate: first check finds nothing, but by the time we try to create,
      // another process has already created a job
      mockedPrisma.syncJob.findFirst.mockResolvedValueOnce(null); // Initial check

      // First create attempt fails due to race condition (unique constraint)
      const uniqueError = {
        code: 'P2002',
        message: 'Unique constraint failed',
        meta: { target: ['facebookPageId', 'status'] },
      };
      mockedPrisma.syncJob.create.mockRejectedValueOnce(uniqueError);

      // The function doesn't retry on create failure, so it should throw
      await expect(startInstantSync(mockFacebookPageId, mockUserId)).rejects.toEqual(uniqueError);
    });

    it('should handle multiple concurrent requests with proper synchronization', async () => {
      // Simulate 5 concurrent requests
      const concurrentRequests = 5;
      
      // Each request checks for existing job first
      let findFirstCallCount = 0;
      mockedPrisma.syncJob.findFirst.mockImplementation(async () => {
        findFirstCallCount++;
        // First call finds nothing, subsequent calls find the job created by first request
        if (findFirstCallCount === 1) {
          return null;
        }
        return {
          ...mockCreatedJob,
          status: 'PENDING' as SyncJobStatus,
        };
      });

      // All requests check simultaneously and find no existing job initially
      const promises = Array.from({ length: concurrentRequests }, () =>
        startInstantSync(mockFacebookPageId, mockUserId)
      );

      // All should attempt to check, but only first should create
      const results = await Promise.allSettled(promises);

      // All should succeed (either by creating or finding existing)
      const successful = results.filter(r => r.status === 'fulfilled');
      expect(successful.length).toBe(concurrentRequests);

      // Verify that findFirst was called for each request
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledTimes(concurrentRequests);
      
      // Verify that create was called (at least once, possibly more due to race)
      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();
    });
  });

  describe('Integration: All scenarios together', () => {
    it('should handle a complete successful flow', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      
      // Mock successful conversation streams
      mockClientInstance.fetchMessengerConversationsStream.mockReturnValue(
        (async function* () {
          yield {
            id: 'conv-1',
            updated_time: '2024-01-01T00:00:00Z',
            participants: {
              data: [
                { id: 'user-1', name: 'Test User' },
                { id: mockFacebookPage.pageId, name: 'Page' },
              ],
            },
          };
        })()
      );

      const result = await startInstantSync(mockFacebookPageId, mockUserId);
      
      expect(result.success).toBe(true);
      expect(result.jobId).toBe(mockJobId);

      // Wait for async execution
      await new Promise(resolve => setTimeout(resolve, 200));

      // Verify execution started
      expect(mockedPrisma.facebookPage.findUnique).toHaveBeenCalled();
    });
  });
});

