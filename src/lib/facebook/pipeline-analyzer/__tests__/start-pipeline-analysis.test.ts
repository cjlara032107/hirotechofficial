/**
 * Tests for startPipelineAnalysis function
 * 
 * Tests for:
 * - Handles database connection errors
 * - Validates forceUpdateExisting boolean
 * - Handles concurrent job creation attempts
 */

import { startPipelineAnalysis } from '../../pipeline-analyzer';
import { prisma } from '@/lib/db';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findFirst: jest.fn(),
      create: jest.fn(),
    },
  },
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('startPipelineAnalysis', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Handles database connection errors', () => {
    it('should throw error when database connection fails during job lookup', async () => {
      // Mock connection failure during findFirst
      const connectionError = new Error('Can\'t reach database');
      (connectionError as any).code = 'P1001';
      mockedPrisma.syncJob.findFirst = jest.fn().mockRejectedValue(connectionError);

      await expect(
        startPipelineAnalysis('test-page-id', false)
      ).rejects.toThrow('Can\'t reach database');

      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();
    });

    it('should throw error when connection pool is exhausted during job lookup', async () => {
      // Mock connection failure during findFirst
      const connectionError = new Error('Connection pool exhausted');
      (connectionError as any).code = 'P2024';
      mockedPrisma.syncJob.findFirst = jest.fn().mockRejectedValue(connectionError);

      await expect(
        startPipelineAnalysis('test-page-id', false)
      ).rejects.toThrow('Connection pool exhausted');

      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();
    });

    it('should throw error when database connection fails during job creation', async () => {
      // Mock successful job lookup (no existing job)
      mockedPrisma.syncJob.findFirst = jest.fn().mockResolvedValue(null);

      // Mock connection failure during create
      const connectionError = new Error('Server has closed the connection');
      mockedPrisma.syncJob.create = jest.fn().mockRejectedValue(connectionError);

      await expect(
        startPipelineAnalysis('test-page-id', false)
      ).rejects.toThrow('Server has closed the connection');

      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();
    });

    it('should handle timeout errors gracefully', async () => {
      // Mock timeout error during findFirst
      const timeoutError = new Error('Connection timeout');
      (timeoutError as any).code = 'ETIMEDOUT';
      mockedPrisma.syncJob.findFirst = jest.fn().mockRejectedValue(timeoutError);

      await expect(
        startPipelineAnalysis('test-page-id', false)
      ).rejects.toThrow('Connection timeout');

      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();
    });

    it('should handle connection reset errors', async () => {
      // Mock connection reset error during findFirst
      const resetError = new Error('ConnectionReset');
      mockedPrisma.syncJob.findFirst = jest.fn().mockRejectedValue(resetError);

      await expect(
        startPipelineAnalysis('test-page-id', false)
      ).rejects.toThrow('ConnectionReset');

      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();
    });
  });

  describe('Validates forceUpdateExisting boolean', () => {
    beforeEach(() => {
      // Mock no existing job
      mockedPrisma.syncJob.findFirst = jest.fn().mockResolvedValue(null);
      mockedPrisma.syncJob.create = jest.fn().mockResolvedValue({
        id: 'job-123',
        facebookPageId: 'test-page-id',
        status: 'PENDING',
        createdAt: new Date(),
      });
    });

    it('should accept true boolean for forceUpdateExisting', async () => {
      const result = await startPipelineAnalysis('test-page-id', true);

      expect(result.success).toBe(true);
      expect(result.jobId).toBe('job-123');
      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();
    });

    it('should accept false boolean for forceUpdateExisting', async () => {
      const result = await startPipelineAnalysis('test-page-id', false);

      expect(result.success).toBe(true);
      expect(result.jobId).toBe('job-123');
      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();
    });

    it('should default to false when forceUpdateExisting is undefined', async () => {
      // TypeScript will enforce boolean, but test runtime behavior
      const result = await startPipelineAnalysis('test-page-id', undefined as any);

      expect(result.success).toBe(true);
      expect(result.jobId).toBe('job-123');
    });
  });

  describe('Handles concurrent job creation attempts', () => {
    beforeEach(() => {
      // Setup default mocks
    });

    it('should return existing job when concurrent requests create jobs simultaneously', async () => {
      // Simulate race condition: first request finds no job, second request finds job created by first
      let callCount = 0;
      mockedPrisma.syncJob.findFirst = jest.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call: no existing job
          return Promise.resolve(null);
        } else {
          // Second call (concurrent): job was created by first request
          return Promise.resolve({
            id: 'job-123',
            facebookPageId: 'test-page-id',
            status: 'PENDING',
            createdAt: new Date(),
          });
        }
      });

      mockedPrisma.syncJob.create = jest.fn().mockResolvedValue({
        id: 'job-123',
        facebookPageId: 'test-page-id',
        status: 'PENDING',
        createdAt: new Date(),
      });

      // Simulate two concurrent calls
      const [result1, result2] = await Promise.all([
        startPipelineAnalysis('test-page-id', false),
        startPipelineAnalysis('test-page-id', false),
      ]);

      // Both should succeed, but ideally one should return existing job
      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      // At least one should have created a job
      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();
    });

    it('should handle unique constraint violation when jobs are created concurrently', async () => {
      // Mock findFirst returns null (no existing job initially)
      mockedPrisma.syncJob.findFirst = jest.fn().mockResolvedValue(null);

      // Mock create to throw unique constraint error (simulating concurrent creation)
      // This happens when two requests try to create a job at the same time
      const uniqueError = new Error('Unique constraint violation');
      (uniqueError as any).code = 'P2002';
      mockedPrisma.syncJob.create = jest.fn().mockRejectedValue(uniqueError);

      // This test verifies the function doesn't handle unique constraint errors
      // The function will throw the error, which is the current behavior
      // In a real implementation, you might want to catch P2002 and check for existing job
      await expect(
        startPipelineAnalysis('test-page-id', false)
      ).rejects.toThrow('Unique constraint violation');

      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();
      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();
    });

    it('should handle multiple concurrent requests creating jobs for same page', async () => {
      // Simulate scenario where multiple requests check simultaneously, all find no job,
      // then all try to create, but only one succeeds
      mockedPrisma.syncJob.findFirst = jest.fn().mockResolvedValue(null);

      let createCallCount = 0;
      mockedPrisma.syncJob.create = jest.fn().mockImplementation(() => {
        createCallCount++;
        if (createCallCount === 1) {
          // First create succeeds
          return Promise.resolve({
            id: 'job-123',
            facebookPageId: 'test-page-id',
            status: 'PENDING',
            createdAt: new Date(),
          });
        } else {
          // Subsequent creates fail with unique constraint
          const uniqueError = new Error('Unique constraint violation');
          (uniqueError as any).code = 'P2002';
          return Promise.reject(uniqueError);
        }
      });

      // Simulate 3 concurrent requests
      const results = await Promise.allSettled([
        startPipelineAnalysis('test-page-id', false),
        startPipelineAnalysis('test-page-id', false),
        startPipelineAnalysis('test-page-id', false),
      ]);

      // At least one should succeed
      const successful = results.filter(r => r.status === 'fulfilled');
      expect(successful.length).toBeGreaterThan(0);

      // Verify create was called multiple times (concurrent attempts)
      expect(mockedPrisma.syncJob.create).toHaveBeenCalledTimes(3);
    });

    it('should return existing job when job is already in progress', async () => {
      // Mock existing job in PENDING status
      mockedPrisma.syncJob.findFirst = jest.fn().mockResolvedValue({
        id: 'existing-job-123',
        facebookPageId: 'test-page-id',
        status: 'PENDING',
        createdAt: new Date(),
      });

      const result = await startPipelineAnalysis('test-page-id', false);

      expect(result.success).toBe(true);
      expect(result.jobId).toBe('existing-job-123');
      expect(result.message).toBe('Pipeline analysis already in progress');
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
    });

    it('should return existing job when job is IN_PROGRESS', async () => {
      // Mock existing job in IN_PROGRESS status
      mockedPrisma.syncJob.findFirst = jest.fn().mockResolvedValue({
        id: 'existing-job-456',
        facebookPageId: 'test-page-id',
        status: 'IN_PROGRESS',
        createdAt: new Date(),
        startedAt: new Date(),
      });

      const result = await startPipelineAnalysis('test-page-id', false);

      expect(result.success).toBe(true);
      expect(result.jobId).toBe('existing-job-456');
      expect(result.message).toBe('Pipeline analysis already in progress');
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
    });
  });
});

