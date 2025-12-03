/**
 * Tests for isJobCancelled function
 * 
 * Tests the isJobCancelled function to ensure:
 * - Returns true when job status is CANCELLED
 * - Returns false when job status is not CANCELLED
 * - Throws Error when job not found
 */

import { isJobCancelled } from '../fast-sync';
import { prisma } from '@/lib/db';
import { SyncJobStatus } from '@prisma/client';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findUnique: jest.fn(),
    },
  },
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('isJobCancelled', () => {
  const mockJobId = 'test-job-id-123';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Test: Returns true when job status is CANCELLED', () => {
    it('should return true when job status is CANCELLED', async () => {
      const mockJob = {
        status: 'CANCELLED' as SyncJobStatus,
      };

      mockedPrisma.syncJob.findUnique.mockResolvedValue(mockJob);

      const result = await isJobCancelled(mockJobId);

      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: mockJobId },
        select: { status: true },
      });

      expect(result).toBe(true);
    });
  });

  describe('Test: Returns false when job status is not CANCELLED', () => {
    it('should return false when job status is PENDING', async () => {
      const mockJob = {
        status: 'PENDING' as SyncJobStatus,
      };

      mockedPrisma.syncJob.findUnique.mockResolvedValue(mockJob);

      const result = await isJobCancelled(mockJobId);

      expect(result).toBe(false);
    });

    it('should return false when job status is IN_PROGRESS', async () => {
      const mockJob = {
        status: 'IN_PROGRESS' as SyncJobStatus,
      };

      mockedPrisma.syncJob.findUnique.mockResolvedValue(mockJob);

      const result = await isJobCancelled(mockJobId);

      expect(result).toBe(false);
    });

    it('should return false when job status is COMPLETED', async () => {
      const mockJob = {
        status: 'COMPLETED' as SyncJobStatus,
      };

      mockedPrisma.syncJob.findUnique.mockResolvedValue(mockJob);

      const result = await isJobCancelled(mockJobId);

      expect(result).toBe(false);
    });

    it('should return false when job status is FAILED', async () => {
      const mockJob = {
        status: 'FAILED' as SyncJobStatus,
      };

      mockedPrisma.syncJob.findUnique.mockResolvedValue(mockJob);

      const result = await isJobCancelled(mockJobId);

      expect(result).toBe(false);
    });
  });

  describe('Test: Throws Error when job not found', () => {
    it('should throw Error when job not found', async () => {
      mockedPrisma.syncJob.findUnique.mockResolvedValue(null);

      await expect(isJobCancelled(mockJobId)).rejects.toThrow('Job not found');

      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: mockJobId },
        select: { status: true },
      });
    });

    it('should throw Error with correct message when job not found', async () => {
      mockedPrisma.syncJob.findUnique.mockResolvedValue(null);

      await expect(isJobCancelled(mockJobId)).rejects.toThrow('Job not found');
      
      // Verify error is an instance of Error with correct message
      mockedPrisma.syncJob.findUnique.mockResolvedValueOnce(null);
      const error = await isJobCancelled(mockJobId).catch(e => e);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Job not found');
    });
  });
});

