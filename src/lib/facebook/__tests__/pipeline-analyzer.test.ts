/**
 * Tests for Pipeline Analyzer Service
 * 
 * Tests the startPipelineAnalysis function to ensure:
 * - Checks for existing active jobs
 * - Returns existing jobId if active job exists
 * - Creates new job when no active job exists
 */

import { startPipelineAnalysis } from '../pipeline-analyzer';
import { prisma } from '@/lib/db';
import { SyncJobStatus } from '@prisma/client';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findFirst: jest.fn(),
      create: jest.fn(),
    },
  },
}));

// Mock the executePipelineAnalysis function (it's not exported, so we'll mock it via module)
jest.mock('../pipeline-analyzer', () => {
  const actual = jest.requireActual('../pipeline-analyzer');
  return {
    ...actual,
    // We'll test startPipelineAnalysis which is exported
  };
});

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('startPipelineAnalysis', () => {
  const mockFacebookPageId = 'test-page-id-123';
  const mockJobId = 'test-job-id-456';
  const mockExistingJobId = 'existing-job-id-789';

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console.log during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Checks for existing active jobs', () => {
    it('should always check for existing active jobs before creating a new job', async () => {
      // No existing job
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

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

      mockedPrisma.syncJob.create.mockResolvedValue(mockCreatedJob);

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify findFirst was called before create
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();
      expect(mockedPrisma.syncJob.create).toHaveBeenCalled();

      // Verify the order: findFirst should be called before create
      const findFirstCallOrder = mockedPrisma.syncJob.findFirst.mock.invocationCallOrder[0];
      const createCallOrder = mockedPrisma.syncJob.create.mock.invocationCallOrder[0];
      expect(findFirstCallOrder).toBeLessThan(createCallOrder);
    });

    it('should check for existing jobs with correct query parameters', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      mockedPrisma.syncJob.create.mockResolvedValue({
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
      });

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the check uses correct parameters
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith({
        where: {
          facebookPageId: mockFacebookPageId,
          status: {
            in: ['PENDING', 'IN_PROGRESS'],
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
    });

    it('should check for existing jobs even when an active job exists', async () => {
      const existingJob = {
        id: mockExistingJobId,
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

      mockedPrisma.syncJob.findFirst.mockResolvedValue(existingJob);

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the check was performed
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledTimes(1);
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith({
        where: {
          facebookPageId: mockFacebookPageId,
          status: {
            in: ['PENDING', 'IN_PROGRESS'],
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
    });

    it('should check for existing jobs with both PENDING and IN_PROGRESS statuses', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      mockedPrisma.syncJob.create.mockResolvedValue({
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
      });

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the status filter includes both PENDING and IN_PROGRESS
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: {
              in: ['PENDING', 'IN_PROGRESS'],
            },
          }),
        })
      );
    });

    it('should check for existing jobs ordered by createdAt descending', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      mockedPrisma.syncJob.create.mockResolvedValue({
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
      });

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the orderBy clause
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          orderBy: {
            createdAt: 'desc',
          },
        })
      );
    });
  });

  describe('Test: Creates new job when no active job exists', () => {
    it('should create a new SyncJob with status PENDING when no active job exists', async () => {
      // No existing job
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

      // Mock the create operation
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

      mockedPrisma.syncJob.create.mockResolvedValue(mockCreatedJob);

      const result = await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the function checked for existing jobs
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith({
        where: {
          facebookPageId: mockFacebookPageId,
          status: {
            in: ['PENDING', 'IN_PROGRESS'],
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      // Verify a new job was created with status PENDING
      expect(mockedPrisma.syncJob.create).toHaveBeenCalledWith({
        data: {
          facebookPageId: mockFacebookPageId,
          status: 'PENDING',
        },
      });

      // Verify the result
      expect(result).toEqual({
        success: true,
        jobId: mockJobId,
        message: 'Pipeline analysis started',
      });
      expect(result.success).toBe(true);
      expect(result.jobId).toBe(mockJobId);
    });

    it('should create SyncJob with status PENDING when forceUpdateExisting is true', async () => {
      // No existing job (force update will create new job)
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

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

      mockedPrisma.syncJob.create.mockResolvedValue(mockCreatedJob);

      const result = await startPipelineAnalysis(mockFacebookPageId, true);

      expect(mockedPrisma.syncJob.create).toHaveBeenCalledWith({
        data: {
          facebookPageId: mockFacebookPageId,
          status: 'PENDING',
        },
      });

      expect(result.success).toBe(true);
      expect(result.jobId).toBe(mockJobId);
    });

    it('should create SyncJob with status PENDING and correct facebookPageId', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

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

      mockedPrisma.syncJob.create.mockResolvedValue(mockCreatedJob);

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the create was called with correct facebookPageId
      expect(mockedPrisma.syncJob.create).toHaveBeenCalledWith({
        data: {
          facebookPageId: mockFacebookPageId,
          status: 'PENDING',
        },
      });
    });
  });

  describe('Test: Returns existing jobId when active job exists', () => {
    it('should return existing jobId when PENDING job exists', async () => {
      const existingJob = {
        id: mockExistingJobId,
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

      mockedPrisma.syncJob.findFirst.mockResolvedValue(existingJob);

      const result = await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify it checked for existing jobs
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith({
        where: {
          facebookPageId: mockFacebookPageId,
          status: {
            in: ['PENDING', 'IN_PROGRESS'],
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      // Verify it did NOT create a new job
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();

      // Verify it returned the existing job ID
      expect(result).toEqual({
        success: true,
        jobId: mockExistingJobId,
        message: 'Pipeline analysis already in progress',
      });
      expect(result.jobId).toBe(mockExistingJobId);
      expect(result.message).toBe('Pipeline analysis already in progress');
    });

    it('should return existing jobId when IN_PROGRESS job exists', async () => {
      const existingJob = {
        id: mockExistingJobId,
        facebookPageId: mockFacebookPageId,
        status: 'IN_PROGRESS' as SyncJobStatus,
        totalContacts: 100,
        syncedContacts: 50,
        failedContacts: 0,
        errors: null,
        tokenExpired: false,
        startedAt: new Date(),
        completedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockedPrisma.syncJob.findFirst.mockResolvedValue(existingJob);

      const result = await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify it checked for existing jobs
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalled();

      // Verify it did NOT create a new job
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();

      // Verify it returned the existing job ID
      expect(result.jobId).toBe(mockExistingJobId);
      expect(result.message).toBe('Pipeline analysis already in progress');
    });

    it('should return existing jobId even when forceUpdateExisting is true but job is active', async () => {
      // Note: The current implementation checks for existing jobs before considering forceUpdateExisting
      // This test verifies that behavior
      const existingJob = {
        id: mockExistingJobId,
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

      mockedPrisma.syncJob.findFirst.mockResolvedValue(existingJob);

      const result = await startPipelineAnalysis(mockFacebookPageId, true);

      // Even with forceUpdateExisting=true, if there's an active job, it should return it
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
      expect(result.jobId).toBe(mockExistingJobId);
    });

    it('should query for existing jobs with correct status filter', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);

      await startPipelineAnalysis(mockFacebookPageId, false);

      // Verify the query includes both PENDING and IN_PROGRESS statuses
      expect(mockedPrisma.syncJob.findFirst).toHaveBeenCalledWith({
        where: {
          facebookPageId: mockFacebookPageId,
          status: {
            in: ['PENDING', 'IN_PROGRESS'],
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
    });
  });

  describe('Error Handling', () => {
    it('should throw error when database query fails', async () => {
      const dbError = new Error('Database connection failed');
      mockedPrisma.syncJob.findFirst.mockRejectedValue(dbError);

      await expect(startPipelineAnalysis(mockFacebookPageId, false)).rejects.toThrow(
        'Database connection failed'
      );
    });

    it('should throw error when job creation fails', async () => {
      mockedPrisma.syncJob.findFirst.mockResolvedValue(null);
      const createError = new Error('Failed to create job');
      mockedPrisma.syncJob.create.mockRejectedValue(createError);

      await expect(startPipelineAnalysis(mockFacebookPageId, false)).rejects.toThrow(
        'Failed to create job'
      );
    });
  });
});

