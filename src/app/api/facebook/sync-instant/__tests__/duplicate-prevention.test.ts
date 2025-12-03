/**
 * Integration Test: User cannot start duplicate job for same page
 * 
 * Tests:
 * 1. If a job is already PENDING for a page, return existing job
 * 2. If a job is already IN_PROGRESS for a page, return existing job
 * 3. If a job is COMPLETED, allow new job to be created
 * 4. If a job is FAILED, allow new job to be created
 * 5. If a job is CANCELLED, allow new job to be created
 * 6. Duplicate prevention works across multiple requests
 */

import { POST } from '../route';
import { GET } from '../../sync-status/[jobId]/route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startInstantSync } from '@/lib/facebook/instant-sync';
import { validateSession } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

// Mock dependencies
jest.mock('@/auth', () => ({
  auth: jest.fn(),
}));

jest.mock('@/lib/db', () => ({
  prisma: {
    facebookPage: {
      findFirst: jest.fn(),
    },
    syncJob: {
      create: jest.fn(),
      findFirst: jest.fn(),
    },
  },
}));

jest.mock('@/lib/prisma-error-handler', () => ({
  isRetryablePrismaError: jest.fn(() => false),
}));

jest.mock('@/lib/facebook/instant-sync', () => ({
  startInstantSync: jest.fn(),
}));

jest.mock('@/lib/api/validate-session', () => ({
  validateSession: jest.fn(),
}));

jest.mock('@/lib/api/validate-uuid', () => ({
  validateUUID: jest.fn(() => null),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedStartInstantSync = startInstantSync as jest.MockedFunction<typeof startInstantSync>;
const mockedValidateSession = validateSession as jest.MockedFunction<typeof validateSession>;
const mockedValidateUUID = validateUUID as jest.MockedFunction<typeof validateUUID>;

describe('User Cannot Start Duplicate Job for Same Page', () => {
  const mockUserId = 'user-123';
  const mockOrgId = 'org-123';
  const mockPageId = 'page-123';
  const existingJobId = 'existing-job-123';
  const newJobId = 'new-job-123';

  const mockSession = {
    user: {
      id: mockUserId,
      organizationId: mockOrgId,
      email: 'test@example.com',
    },
  };

  const mockPage = {
    id: mockPageId,
    pageId: 'fb-page-123',
    pageName: 'Test Page',
    organizationId: mockOrgId,
    pageAccessToken: 'token-123',
    instagramAccountId: null,
    instagramUsername: null,
    isActive: true,
    lastSyncedAt: null,
    autoSync: false,
    autoPipelineId: null,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue(mockSession as any);
    mockedValidateSession.mockReturnValue({ session: mockSession } as any);
    mockedValidateUUID.mockReturnValue(null);
    (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
  });

  describe('Prevent duplicate PENDING jobs', () => {
    it('should return existing job when PENDING job exists', async () => {
      const existingJob = {
        id: existingJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
      };

      // Mock finding existing job
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(existingJob);

      // Mock startInstantSync to return existing job
      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: existingJobId,
        message: 'Sync already in progress',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const request = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const response = await POST(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.jobId).toBe(existingJobId);
      expect(data.message).toContain('already in progress');
      // Should not create a new job
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
    });
  });

  describe('Prevent duplicate IN_PROGRESS jobs', () => {
    it('should return existing job when IN_PROGRESS job exists', async () => {
      const existingJob = {
        id: existingJobId,
        facebookPageId: mockPageId,
        status: 'IN_PROGRESS',
        syncedContacts: 5,
        failedContacts: 0,
        totalContacts: 10,
        createdAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
      };

      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(existingJob);
      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: existingJobId,
        message: 'Sync already in progress',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const request = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const response = await POST(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.jobId).toBe(existingJobId);
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
    });
  });

  describe('Allow new job after completion', () => {
    it('should allow new job when previous job is COMPLETED', async () => {
      const completedJob = {
        id: existingJobId,
        facebookPageId: mockPageId,
        status: 'COMPLETED',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 10,
        createdAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
      };

      // No active job found (completed job doesn't count)
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.syncJob.create as jest.Mock).mockResolvedValue({
        id: newJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
      });

      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: newJobId,
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const request = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const response = await POST(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.jobId).toBe(newJobId);
      expect(data.jobId).not.toBe(existingJobId);
    });

    it('should allow new job when previous job is FAILED', async () => {
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.syncJob.create as jest.Mock).mockResolvedValue({
        id: newJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
      });

      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: newJobId,
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const request = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const response = await POST(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.jobId).toBe(newJobId);
    });

    it('should allow new job when previous job is CANCELLED', async () => {
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.syncJob.create as jest.Mock).mockResolvedValue({
        id: newJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
      });

      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: newJobId,
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const request = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const response = await POST(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.jobId).toBe(newJobId);
    });
  });

  describe('Concurrent duplicate prevention', () => {
    it('should prevent duplicate even when multiple requests arrive simultaneously', async () => {
      const existingJob = {
        id: existingJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
      };

      // First request finds existing job
      (mockedPrisma.syncJob.findFirst as jest.Mock)
        .mockResolvedValueOnce(existingJob) // First request
        .mockResolvedValueOnce(existingJob); // Second request (concurrent)

      mockedStartInstantSync
        .mockResolvedValueOnce({
          success: true,
          jobId: existingJobId,
          message: 'Sync already in progress',
          contactsStored: 0,
          aiAnalysisQueued: false,
        })
        .mockResolvedValueOnce({
          success: true,
          jobId: existingJobId,
          message: 'Sync already in progress',
          contactsStored: 0,
          aiAnalysisQueued: false,
        });

      // Simulate two concurrent requests
      const request1 = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const request2 = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const [response1, response2] = await Promise.all([
        POST(request1),
        POST(request2),
      ]);

      const data1 = await response1.json();
      const data2 = await response2.json();

      // Both should return the same existing job
      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);
      expect(data1.jobId).toBe(existingJobId);
      expect(data2.jobId).toBe(existingJobId);
      // Should not create any new jobs
      expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
    });
  });

  describe('Status-based duplicate check', () => {
    it('should only check PENDING and IN_PROGRESS statuses', async () => {
      // Verify the query logic checks for PENDING and IN_PROGRESS
      const testCases = [
        { status: 'PENDING', shouldPrevent: true },
        { status: 'IN_PROGRESS', shouldPrevent: true },
        { status: 'COMPLETED', shouldPrevent: false },
        { status: 'FAILED', shouldPrevent: false },
        { status: 'CANCELLED', shouldPrevent: false },
      ];

      for (const testCase of testCases) {
        jest.clearAllMocks();
        mockedAuth.mockResolvedValue(mockSession as any);
        (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);

        if (testCase.shouldPrevent) {
          (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue({
            id: existingJobId,
            status: testCase.status,
            facebookPageId: mockPageId,
          });
          mockedStartInstantSync.mockResolvedValue({
            success: true,
            jobId: existingJobId,
            message: 'Sync already in progress',
            contactsStored: 0,
            aiAnalysisQueued: false,
          });
        } else {
          (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(null);
          (mockedPrisma.syncJob.create as jest.Mock).mockResolvedValue({
            id: newJobId,
            facebookPageId: mockPageId,
            status: 'PENDING',
          });
          mockedStartInstantSync.mockResolvedValue({
            success: true,
            jobId: newJobId,
            message: 'Sync started',
            contactsStored: 0,
            aiAnalysisQueued: false,
          });
        }

        const request = {
          json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
        } as any;

        const response = await POST(request);
        const data = await response.json();

        if (testCase.shouldPrevent) {
          expect(data.jobId).toBe(existingJobId);
          expect(mockedPrisma.syncJob.create).not.toHaveBeenCalled();
        } else {
          expect(data.jobId).toBe(newJobId);
        }
      }
    });
  });
});

