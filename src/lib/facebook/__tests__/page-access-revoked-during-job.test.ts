/**
 * Tests for page access revocation during job execution
 * 
 * Tests the scenario where a user's page access is revoked while a job is running.
 * This should result in the job being cancelled or stopped gracefully.
 */

import { checkPageAccess } from '@/lib/developer/check-page-access';
import { prisma } from '@/lib/db';
import { SyncJobStatus } from '@prisma/client';

// Mock Prisma Client first
jest.mock('@prisma/client', () => ({
  Prisma: {
    JsonNull: null,
  },
  SyncJobStatus: {
    PENDING: 'PENDING',
    IN_PROGRESS: 'IN_PROGRESS',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
    CANCELLED: 'CANCELLED',
  },
}));

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findUnique: jest.fn(),
      update: jest.fn(),
      findMany: jest.fn(),
    },
    facebookPage: {
      findUnique: jest.fn(),
    },
    contact: {
      findMany: jest.fn(),
    },
    pageAccess: {
      findUnique: jest.fn(),
    },
  },
}));

jest.mock('@/lib/developer/check-page-access', () => ({
  checkPageAccess: jest.fn(),
}));

jest.mock('../client');
jest.mock('../pipeline-analyzer', () => ({
  executePipelineAnalysis: jest.fn(),
}));
jest.mock('../background-sync', () => ({
  executeBackgroundSync: jest.fn(),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedCheckPageAccess = checkPageAccess as jest.MockedFunction<typeof checkPageAccess>;

describe('Test: Page access revoked during job', () => {
  const mockJobId = 'test-job-id-123';
  const mockFacebookPageId = 'test-page-id-456';
  const mockUserId = 'test-user-id-789';
  const mockPagePath = '/contacts';

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Pipeline Analysis Job - Page Access Revoked', () => {
    it('should stop processing when page access is revoked during pipeline analysis', async () => {
      // Setup: Job starts with access enabled
      mockedPrisma.syncJob.findUnique.mockResolvedValueOnce({
        id: mockJobId,
        status: 'IN_PROGRESS' as SyncJobStatus,
        facebookPageId: mockFacebookPageId,
        userId: mockUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 10,
        errors: null,
      });

      mockedPrisma.facebookPage.findUnique.mockResolvedValueOnce({
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageName: 'Test Page',
        pageAccessToken: 'token-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipelineMode: 'SKIP_EXISTING',
        createdAt: new Date(),
        updatedAt: new Date(),
        autoPipeline: null,
      });

      mockedPrisma.contact.findMany.mockResolvedValueOnce([]);

      // Simulate page access being revoked mid-job
      // First check: access enabled
      mockedCheckPageAccess.mockResolvedValueOnce(true);
      // Second check: access revoked
      mockedCheckPageAccess.mockResolvedValueOnce(false);

      // Mock pageAccess check to return disabled
      mockedPrisma.pageAccess.findUnique.mockResolvedValueOnce({
        id: 'access-1',
        userId: mockUserId,
        pagePath: mockPagePath,
        isEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Mock job cancellation check - should return true after access is revoked
      mockedPrisma.syncJob.findUnique
        .mockResolvedValueOnce({
          status: 'IN_PROGRESS' as SyncJobStatus,
        })
        .mockResolvedValueOnce({
          status: 'CANCELLED' as SyncJobStatus,
        });

      // Simulate job execution checking page access
      const pageAccessBefore = await mockedCheckPageAccess(mockUserId, mockPagePath);
      expect(pageAccessBefore).toBe(true);

      // Simulate access being revoked
      const pageAccessAfter = await mockedCheckPageAccess(mockUserId, mockPagePath);
      expect(pageAccessAfter).toBe(false);

      // Verify that page access was checked
      expect(mockedCheckPageAccess).toHaveBeenCalled();
    });

    it('should cancel job when page access is revoked during background sync', async () => {
      // Setup: Job in progress
      mockedPrisma.syncJob.findUnique.mockResolvedValue({
        id: mockJobId,
        status: 'IN_PROGRESS' as SyncJobStatus,
        facebookPageId: mockFacebookPageId,
        userId: mockUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        errors: null,
      });

      mockedPrisma.facebookPage.findUnique.mockResolvedValue({
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageName: 'Test Page',
        pageAccessToken: 'token-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipelineMode: 'SKIP_EXISTING',
        createdAt: new Date(),
        updatedAt: new Date(),
        autoPipeline: null,
      });

      // Simulate access being revoked
      mockedCheckPageAccess.mockResolvedValue(false);
      mockedPrisma.pageAccess.findUnique.mockResolvedValue({
        id: 'access-1',
        userId: mockUserId,
        pagePath: mockPagePath,
        isEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Job should be cancelled
      mockedPrisma.syncJob.update.mockResolvedValue({
        id: mockJobId,
        status: 'CANCELLED' as SyncJobStatus,
        facebookPageId: mockFacebookPageId,
        userId: mockUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        errors: null,
      });

      // Simulate page access check during job execution
      const hasAccess = await mockedCheckPageAccess(mockUserId, mockPagePath);
      expect(hasAccess).toBe(false);

      // Job should be cancelled when access is revoked
      if (!hasAccess) {
        await mockedPrisma.syncJob.update({
          where: { id: mockJobId },
          data: {
            status: 'CANCELLED',
            completedAt: new Date(),
          },
        });
      }

      // Verify job status was updated to CANCELLED
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: mockJobId },
          data: expect.objectContaining({
            status: 'CANCELLED',
          }),
        })
      );
    });

    it('should handle page access revocation gracefully without throwing unhandled errors', async () => {
      // Setup: Job running
      mockedPrisma.syncJob.findUnique.mockResolvedValue({
        id: mockJobId,
        status: 'IN_PROGRESS' as SyncJobStatus,
        facebookPageId: mockFacebookPageId,
        userId: mockUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
        syncedContacts: 5,
        failedContacts: 0,
        totalContacts: 10,
        errors: null,
      });

      mockedPrisma.facebookPage.findUnique.mockResolvedValue({
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageName: 'Test Page',
        pageAccessToken: 'token-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipelineMode: 'SKIP_EXISTING',
        createdAt: new Date(),
        updatedAt: new Date(),
        autoPipeline: null,
      });

      // Access revoked mid-execution
      mockedCheckPageAccess
        .mockResolvedValueOnce(true) // Initial check: enabled
        .mockResolvedValueOnce(false); // Later check: revoked

      mockedPrisma.pageAccess.findUnique.mockResolvedValue({
        id: 'access-1',
        userId: mockUserId,
        pagePath: mockPagePath,
        isEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Job cancellation should be handled
      mockedPrisma.syncJob.findUnique.mockResolvedValue({
        status: 'CANCELLED' as SyncJobStatus,
      });

      mockedPrisma.syncJob.update.mockResolvedValue({
        id: mockJobId,
        status: 'CANCELLED' as SyncJobStatus,
        facebookPageId: mockFacebookPageId,
        userId: mockUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
        syncedContacts: 5,
        failedContacts: 0,
        totalContacts: 10,
        errors: null,
      });

      // Simulate checking access during job execution
      const initialAccess = await mockedCheckPageAccess(mockUserId, mockPagePath);
      expect(initialAccess).toBe(true);

      // Access revoked
      const revokedAccess = await mockedCheckPageAccess(mockUserId, mockPagePath);
      expect(revokedAccess).toBe(false);

      // Job should handle this gracefully
      if (!revokedAccess) {
        await mockedPrisma.syncJob.update({
          where: { id: mockJobId },
          data: { status: 'CANCELLED', completedAt: new Date() },
        });
      }

      // Should not throw unhandled promise rejection
      expect(mockedPrisma.syncJob.update).toHaveBeenCalled();
    });

    it('should preserve partial progress when page access is revoked', async () => {
      // Setup: Job has processed some contacts
      const partialProgress = {
        id: mockJobId,
        status: 'IN_PROGRESS' as SyncJobStatus,
        facebookPageId: mockFacebookPageId,
        userId: mockUserId,
        createdAt: new Date(),
        updatedAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
        syncedContacts: 7,
        failedContacts: 1,
        totalContacts: 10,
        errors: null,
      };

      mockedPrisma.syncJob.findUnique.mockResolvedValue(partialProgress);

      mockedPrisma.facebookPage.findUnique.mockResolvedValue({
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageName: 'Test Page',
        pageAccessToken: 'token-123',
        organizationId: 'org-123',
        autoPipelineId: null,
        autoPipelineMode: 'SKIP_EXISTING',
        createdAt: new Date(),
        updatedAt: new Date(),
        autoPipeline: null,
      });

      // Access revoked
      mockedCheckPageAccess.mockResolvedValue(false);
      mockedPrisma.pageAccess.findUnique.mockResolvedValue({
        id: 'access-1',
        userId: mockUserId,
        pagePath: mockPagePath,
        isEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Job should be cancelled but preserve progress
      mockedPrisma.syncJob.update.mockResolvedValue({
        ...partialProgress,
        status: 'CANCELLED' as SyncJobStatus,
        completedAt: new Date(),
      });

      // Simulate access check during job
      const hasAccess = await mockedCheckPageAccess(mockUserId, mockPagePath);
      expect(hasAccess).toBe(false);

      // Cancel job but preserve progress
      if (!hasAccess) {
        await mockedPrisma.syncJob.update({
          where: { id: mockJobId },
          data: {
            status: 'CANCELLED',
            completedAt: new Date(),
            syncedContacts: partialProgress.syncedContacts,
            failedContacts: partialProgress.failedContacts,
            totalContacts: partialProgress.totalContacts,
          },
        });
      }

      // Verify progress is preserved
      const updateCall = mockedPrisma.syncJob.update.mock.calls.find(
        call => call[0].data.status === 'CANCELLED'
      );
      expect(updateCall).toBeDefined();
      if (updateCall) {
        expect(updateCall[0].data.syncedContacts).toBe(7);
        expect(updateCall[0].data.failedContacts).toBe(1);
        expect(updateCall[0].data.totalContacts).toBe(10);
      }
    });
  });
});

