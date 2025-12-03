/**
 * Integration Test: Multiple users can run jobs simultaneously (different pages)
 * 
 * Tests:
 * 1. User A can start a job for Page A
 * 2. User B can start a job for Page B at the same time
 * 3. Jobs don't interfere with each other
 * 4. Each user can only see their own organization's jobs
 * 5. Status endpoints return correct jobs for each user
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
      findUnique: jest.fn(),
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

jest.mock('@/lib/api/validate-uuid', () => ({
  validateUUID: jest.fn(() => null),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedStartInstantSync = startInstantSync as jest.MockedFunction<typeof startInstantSync>;
const mockedValidateSession = validateSession as jest.MockedFunction<typeof validateSession>;
const mockedValidateUUID = validateUUID as jest.MockedFunction<typeof validateUUID>;

describe('Multiple Users Can Run Jobs Simultaneously', () => {
  const userA = {
    id: 'user-a',
    organizationId: 'org-a',
    email: 'user-a@example.com',
  };

  const userB = {
    id: 'user-b',
    organizationId: 'org-b',
    email: 'user-b@example.com',
  };

  const pageA = {
    id: 'page-a',
    pageId: 'fb-page-a',
    pageName: 'Page A',
    organizationId: 'org-a',
    pageAccessToken: 'token-a',
    instagramAccountId: null,
    instagramUsername: null,
    isActive: true,
    lastSyncedAt: null,
    autoSync: false,
    autoPipelineId: null,
  };

  const pageB = {
    id: 'page-b',
    pageId: 'fb-page-b',
    pageName: 'Page B',
    organizationId: 'org-b',
    pageAccessToken: 'token-b',
    instagramAccountId: null,
    instagramUsername: null,
    isActive: true,
    lastSyncedAt: null,
    autoSync: false,
    autoPipelineId: null,
  };

  const jobA = {
    id: 'job-a',
    facebookPageId: 'page-a',
    status: 'IN_PROGRESS',
    syncedContacts: 5,
    failedContacts: 0,
    totalContacts: 10,
    startedAt: new Date(),
    completedAt: null,
    tokenExpired: false,
    errors: [],
    facebookPage: {
      organizationId: 'org-a',
    },
  };

  const jobB = {
    id: 'job-b',
    facebookPageId: 'page-b',
    status: 'IN_PROGRESS',
    syncedContacts: 3,
    failedContacts: 0,
    totalContacts: 8,
    startedAt: new Date(),
    completedAt: null,
    tokenExpired: false,
    errors: [],
    facebookPage: {
      organizationId: 'org-b',
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Concurrent job creation', () => {
    it('should allow User A and User B to start jobs simultaneously', async () => {
      // User A starts job
      mockedAuth.mockResolvedValueOnce({ user: userA } as any);
      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValueOnce(pageA);
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValueOnce(null);
      mockedStartInstantSync.mockResolvedValueOnce({
        success: true,
        jobId: 'job-a',
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const requestA = {
        json: jest.fn().mockResolvedValue({ facebookPageId: 'page-a' }),
      } as any;

      const responseA = await POST(requestA);
      const dataA = await responseA.json();

      expect(responseA.status).toBe(200);
      expect(dataA.jobId).toBe('job-a');
      expect(mockedStartInstantSync).toHaveBeenCalledWith('page-a', 'user-a');

      // User B starts job (simultaneously)
      mockedAuth.mockResolvedValueOnce({ user: userB } as any);
      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValueOnce(pageB);
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValueOnce(null);
      mockedStartInstantSync.mockResolvedValueOnce({
        success: true,
        jobId: 'job-b',
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const requestB = {
        json: jest.fn().mockResolvedValue({ facebookPageId: 'page-b' }),
      } as any;

      const responseB = await POST(requestB);
      const dataB = await responseB.json();

      expect(responseB.status).toBe(200);
      expect(dataB.jobId).toBe('job-b');
      expect(mockedStartInstantSync).toHaveBeenCalledWith('page-b', 'user-b');
    });
  });

  describe('Job isolation', () => {
    it('should return correct job status for each user', async () => {
      // User A checks their job
      mockedAuth.mockResolvedValueOnce({ user: userA } as any);
      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValueOnce(jobA);

      const statusRequestA = {} as any;
      const paramsA = Promise.resolve({ jobId: 'job-a' });
      const statusResponseA = await GET(statusRequestA, { params: paramsA });
      const statusDataA = await statusResponseA.json();

      expect(statusResponseA.status).toBe(200);
      expect(statusDataA.id).toBe('job-a');
      expect(statusDataA.syncedContacts).toBe(5);

      // User B checks their job
      mockedAuth.mockResolvedValueOnce({ user: userB } as any);
      mockedValidateSession.mockReturnValueOnce({ session: { user: userB } } as any);
      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValueOnce(jobB);

      const statusRequestB = {} as any;
      const paramsB = Promise.resolve({ jobId: 'job-b' });
      const statusResponseB = await GET(statusRequestB, { params: paramsB });
      const statusDataB = await statusResponseB.json();

      expect(statusResponseB.status).toBe(200);
      expect(statusDataB.id).toBe('job-b');
      expect(statusDataB.syncedContacts).toBe(3);
    });

    it('should prevent User A from accessing User B\'s job', async () => {
      // User A tries to access User B's job
      mockedAuth.mockResolvedValueOnce({ user: userA } as any);
      mockedValidateSession.mockReturnValueOnce({ session: { user: userA } } as any);
      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValueOnce(jobB);

      const statusRequest = {} as any;
      const params = Promise.resolve({ jobId: 'job-b' });
      const statusResponse = await GET(statusRequest, { params });
      const statusData = await statusResponse.json();

      // Should return 403 because job belongs to different organization
      expect(statusResponse.status).toBe(403);
      expect(statusData.error).toContain('Unauthorized');
    });
  });

  describe('Parallel execution', () => {
    it('should handle multiple jobs running in parallel', async () => {
      // Simulate both jobs running simultaneously
      const jobs = [
        { ...jobA, syncedContacts: 7 },
        { ...jobB, syncedContacts: 4 },
      ];

      // Check both jobs in parallel
      mockedAuth.mockResolvedValueOnce({ user: userA } as any);
      mockedAuth.mockResolvedValueOnce({ user: userB } as any);
      mockedValidateSession.mockReturnValueOnce({ session: { user: userA } } as any);
      mockedValidateSession.mockReturnValueOnce({ session: { user: userB } } as any);
      (mockedPrisma.syncJob.findUnique as jest.Mock)
        .mockResolvedValueOnce(jobs[0])
        .mockResolvedValueOnce(jobs[1]);

      const [responseA, responseB] = await Promise.all([
        GET(
          {} as any,
          { params: Promise.resolve({ jobId: 'job-a' }) }
        ),
        GET(
          {} as any,
          { params: Promise.resolve({ jobId: 'job-b' }) }
        ),
      ]);

      const dataA = await responseA.json();
      const dataB = await responseB.json();

      expect(responseA.status).toBe(200);
      expect(responseB.status).toBe(200);
      expect(dataA.id).toBe('job-a');
      expect(dataB.id).toBe('job-b');
      expect(dataA.syncedContacts).toBe(7);
      expect(dataB.syncedContacts).toBe(4);
    });
  });
});

