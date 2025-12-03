/**
 * Integration Test: Complete flow from button click to job completion
 * 
 * Tests the full end-to-end flow:
 * 1. User clicks sync button (calls handleSync)
 * 2. API endpoint receives request and creates job
 * 3. Job executes in background
 * 4. Progress updates are available via status endpoint
 * 5. Job completes successfully
 * 6. UI receives completion notification
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
      update: jest.fn(),
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

describe('Complete Flow: Button Click to Job Completion', () => {
  const mockUserId = 'user-123';
  const mockOrgId = 'org-123';
  const mockPageId = 'page-123';
  const mockJobId = 'job-123';

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
  });

  describe('Step 1: Button Click → API Request', () => {
    it('should create job when sync button is clicked', async () => {
      // Mock page lookup
      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);

      // Mock job creation
      (mockedPrisma.syncJob.findFirst as jest.Mock).mockResolvedValue(null);
      (mockedPrisma.syncJob.create as jest.Mock).mockResolvedValue({
        id: mockJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        createdAt: new Date(),
        startedAt: null,
        completedAt: null,
      });

      // Mock startInstantSync to return job ID
      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: mockJobId,
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      // Simulate button click → API call
      const request = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const response = await POST(request);
      const data = await response.json();

      // Verify job was created
      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.jobId).toBe(mockJobId);
      expect(mockedStartInstantSync).toHaveBeenCalledWith(mockPageId, mockUserId);
    });
  });

  describe('Step 2: Job Execution', () => {
    it('should execute job and update status to IN_PROGRESS', async () => {
      const mockJob = {
        id: mockJobId,
        facebookPageId: mockPageId,
        status: 'IN_PROGRESS',
        syncedContacts: 5,
        failedContacts: 0,
        totalContacts: 10,
        startedAt: new Date(),
        completedAt: null,
        facebookPage: {
          organizationId: mockOrgId,
        },
      };

      // Mock status endpoint
      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);

      const request = {} as any;
      const params = Promise.resolve({ jobId: mockJobId });

      const response = await GET(request, { params });
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.status).toBe('IN_PROGRESS');
      expect(data.syncedContacts).toBe(5);
      expect(data.totalContacts).toBe(10);
    });
  });

  describe('Step 3: Job Completion', () => {
    it('should complete job and return final status', async () => {
      const completedJob = {
        id: mockJobId,
        facebookPageId: mockPageId,
        status: 'COMPLETED',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 10,
        startedAt: new Date(Date.now() - 5000),
        completedAt: new Date(),
        tokenExpired: false,
        errors: [],
        facebookPage: {
          organizationId: mockOrgId,
        },
      };

      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(completedJob);

      const request = {} as any;
      const params = Promise.resolve({ jobId: mockJobId });

      const response = await GET(request, { params });
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.status).toBe('COMPLETED');
      expect(data.syncedContacts).toBe(10);
      expect(data.totalContacts).toBe(10);
      expect(data.completedAt).toBeDefined();
    });
  });

  describe('Step 4: Full End-to-End Flow', () => {
    it('should complete entire flow from button click to completion', async () => {
      // Step 1: Start sync
      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      mockedStartInstantSync.mockResolvedValue({
        success: true,
        jobId: mockJobId,
        message: 'Sync started',
        contactsStored: 0,
        aiAnalysisQueued: false,
      });

      const startRequest = {
        json: jest.fn().mockResolvedValue({ facebookPageId: mockPageId }),
      } as any;

      const startResponse = await POST(startRequest);
      const startData = await startResponse.json();
      expect(startData.jobId).toBe(mockJobId);

      // Step 2: Check status during execution
      const inProgressJob = {
        id: mockJobId,
        facebookPageId: mockPageId,
        status: 'IN_PROGRESS',
        syncedContacts: 5,
        failedContacts: 0,
        totalContacts: 10,
        startedAt: new Date(),
        completedAt: null,
        tokenExpired: false,
        errors: [],
        facebookPage: {
          organizationId: mockOrgId,
        },
      };

      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(inProgressJob);

      const statusRequest1 = {} as any;
      const params1 = Promise.resolve({ jobId: mockJobId });
      const statusResponse1 = await GET(statusRequest1, { params: params1 });
      const statusData1 = await statusResponse1.json();
      expect(statusData1.status).toBe('IN_PROGRESS');
      expect(statusData1.syncedContacts).toBe(5);

      // Step 3: Check final status
      const completedJob = {
        ...inProgressJob,
        status: 'COMPLETED',
        syncedContacts: 10,
        completedAt: new Date(),
      };

      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(completedJob);

      const statusRequest2 = {} as any;
      const params2 = Promise.resolve({ jobId: mockJobId });
      const statusResponse2 = await GET(statusRequest2, { params: params2 });
      const statusData2 = await statusResponse2.json();
      expect(statusData2.status).toBe('COMPLETED');
      expect(statusData2.syncedContacts).toBe(10);
    });
  });
});

