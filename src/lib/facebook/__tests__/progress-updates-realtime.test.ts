/**
 * Integration Test: Progress updates reflect in real-time
 * 
 * Tests:
 * 1. Progress updates are available via status endpoint
 * 2. Progress counts increment as job processes
 * 3. Status transitions: PENDING → IN_PROGRESS → COMPLETED
 * 4. Multiple progress checks show incremental updates
 * 5. Real-time polling can detect progress changes
 */

import { GET } from '@/app/api/facebook/sync-status/[jobId]/route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

// Mock dependencies
jest.mock('@/auth', () => ({
  auth: jest.fn(),
}));

jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findUnique: jest.fn(),
    },
  },
}));

jest.mock('@/lib/prisma-error-handler', () => ({
  isRetryablePrismaError: jest.fn(() => false),
}));

jest.mock('@/lib/api/validate-session', () => ({
  validateSession: jest.fn(),
}));

jest.mock('@/lib/api/validate-uuid', () => ({
  validateUUID: jest.fn(() => null),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedValidateSession = require('@/lib/api/validate-session').validateSession as jest.MockedFunction<any>;
const mockedValidateUUID = require('@/lib/api/validate-uuid').validateUUID as jest.MockedFunction<any>;

describe('Progress Updates Reflect in Real-Time', () => {
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

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue(mockSession as any);
    mockedValidateSession.mockReturnValue({ session: mockSession } as any);
    mockedValidateUUID.mockReturnValue(null);
  });

  describe('Progress updates increment', () => {
    it('should show incremental progress updates', async () => {
      const progressStates = [
        {
          status: 'PENDING',
          syncedContacts: 0,
          failedContacts: 0,
          totalContacts: 0,
        },
        {
          status: 'IN_PROGRESS',
          syncedContacts: 2,
          failedContacts: 0,
          totalContacts: 10,
        },
        {
          status: 'IN_PROGRESS',
          syncedContacts: 5,
          failedContacts: 0,
          totalContacts: 10,
        },
        {
          status: 'IN_PROGRESS',
          syncedContacts: 8,
          failedContacts: 1,
          totalContacts: 10,
        },
        {
          status: 'COMPLETED',
          syncedContacts: 9,
          failedContacts: 1,
          totalContacts: 10,
        },
      ];

      for (const progressState of progressStates) {
        const mockJob = {
          id: mockJobId,
          facebookPageId: mockPageId,
          ...progressState,
          startedAt: progressState.status !== 'PENDING' ? new Date() : null,
          completedAt: progressState.status === 'COMPLETED' ? new Date() : null,
          tokenExpired: false,
          errors: [],
          facebookPage: {
            organizationId: mockOrgId,
          },
        };

        (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);

        const request = {} as any;
        const params = Promise.resolve({ jobId: mockJobId });

        const response = await GET(request, { params });
        const data = await response.json();

        expect(response.status).toBe(200);
        expect(data.status).toBe(progressState.status);
        expect(data.syncedContacts).toBe(progressState.syncedContacts);
        expect(data.failedContacts).toBe(progressState.failedContacts);
        expect(data.totalContacts).toBe(progressState.totalContacts);
      }
    });
  });

  describe('Status transitions', () => {
    it('should transition from PENDING to IN_PROGRESS to COMPLETED', async () => {
      // PENDING state
      let mockJob = {
        id: mockJobId,
        facebookPageId: mockPageId,
        status: 'PENDING',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        startedAt: null,
        completedAt: null,
        tokenExpired: false,
        errors: [],
        facebookPage: {
          organizationId: mockOrgId,
        },
      };

      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);
      let request = {} as any;
      let params = Promise.resolve({ jobId: mockJobId });
      let response = await GET(request, { params });
      let data = await response.json();
      expect(data.status).toBe('PENDING');

      // IN_PROGRESS state
      mockJob = {
        ...mockJob,
        status: 'IN_PROGRESS',
        startedAt: new Date(),
        syncedContacts: 5,
        totalContacts: 10,
      };

      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);
      request = {} as any;
      params = Promise.resolve({ jobId: mockJobId });
      response = await GET(request, { params });
      data = await response.json();
      expect(data.status).toBe('IN_PROGRESS');
      expect(data.syncedContacts).toBe(5);

      // COMPLETED state
      mockJob = {
        ...mockJob,
        status: 'COMPLETED',
        syncedContacts: 10,
        completedAt: new Date(),
      };

      (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);
      request = {} as any;
      params = Promise.resolve({ jobId: mockJobId });
      response = await GET(request, { params });
      data = await response.json();
      expect(data.status).toBe('COMPLETED');
      expect(data.syncedContacts).toBe(10);
      expect(data.completedAt).toBeDefined();
    });
  });

  describe('Real-time polling simulation', () => {
    it('should detect progress changes across multiple polls', async () => {
      const pollResults: Array<{ synced: number; status: string }> = [];

      // Simulate 5 polling cycles
      for (let i = 0; i < 5; i++) {
        const mockJob = {
          id: mockJobId,
          facebookPageId: mockPageId,
          status: i < 4 ? 'IN_PROGRESS' : 'COMPLETED',
          syncedContacts: i * 2,
          failedContacts: 0,
          totalContacts: 10,
          startedAt: new Date(),
          completedAt: i === 4 ? new Date() : null,
          tokenExpired: false,
          errors: [],
          facebookPage: {
            organizationId: mockOrgId,
          },
        };

        (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);

        const request = {} as any;
        const params = Promise.resolve({ jobId: mockJobId });
        const response = await GET(request, { params });
        const data = await response.json();

        pollResults.push({
          synced: data.syncedContacts,
          status: data.status,
        });
      }

      // Verify progress increased
      expect(pollResults[0].synced).toBe(0);
      expect(pollResults[1].synced).toBe(2);
      expect(pollResults[2].synced).toBe(4);
      expect(pollResults[3].synced).toBe(6);
      expect(pollResults[4].synced).toBe(8);
      expect(pollResults[4].status).toBe('COMPLETED');
    });
  });

  describe('Progress percentage calculation', () => {
    it('should calculate progress percentage correctly', async () => {
      const testCases = [
        { synced: 0, total: 10, expected: 0 },
        { synced: 5, total: 10, expected: 50 },
        { synced: 10, total: 10, expected: 100 },
        { synced: 3, total: 0, expected: 0 }, // Edge case: no total yet
      ];

      for (const testCase of testCases) {
        const mockJob = {
          id: mockJobId,
          facebookPageId: mockPageId,
          status: testCase.synced === testCase.total ? 'COMPLETED' : 'IN_PROGRESS',
          syncedContacts: testCase.synced,
          failedContacts: 0,
          totalContacts: testCase.total,
          startedAt: new Date(),
          completedAt: testCase.synced === testCase.total ? new Date() : null,
          tokenExpired: false,
          errors: [],
          facebookPage: {
            organizationId: mockOrgId,
          },
        };

        (mockedPrisma.syncJob.findUnique as jest.Mock).mockResolvedValue(mockJob);

        const request = {} as any;
        const params = Promise.resolve({ jobId: mockJobId });
        const response = await GET(request, { params });
        const data = await response.json();

        const progress = testCase.total > 0 
          ? Math.round((data.syncedContacts / data.totalContacts) * 100)
          : 0;

        // Handle NaN case when total is 0 but synced > 0
        const finalProgress = isNaN(progress) ? 0 : progress;
        expect(finalProgress).toBe(testCase.expected);
      }
    });
  });
});

