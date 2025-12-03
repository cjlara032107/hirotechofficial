/**
 * Tests for Pipeline Analyzer Contact Querying Logic
 * 
 * Tests the executePipelineAnalysis function to ensure correct contact filtering:
 * - Returns all contacts when no pipeline exists
 * - Returns only unassigned contacts in SKIP_EXISTING mode
 * - Returns all contacts in force update mode
 */

import { executePipelineAnalysis } from '../pipeline-analyzer';
import { prisma } from '@/lib/db';
import { withRetry } from '@/lib/db-retry';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      update: jest.fn(),
    },
    facebookPage: {
      findUnique: jest.fn(),
    },
    contact: {
      findMany: jest.fn(),
    },
  },
}));

jest.mock('@/lib/db-retry', () => ({
  withRetry: jest.fn((fn) => fn()),
}));

jest.mock('../client', () => ({
  FacebookClient: jest.fn().mockImplementation(() => ({
    getConversations: jest.fn(),
  })),
}));

jest.mock('@/lib/ai/enhanced-analysis', () => ({
  analyzeWithFallback: jest.fn(),
}));

jest.mock('@/lib/pipelines/auto-assign', () => ({
  autoAssignContactToPipeline: jest.fn(),
}));

jest.mock('@/lib/pipelines/stage-analyzer', () => ({
  applyStageScoreRanges: jest.fn(),
}));

jest.mock('@/lib/ai/dynamic-concurrency', () => ({
  getCachedConcurrencyLimits: jest.fn(() => ({
    keyCount: 1,
    analysisConcurrency: 50,
    conversationFetchConcurrency: 30,
    batchConcurrency: 3,
    messageGenerationConcurrency: 20,
    batchSize: 50,
    chunkSize: 100,
    systemResources: {
      availableMemory: 8 * 1024 * 1024 * 1024, // 8GB
      totalMemory: 16 * 1024 * 1024 * 1024, // 16GB
      memoryUsagePercent: 50,
      processMemoryUsage: {
        rss: 100 * 1024 * 1024, // 100MB
        heapTotal: 50 * 1024 * 1024,
        heapUsed: 30 * 1024 * 1024,
        external: 10 * 1024 * 1024,
        arrayBuffers: 5 * 1024 * 1024,
      },
      cpuCores: 8,
      cpuLoadAverage: 1.5,
      resourceAvailabilityScore: 0.75,
    },
  })),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedWithRetry = withRetry as jest.MockedFunction<typeof withRetry>;

describe('executePipelineAnalysis - Contact Querying', () => {
  const mockJobId = 'test-job-id-123';
  const mockFacebookPageId = 'test-page-id-456';
  const mockOrganizationId = 'test-org-id-789';

  const mockContacts = [
    {
      id: 'contact-1',
      messengerPSID: 'psid-1',
      instagramSID: null,
      firstName: 'John',
      lastName: 'Doe',
      lastInteraction: new Date(),
      pipelineId: null,
    },
    {
      id: 'contact-2',
      messengerPSID: 'psid-2',
      instagramSID: null,
      firstName: 'Jane',
      lastName: 'Smith',
      lastInteraction: new Date(),
      pipelineId: 'pipeline-1',
    },
    {
      id: 'contact-3',
      instagramSID: 'ig-sid-1',
      messengerPSID: null,
      firstName: 'Bob',
      lastName: 'Johnson',
      lastInteraction: new Date(),
      pipelineId: null,
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console.log during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    // Default mock for withRetry - just execute the function
    mockedWithRetry.mockImplementation((fn) => fn());

    // Default mock for syncJob.update
    mockedPrisma.syncJob.update.mockResolvedValue({
      id: mockJobId,
      status: 'IN_PROGRESS',
      startedAt: new Date(),
    } as any);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Returns all contacts when no pipeline exists', () => {
    it('should return all contacts when autoPipelineId is null', async () => {
      // Mock page with no pipeline
      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: null,
        autoPipeline: null,
        autoPipelineMode: 'SKIP_EXISTING' as const,
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);

      // Mock contact.findMany to return empty array to trigger early return
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return (when no contacts)
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      // Execute the function
      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Verify contact.findMany was called
      expect(mockedPrisma.contact.findMany).toHaveBeenCalled();

      // Verify the whereClause does NOT include pipelineId filter
      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      expect(whereClause).toMatchObject({
        facebookPageId: mockFacebookPageId,
        OR: [
          { messengerPSID: { not: null } },
          { instagramSID: { not: null } },
        ],
      });

      // Verify pipelineId is NOT in the whereClause
      expect(whereClause.pipelineId).toBeUndefined();
    });

    it('should return all contacts when autoPipeline is null', async () => {
      // Mock page with autoPipelineId but null autoPipeline
      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: 'pipeline-123',
        autoPipeline: null, // Pipeline ID exists but pipeline is null
        autoPipelineMode: 'SKIP_EXISTING' as const,
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);
      // Mock empty contacts to trigger early return (we just need to verify the whereClause)
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      // Should not filter by pipelineId when no pipeline exists
      expect(whereClause.pipelineId).toBeUndefined();
    });
  });

  describe('Test: Returns only unassigned contacts in SKIP_EXISTING mode', () => {
    it('should return only contacts with pipelineId null when pipeline exists and mode is SKIP_EXISTING', async () => {
      const mockPipeline = {
        id: 'pipeline-1',
        name: 'Sales Pipeline',
        stages: [
          { id: 'stage-1', order: 0, leadScoreMin: 0, leadScoreMax: 50 },
          { id: 'stage-2', order: 1, leadScoreMin: 51, leadScoreMax: 100 },
        ],
      };

      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: 'pipeline-1',
        autoPipeline: mockPipeline,
        autoPipelineMode: 'SKIP_EXISTING' as const,
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);

      // Mock empty contacts to trigger early return (we just need to verify the whereClause)
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Verify contact.findMany was called
      expect(mockedPrisma.contact.findMany).toHaveBeenCalled();

      // Verify the whereClause includes pipelineId: null
      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      expect(whereClause).toMatchObject({
        facebookPageId: mockFacebookPageId,
        OR: [
          { messengerPSID: { not: null } },
          { instagramSID: { not: null } },
        ],
        pipelineId: null, // Should filter for unassigned contacts
      });
    });

    it('should filter by pipelineId null even when forceUpdateExisting is false', async () => {
      const mockPipeline = {
        id: 'pipeline-1',
        name: 'Sales Pipeline',
        stages: [
          { id: 'stage-1', order: 0, leadScoreMin: 0, leadScoreMax: 100 },
        ],
      };

      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: 'pipeline-1',
        autoPipeline: mockPipeline,
        autoPipelineMode: 'SKIP_EXISTING' as const,
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      // Should still filter by pipelineId: null in SKIP_EXISTING mode
      expect(whereClause.pipelineId).toBe(null);
    });
  });

  describe('Test: Returns all contacts in force update mode', () => {
    it('should return all contacts when forceUpdateExisting is true', async () => {
      const mockPipeline = {
        id: 'pipeline-1',
        name: 'Sales Pipeline',
        stages: [
          { id: 'stage-1', order: 0, leadScoreMin: 0, leadScoreMax: 50 },
          { id: 'stage-2', order: 1, leadScoreMin: 51, leadScoreMax: 100 },
        ],
      };

      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: 'pipeline-1',
        autoPipeline: mockPipeline,
        autoPipelineMode: 'SKIP_EXISTING' as const, // Even if mode is SKIP_EXISTING
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);
      // Mock empty contacts to trigger early return (we just need to verify the whereClause)
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      // Call with forceUpdateExisting = true
      await executePipelineAnalysis(mockJobId, mockFacebookPageId, true);

      // Verify contact.findMany was called
      expect(mockedPrisma.contact.findMany).toHaveBeenCalled();

      // Verify the whereClause does NOT include pipelineId filter
      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      expect(whereClause).toMatchObject({
        facebookPageId: mockFacebookPageId,
        OR: [
          { messengerPSID: { not: null } },
          { instagramSID: { not: null } },
        ],
      });

      // Verify pipelineId is NOT in the whereClause (should return all contacts)
      expect(whereClause.pipelineId).toBeUndefined();
    });

    it('should return all contacts when mode is UPDATE_EXISTING', async () => {
      const mockPipeline = {
        id: 'pipeline-1',
        name: 'Sales Pipeline',
        stages: [
          { id: 'stage-1', order: 0, leadScoreMin: 0, leadScoreMax: 100 },
        ],
      };

      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: 'pipeline-1',
        autoPipeline: mockPipeline,
        autoPipelineMode: 'UPDATE_EXISTING' as const, // Mode is UPDATE_EXISTING
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);
      // Mock empty contacts to trigger early return (we just need to verify the whereClause)
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      // Should NOT filter by pipelineId in UPDATE_EXISTING mode
      expect(whereClause.pipelineId).toBeUndefined();
    });

    it('should override SKIP_EXISTING mode when forceUpdateExisting is true', async () => {
      const mockPipeline = {
        id: 'pipeline-1',
        name: 'Sales Pipeline',
        stages: [
          { id: 'stage-1', order: 0, leadScoreMin: 0, leadScoreMax: 100 },
        ],
      };

      const mockPage = {
        id: mockFacebookPageId,
        pageId: 'fb-page-123',
        pageAccessToken: 'token-123',
        autoPipelineId: 'pipeline-1',
        autoPipeline: mockPipeline,
        autoPipelineMode: 'SKIP_EXISTING' as const, // Page mode is SKIP_EXISTING
        organizationId: mockOrganizationId,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockPage as any);
      mockedPrisma.contact.findMany.mockResolvedValue([] as any);

      // Mock syncJob.update for early return
      mockedPrisma.syncJob.update
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'IN_PROGRESS',
          startedAt: new Date(),
        } as any)
        .mockResolvedValueOnce({
          id: mockJobId,
          status: 'COMPLETED',
          totalContacts: 0,
          syncedContacts: 0,
          failedContacts: 0,
          completedAt: new Date(),
        } as any);

      // Force update should override the page's SKIP_EXISTING mode
      await executePipelineAnalysis(mockJobId, mockFacebookPageId, true);

      const findManyCall = mockedPrisma.contact.findMany.mock.calls[0];
      const whereClause = findManyCall[0].where;

      // Should NOT filter by pipelineId when forceUpdateExisting is true
      expect(whereClause.pipelineId).toBeUndefined();
    });
  });
});

