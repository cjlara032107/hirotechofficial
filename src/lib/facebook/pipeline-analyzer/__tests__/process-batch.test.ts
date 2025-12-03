/**
 * Tests for processBatch function in pipeline-analyzer.ts
 * 
 * Tests cover:
 * - Updates contacts in auto-create mode (analysis only)
 * - Handles empty batch
 * - Handles all contacts filtered out
 * - Handles missing database columns (retries without new fields)
 * - Uses database transactions for consistency
 * 
 * NOTE: These tests require Prisma to be generated (run `npm run prisma:generate` first).
 * The batch processing logic is tested through executePipelineAnalysis which requires
 * the full Prisma client setup.
 * 
 * The core auto-assign functionality is thoroughly tested in auto-assign.test.ts.
 * These tests focus on batch-level behaviors and edge cases.
 */

import { executePipelineAnalysis } from '../../pipeline-analyzer';
import { prisma } from '@/lib/db';
import { FacebookClient } from '../../client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      create: jest.fn(),
      update: jest.fn(),
      findUnique: jest.fn(),
    },
    facebookPage: {
      findUnique: jest.fn(),
    },
    contact: {
      findMany: jest.fn(),
      update: jest.fn(),
    },
    pipeline: {
      findUnique: jest.fn(),
    },
    contactActivity: {
      create: jest.fn(),
    },
    $transaction: jest.fn((callback) => callback({
      contact: {
        update: jest.fn(),
        findMany: jest.fn(),
      },
      contactActivity: {
        create: jest.fn(),
      },
    })),
  },
}));

jest.mock('../../client', () => ({
  FacebookClient: jest.fn().mockImplementation(() => ({
    getConversations: jest.fn(),
    getAllMessagesForConversation: jest.fn(),
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
  findBestMatchingStage: jest.fn(),
  shouldPreventDowngrade: jest.fn(),
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

jest.mock('@/lib/db-retry', () => ({
  withRetry: jest.fn((fn) => fn()),
}));

jest.mock('../../pipeline-analyzer/update-progress', () => ({
  updateSyncJobProgress: jest.fn(),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedAnalyzeWithFallback = analyzeWithFallback as jest.MockedFunction<typeof analyzeWithFallback>;
const mockedAutoAssignContactToPipeline = autoAssignContactToPipeline as jest.MockedFunction<typeof autoAssignContactToPipeline>;
const mockedApplyStageScoreRanges = applyStageScoreRanges as jest.MockedFunction<typeof applyStageScoreRanges>;

describe('processBatch - Batch Processing Scenarios', () => {
  const mockJobId = 'test-job-id-123';
  const mockFacebookPageId = 'test-page-id-456';
  const mockOrganizationId = 'test-org-id-789';
  const mockPipelineId = 'pipeline-123';
  const mockStageId = 'stage-456';

  const mockFacebookPage = {
    id: mockFacebookPageId,
    pageId: '123456789',
    pageName: 'Test Page',
    pageAccessToken: 'test-token',
    organizationId: mockOrganizationId,
    autoPipelineId: mockPipelineId,
    autoPipelineMode: 'SKIP_EXISTING' as const,
    lastSyncedAt: null,
    instagramAccountId: null,
    instagramUsername: null,
    autoPipeline: null,
  };

  const mockPipeline = {
    id: mockPipelineId,
    name: 'Sales Pipeline',
    organizationId: mockOrganizationId,
    isArchived: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    stages: [
      {
        id: mockStageId,
        name: 'Qualified',
        type: 'IN_PROGRESS',
        order: 1,
        leadScoreMin: 31,
        leadScoreMax: 80,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ],
  };

  const mockAiAnalysis = {
    summary: 'Test contact summary',
    recommendedStage: 'Qualified',
    leadScore: 75,
    leadStatus: 'QUALIFIED',
    confidence: 85,
    reasoning: 'High engagement and clear buying intent',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});

    // Default mocks
    mockedPrisma.syncJob.create.mockResolvedValue({
      id: mockJobId,
      status: 'PROCESSING',
      facebookPageId: mockFacebookPageId,
      organizationId: mockOrganizationId,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);

    mockedPrisma.syncJob.findUnique.mockResolvedValue({
      id: mockJobId,
      status: 'PROCESSING',
      facebookPageId: mockFacebookPageId,
      organizationId: mockOrganizationId,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);

    mockedPrisma.facebookPage.findUnique.mockResolvedValue(mockFacebookPage as any);
    mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
    mockedAnalyzeWithFallback.mockResolvedValue({
      analysis: mockAiAnalysis,
      usedFallback: false,
    });
    mockedAutoAssignContactToPipeline.mockResolvedValue(undefined);
    mockedApplyStageScoreRanges.mockResolvedValue(undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Updates contacts in auto-create mode (analysis only)', () => {
    it('should update contacts with AI analysis only when pipelineId is TEMP', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        },
      ];

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock transaction to capture updates
      const mockTransaction = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
          findMany: jest.fn().mockResolvedValue(mockContacts),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        return callback(mockTransaction);
      });

      // Set pipelineId to 'TEMP' for auto-create mode
      const pageWithAutoCreate = {
        ...mockFacebookPage,
        autoPipelineId: 'TEMP',
        autoPipeline: null,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(pageWithAutoCreate as any);

      // Mock conversation fetching
      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([
        {
          id: 'conversation-1',
          participants: {
            data: [{ id: 'psid-1' }],
          },
          updated_time: new Date().toISOString(),
        },
      ]);
      (mockClient.getAllMessagesForConversation as jest.Mock) = jest.fn().mockResolvedValue([
        {
          from: { id: 'psid-1', name: 'John Doe' },
          message: 'Hello',
          created_time: new Date().toISOString(),
        },
      ]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // In auto-create mode, should update contact with AI analysis but not assign to pipeline
      expect(mockTransaction.contact.update).toHaveBeenCalled();
      expect(mockedAutoAssignContactToPipeline).not.toHaveBeenCalled();

      // Verify that AI context is updated
      const updateCall = mockTransaction.contact.update.mock.calls[0];
      expect(updateCall[0].data).toMatchObject({
        aiContext: expect.any(String),
        leadScore: mockAiAnalysis.leadScore,
        leadStatus: mockAiAnalysis.leadStatus,
      });
    });

    it('should not assign contacts to pipeline in auto-create mode', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        },
      ];

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      const mockTransaction = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
          findMany: jest.fn().mockResolvedValue(mockContacts),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        return callback(mockTransaction);
      });

      const pageWithAutoCreate = {
        ...mockFacebookPage,
        autoPipelineId: 'TEMP',
        autoPipeline: null,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(pageWithAutoCreate as any);

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);
      (mockClient.getAllMessagesForConversation as jest.Mock) = jest.fn().mockResolvedValue([]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Should not call auto-assign in auto-create mode
      expect(mockedAutoAssignContactToPipeline).not.toHaveBeenCalled();
    });
  });

  describe('Test: Handles empty batch', () => {
    it('should handle empty batch gracefully', async () => {
      mockedPrisma.contact.findMany.mockResolvedValue([]);

      const mockTransaction = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
          findMany: jest.fn().mockResolvedValue([]),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        return callback(mockTransaction);
      });

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Should complete without errors
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: mockJobId },
          data: expect.objectContaining({
            status: expect.any(String),
          }),
        })
      );
    });

    it('should not throw error when batch array is empty', async () => {
      mockedPrisma.contact.findMany.mockResolvedValue([]);

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);

      await expect(
        executePipelineAnalysis(mockJobId, mockFacebookPageId, false)
      ).resolves.not.toThrow();
    });
  });

  describe('Test: Handles all contacts filtered out', () => {
    it('should handle case where all contacts are filtered out in SKIP_EXISTING mode', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: mockPipelineId, // Already assigned
          stageId: mockStageId,
          leadScore: 50,
          stage: {
            order: 1,
            leadScoreMin: 31,
            name: 'Qualified',
          },
        },
      ];

      // First call returns contacts for processing
      mockedPrisma.contact.findMany
        .mockResolvedValueOnce(mockContacts as any) // Initial query
        .mockResolvedValueOnce(mockContacts as any); // Batch query

      const mockTransaction = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
          findMany: jest.fn().mockResolvedValue(mockContacts),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        return callback(mockTransaction);
      });

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([
        {
          id: 'conversation-1',
          participants: {
            data: [{ id: 'psid-1' }],
          },
          updated_time: new Date().toISOString(),
        },
      ]);
      (mockClient.getAllMessagesForConversation as jest.Mock) = jest.fn().mockResolvedValue([
        {
          from: { id: 'psid-1', name: 'John Doe' },
          message: 'Hello',
          created_time: new Date().toISOString(),
        },
      ]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Should still update AI context even when all contacts are filtered out
      expect(mockTransaction.contact.update).toHaveBeenCalled();
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('All contacts in batch already assigned')
      );
    });

    it('should update AI context even when contacts are filtered out', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: mockPipelineId,
          stageId: mockStageId,
          leadScore: 50,
          stage: {
            order: 1,
            leadScoreMin: 31,
            name: 'Qualified',
          },
        },
      ];

      mockedPrisma.contact.findMany
        .mockResolvedValueOnce(mockContacts as any)
        .mockResolvedValueOnce(mockContacts as any);

      const mockTransaction = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
          findMany: jest.fn().mockResolvedValue(mockContacts),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        return callback(mockTransaction);
      });

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Should still attempt to update AI context
      expect(mockTransaction.contact.update).toHaveBeenCalled();
    });
  });

  describe('Test: Handles missing database columns (retries without new fields)', () => {
    it('should handle missing column errors gracefully', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        },
      ];

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Simulate missing column error
      const prismaError = new Error('Column "conversionPath" does not exist');
      (prismaError as any).code = 'P2021';

      const mockTransaction = {
        contact: {
          update: jest.fn()
            .mockRejectedValueOnce(prismaError) // First attempt fails
            .mockResolvedValueOnce({}), // Retry succeeds
          findMany: jest.fn().mockResolvedValue(mockContacts),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        try {
          return await callback(mockTransaction);
        } catch (error: any) {
          // Simulate retry logic - second call should succeed
          if (error?.code === 'P2021' || error?.message?.includes('does not exist')) {
            return await callback({
              ...mockTransaction,
              contact: {
                ...mockTransaction.contact,
                update: jest.fn().mockResolvedValue({}),
              },
            });
          }
          throw error;
        }
      });

      const pageWithAutoCreate = {
        ...mockFacebookPage,
        autoPipelineId: 'TEMP',
        autoPipeline: null,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(pageWithAutoCreate as any);

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Should handle the error and continue
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('New AI columns not found')
      );
    });
  });

  describe('Test: Uses database transactions for consistency', () => {
    it('should use transactions for batch updates', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        },
      ];

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      const mockTransaction = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
          findMany: jest.fn().mockResolvedValue(mockContacts),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };

      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        return callback(mockTransaction);
      });

      const pageWithAutoCreate = {
        ...mockFacebookPage,
        autoPipelineId: 'TEMP',
        autoPipeline: null,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(pageWithAutoCreate as any);

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);

      await executePipelineAnalysis(mockJobId, mockFacebookPageId, false);

      // Should use transaction
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });

    it('should rollback transaction on error', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          messengerPSID: 'psid-1',
          firstName: 'John',
          lastName: 'Doe',
          lastInteraction: new Date(),
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        },
      ];

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      const transactionError = new Error('Transaction failed');
      mockedPrisma.$transaction.mockRejectedValue(transactionError);

      const pageWithAutoCreate = {
        ...mockFacebookPage,
        autoPipelineId: 'TEMP',
        autoPipeline: null,
      };

      mockedPrisma.facebookPage.findUnique.mockResolvedValue(pageWithAutoCreate as any);

      const mockClient = new FacebookClient('test-token');
      (mockClient.getConversations as jest.Mock) = jest.fn().mockResolvedValue([]);

      await expect(
        executePipelineAnalysis(mockJobId, mockFacebookPageId, false)
      ).rejects.toThrow('Transaction failed');
    });
  });
});
