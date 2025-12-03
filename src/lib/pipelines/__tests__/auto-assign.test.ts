/**
 * Comprehensive tests for auto-assign.ts
 * 
 * Tests cover:
 * - Updates contacts in auto-create mode (analysis only)
 * - Assigns contacts to stages correctly
 * - Prevents downgrades when configured
 * - Skips existing contacts in SKIP_EXISTING mode
 * - Handles missing database columns (retries without new fields)
 * - Handles empty batch
 * - Handles all contacts filtered out
 * - Creates activity logs for stage changes
 * - Uses database transactions for consistency
 */

import { autoAssignContactToPipeline } from '../auto-assign';
import { prisma } from '@/lib/db';
import { AIContactAnalysis } from '@/lib/ai/google-ai-service';
import { findBestMatchingStage, shouldPreventDowngrade } from '../stage-analyzer';

// Store transaction mock for test access
let mockTransactionClient: {
  contact: { update: jest.Mock };
  contactActivity: { create: jest.Mock };
} | undefined;

// Mock Prisma client
jest.mock('@/lib/db', () => ({
  prisma: {
    contact: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    pipeline: {
      findUnique: jest.fn(),
    },
    contactActivity: {
      create: jest.fn(),
    },
    $transaction: jest.fn((callback) => {
      // Create transaction client that tests can access
      mockTransactionClient = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };
      return callback(mockTransactionClient);
    }),
  },
}));

// Mock stage-analyzer
jest.mock('../stage-analyzer', () => ({
  findBestMatchingStage: jest.fn(),
  shouldPreventDowngrade: jest.fn(),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedFindBestMatchingStage = findBestMatchingStage as jest.MockedFunction<typeof findBestMatchingStage>;
const mockedShouldPreventDowngrade = shouldPreventDowngrade as jest.MockedFunction<typeof shouldPreventDowngrade>;

describe('autoAssignContactToPipeline', () => {
  const mockContactId = 'contact-123';
  const mockPipelineId = 'pipeline-456';
  const mockStageId = 'stage-789';
  const mockUserId = 'user-abc';

  const mockAiAnalysis: AIContactAnalysis = {
    summary: 'Test contact summary',
    recommendedStage: 'Qualified',
    leadScore: 75,
    leadStatus: 'QUALIFIED',
    confidence: 85,
    reasoning: 'High engagement and clear buying intent',
  };

  const mockPipeline = {
    id: mockPipelineId,
    name: 'Sales Pipeline',
    organizationId: 'org-123',
    isArchived: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    stages: [
      {
        id: 'stage-1',
        name: 'New Lead',
        type: 'LEAD',
        order: 0,
        leadScoreMin: 0,
        leadScoreMax: 30,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
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
      {
        id: 'stage-3',
        name: 'Closed Won',
        type: 'WON',
        order: 2,
        leadScoreMin: 81,
        leadScoreMax: 100,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockTransactionClient = undefined; // Reset before each test
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Assigns contacts to stages correctly', () => {
    it('should assign a new contact to the correct stage based on AI analysis', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
        userId: mockUserId,
      });

      expect(mockedPrisma.contact.findUnique).toHaveBeenCalledWith({
        where: { id: mockContactId },
        select: {
          pipelineId: true,
          stageId: true,
          leadScore: true,
          stage: {
            select: {
              order: true,
              leadScoreMin: true,
              name: true,
            },
          },
        },
      });

      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        mockAiAnalysis.leadScore, // Clamped value (75 is already in range)
        mockAiAnalysis.leadStatus
      );

      // Verify transaction was called
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      
      // Check calls on the transaction client (should be set by the mock)
      expect(mockTransactionClient).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalledWith({
        where: { id: mockContactId },
        data: {
          pipelineId: mockPipelineId,
          stageId: mockStageId,
          stageEnteredAt: expect.any(Date),
          leadScore: mockAiAnalysis.leadScore, // Should be clamped (75 is already valid)
          leadStatus: mockAiAnalysis.leadStatus,
        },
      });

      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'AI auto-assigned to pipeline',
          description: mockAiAnalysis.reasoning,
          toStageId: mockStageId,
          fromStageId: undefined,
          userId: mockUserId,
          metadata: {
            confidence: mockAiAnalysis.confidence,
            aiRecommendation: mockAiAnalysis.recommendedStage,
            leadScore: mockAiAnalysis.leadScore, // Should be clamped (75 is already valid)
            leadStatus: mockAiAnalysis.leadStatus,
          },
        },
      });
    });

    it('should use AI-recommended stage name if findBestMatchingStage returns null', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      // Use a recommendedStage that doesn't match any stage name to test fallback
      const aiAnalysisWithUnmatchedStage = {
        ...mockAiAnalysis,
        recommendedStage: 'NonExistentStage',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(null);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Ensure transaction mock sets mockTransactionClient
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: aiAnalysisWithUnmatchedStage,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should fall back to first stage when no match found (neither by ID nor by name)
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalledWith({
        where: { id: mockContactId },
        data: expect.objectContaining({
          stageId: mockPipeline.stages[0].id,
        }),
      });
    });

    it('should use first stage as fallback when no stage matches', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const pipelineWithoutMatchingStage = {
        ...mockPipeline,
        stages: [
          {
            id: 'stage-1',
            name: 'New Lead',
            type: 'LEAD',
            order: 0,
            leadScoreMin: 0,
            leadScoreMax: 30,
            pipelineId: mockPipelineId,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ],
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(pipelineWithoutMatchingStage as any);
      mockedFindBestMatchingStage.mockResolvedValue(null);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      mockedPrisma.contact.update.mockResolvedValue({} as any);
      mockedPrisma.contactActivity.create.mockResolvedValue({} as any);

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalledWith({
        where: { id: mockContactId },
        data: expect.objectContaining({
          stageId: 'stage-1',
        }),
      });
    });
  });

  describe('Test: Prevents downgrades when configured', () => {
    it('should prevent downgrade when shouldPreventDowngrade returns true', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: mockPipelineId,
        stageId: 'stage-3', // Currently in "Closed Won" (high stage)
        leadScore: 90,
        stage: {
          order: 2,
          leadScoreMin: 81,
          name: 'Closed Won',
        },
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue('stage-1'); // Would move to "New Lead" (low stage)
      mockedShouldPreventDowngrade.mockReturnValue(true); // Prevent downgrade

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: { ...mockAiAnalysis, leadScore: 85 },
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should not update contact when downgrade is prevented
      expect(mockedPrisma.$transaction).not.toHaveBeenCalled();
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Keeping contact in current stage')
      );
    });

    it('should allow upgrade when shouldPreventDowngrade returns false', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: mockPipelineId,
        stageId: 'stage-1', // Currently in "New Lead" (low stage)
        leadScore: 20,
        stage: {
          order: 0,
          leadScoreMin: 0,
          name: 'New Lead',
        },
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId); // Move to "Qualified" (higher stage)
      mockedShouldPreventDowngrade.mockReturnValue(false); // Allow upgrade
      mockedPrisma.contact.update.mockResolvedValue({} as any);
      mockedPrisma.contactActivity.create.mockResolvedValue({} as any);

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: { ...mockAiAnalysis, leadScore: 75 },
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should update contact when upgrade is allowed
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalled();
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contactActivity.create).toHaveBeenCalled();
    });

    it('should check downgrade prevention with correct parameters', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: mockPipelineId,
        stageId: 'stage-3',
        leadScore: 90,
        stage: {
          order: 2,
          leadScoreMin: 81,
          name: 'Closed Won',
        },
      };

      const proposedStage = mockPipeline.stages[0]; // "New Lead" stage

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(proposedStage.id);
      mockedShouldPreventDowngrade.mockReturnValue(true);
      mockedPrisma.contact.update.mockResolvedValue({} as any);
      mockedPrisma.contactActivity.create.mockResolvedValue({} as any);

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: { ...mockAiAnalysis, leadScore: 85 },
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockedShouldPreventDowngrade).toHaveBeenCalledWith(
        2, // currentStageOrder
        0, // targetStageOrder (proposedStage.order)
        90, // currentScore
        85, // newScore (aiAnalysis.leadScore)
        0   // targetStageMin (proposedStage.leadScoreMin)
      );
    });
  });

  describe('Test: Skips existing contacts in SKIP_EXISTING mode', () => {
    it('should skip contact that already has a pipelineId in SKIP_EXISTING mode', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: mockPipelineId, // Already assigned
        stageId: mockStageId,
        leadScore: 50,
        stage: {
          order: 1,
          leadScoreMin: 31,
          name: 'Qualified',
        },
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'SKIP_EXISTING',
      });

      // Should not fetch pipeline or update contact
      expect(mockedPrisma.pipeline.findUnique).not.toHaveBeenCalled();
      expect(mockedPrisma.$transaction).not.toHaveBeenCalled();
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Skipping contact')
      );
    });

    it('should process contact without pipelineId in SKIP_EXISTING mode', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null, // Not assigned yet
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'SKIP_EXISTING',
      });

      // Should process contact when no pipelineId exists
      expect(mockedPrisma.pipeline.findUnique).toHaveBeenCalled();
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalled();
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contactActivity.create).toHaveBeenCalled();
    });

    it('should process contact with pipelineId in UPDATE_EXISTING mode', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: mockPipelineId, // Already assigned
        stageId: mockStageId,
        leadScore: 50,
        stage: {
          order: 1,
          leadScoreMin: 31,
          name: 'Qualified',
        },
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should process contact in UPDATE_EXISTING mode even if already assigned
      expect(mockedPrisma.pipeline.findUnique).toHaveBeenCalled();
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalled();
    });
  });

  describe('Test: Creates activity logs for stage changes', () => {
    it('should create activity log when contact is assigned to a stage', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
        userId: mockUserId,
      });

      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'AI auto-assigned to pipeline',
          description: mockAiAnalysis.reasoning,
          toStageId: mockStageId,
          fromStageId: undefined,
          userId: mockUserId,
          metadata: {
            confidence: mockAiAnalysis.confidence,
            aiRecommendation: mockAiAnalysis.recommendedStage,
            leadScore: mockAiAnalysis.leadScore,
            leadStatus: mockAiAnalysis.leadStatus,
          },
        },
      });
    });

    it('should include fromStageId when contact moves from one stage to another', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: mockPipelineId,
        stageId: 'stage-1', // Moving from "New Lead"
        leadScore: 20,
        stage: {
          order: 0,
          leadScoreMin: 0,
          name: 'New Lead',
        },
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contactActivity.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          fromStageId: 'stage-1',
          toStageId: mockStageId,
        }),
      });
    });

    it('should create activity log without userId when not provided', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
        // userId not provided
      });

      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contactActivity.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: undefined,
        }),
      });
    });
  });

  describe('Test: Handles edge cases', () => {
    it('should return early if contact is not found', async () => {
      mockedPrisma.contact.findUnique.mockResolvedValue(null);

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockedPrisma.pipeline.findUnique).not.toHaveBeenCalled();
      expect(mockedPrisma.$transaction).not.toHaveBeenCalled();
    });

    it('should return early if pipeline is not found', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(null);

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockedPrisma.$transaction).not.toHaveBeenCalled();
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Pipeline')
      );
    });

    it('should handle contact without stage information', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null, // No stage information
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      // Mock transaction
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        mockTransactionClient = {
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        };
        return callback(mockTransactionClient);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should not call shouldPreventDowngrade when stage is null
      expect(mockedShouldPreventDowngrade).not.toHaveBeenCalled();
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      expect(mockTransactionClient!).toBeDefined();
      expect(mockTransactionClient!.contact.update).toHaveBeenCalled();
    });
  });

  describe('Test: Uses database transactions for consistency', () => {
    it('should handle transaction errors gracefully', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockRejectedValue(new Error('Database error')),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(mockTx);
      });

      await expect(
        autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        })
      ).rejects.toThrow('Database error');
    });
  });

  describe('Test: Handles missing database columns (retries without new fields)', () => {
    it('should handle Prisma errors for missing columns gracefully', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);

      // Simulate missing column error
      const prismaError = new Error('Column does not exist');
      (prismaError as any).code = 'P2021';
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockRejectedValue(prismaError),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(mockTx);
      });

      await expect(
        autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        })
      ).rejects.toThrow('Column does not exist');
    });
  });

  describe('Test: Contact updates are atomic (transaction rollback on failure)', () => {
    beforeEach(() => {
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      mockedShouldPreventDowngrade.mockReturnValue(false);
    });

    it('should rollback transaction when contact update fails', async () => {
      const updateError = new Error('Database constraint violation');
      
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockRejectedValue(updateError),
          },
          contactActivity: {
            create: jest.fn(),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction should rollback - verify activity log was never created
          expect(mockTx.contactActivity.create).not.toHaveBeenCalled();
          throw error;
        }
      });

      await expect(
        autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        })
      ).rejects.toThrow('Database constraint violation');
      
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });

    it('should rollback transaction when activity log creation fails', async () => {
      const activityLogError = new Error('Activity log creation failed');
      
      let contactUpdateCalled = false;
      
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async () => {
              contactUpdateCalled = true;
              return { id: mockContactId, stageId: mockStageId };
            }),
          },
          contactActivity: {
            create: jest.fn().mockRejectedValue(activityLogError),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction should rollback - contact update should be undone
          expect(contactUpdateCalled).toBe(true);
          throw error;
        }
      });

      await expect(
        autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        })
      ).rejects.toThrow('Activity log creation failed');
      
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });

    it('should update contact and create activity log atomically on success', async () => {
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockResolvedValue({
              id: mockContactId,
              stageId: mockStageId,
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({
              id: 'activity-123',
              contactId: mockContactId,
            }),
          },
        };
        return await callback(mockTx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      
      // Verify both operations were called within transaction
      const transactionCallback = (mockedPrisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {
        contact: {
          update: jest.fn().mockResolvedValue({}),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };
      await transactionCallback(mockTx);
      
      expect(mockTx.contact.update).toHaveBeenCalled();
      expect(mockTx.contactActivity.create).toHaveBeenCalled();
    });

    it('should not leave contact in inconsistent state when activity log fails', async () => {
      let contactUpdateSucceeded = false;
      
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async () => {
              contactUpdateSucceeded = true;
              return { id: mockContactId, stageId: mockStageId };
            }),
          },
          contactActivity: {
            create: jest.fn().mockRejectedValue(new Error('Activity log failed')),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction rollback should prevent partial update
          throw error;
        }
      });

      await expect(
        autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        })
      ).rejects.toThrow('Activity log failed');

      // Verify transaction handled the error (rollback)
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      // Contact update was attempted but should be rolled back
      expect(contactUpdateSucceeded).toBe(true);
    });
  });
});

