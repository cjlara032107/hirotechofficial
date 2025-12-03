/**
 * Tests for leadScore clamping in auto-assign.ts
 * 
 * Tests cover:
 * - leadScore is clamped to 0-100 range
 * - Negative scores are clamped to 0
 * - Scores over 100 are clamped to 100
 * - Null/undefined scores default to 0
 * - Clamped score is used in all operations (update, activity log, etc.)
 */

import { autoAssignContactToPipeline } from '../auto-assign';
import { prisma } from '@/lib/db';
import { AIContactAnalysis } from '@/lib/ai/google-ai-service';
import { findBestMatchingStage, shouldPreventDowngrade } from '../stage-analyzer';

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
      const mockTx = {
        contact: {
          update: jest.fn(),
        },
        contactActivity: {
          create: jest.fn(),
        },
      };
      return callback(mockTx);
    }),
  },
}));

jest.mock('../stage-analyzer', () => ({
  findBestMatchingStage: jest.fn(),
  shouldPreventDowngrade: jest.fn(),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedFindBestMatchingStage = findBestMatchingStage as jest.MockedFunction<typeof findBestMatchingStage>;
const mockedShouldPreventDowngrade = shouldPreventDowngrade as jest.MockedFunction<typeof shouldPreventDowngrade>;

describe('LeadScore Clamping in Auto-Assign', () => {
  const mockContactId = 'contact-123';
  const mockPipelineId = 'pipeline-456';
  const mockStageId = 'stage-789';

  const mockContact = {
    id: mockContactId,
    pipelineId: null,
    stageId: null,
    leadScore: 50,
    stage: null,
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

  beforeEach(() => {
    jest.clearAllMocks();
    mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
    mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
    mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
    mockedShouldPreventDowngrade.mockReturnValue(false);
  });

  describe('Clamping negative scores to 0', () => {
    it('should clamp negative leadScore to 0', async () => {
      const negativeScoreAnalysis: AIContactAnalysis = {
        summary: 'Test',
        recommendedStage: 'Qualified',
        leadScore: -10,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      let contactUpdateData: any = null;
      let activityLogData: any = null;

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async (args: any) => {
              contactUpdateData = args.data;
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockImplementation(async (args: any) => {
              activityLogData = args.data;
              return {};
            }),
          },
        };
        return await callback(mockTx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: negativeScoreAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should be clamped to 0
      expect(contactUpdateData.leadScore).toBe(0);
      expect(activityLogData.metadata.leadScore).toBe(0);
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        0, // Clamped score
        negativeScoreAnalysis.leadStatus
      );
    });
  });

  describe('Clamping scores over 100 to 100', () => {
    it('should clamp leadScore over 100 to 100', async () => {
      const highScoreAnalysis: AIContactAnalysis = {
        summary: 'Test',
        recommendedStage: 'Qualified',
        leadScore: 150,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      let contactUpdateData: any = null;
      let activityLogData: any = null;

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async (args: any) => {
              contactUpdateData = args.data;
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockImplementation(async (args: any) => {
              activityLogData = args.data;
              return {};
            }),
          },
        };
        return await callback(mockTx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: highScoreAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should be clamped to 100
      expect(contactUpdateData.leadScore).toBe(100);
      expect(activityLogData.metadata.leadScore).toBe(100);
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        100, // Clamped score
        highScoreAnalysis.leadStatus
      );
    });
  });

  describe('Handling null/undefined scores', () => {
    it('should default null leadScore to 0', async () => {
      const nullScoreAnalysis: AIContactAnalysis = {
        summary: 'Test',
        recommendedStage: 'Qualified',
        leadScore: null as any,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      let contactUpdateData: any = null;

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async (args: any) => {
              contactUpdateData = args.data;
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return await callback(mockTx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: nullScoreAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should default to 0
      expect(contactUpdateData.leadScore).toBe(0);
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        0,
        nullScoreAnalysis.leadStatus
      );
    });

    it('should default undefined leadScore to 0', async () => {
      const undefinedScoreAnalysis: AIContactAnalysis = {
        summary: 'Test',
        recommendedStage: 'Qualified',
        leadScore: undefined as any,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      let contactUpdateData: any = null;

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async (args: any) => {
              contactUpdateData = args.data;
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return await callback(mockTx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: undefinedScoreAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Should default to 0
      expect(contactUpdateData.leadScore).toBe(0);
    });
  });

  describe('Valid scores remain unchanged', () => {
    it('should keep valid scores (0-100) unchanged', async () => {
      const validScores = [0, 50, 100];

      for (const score of validScores) {
        jest.clearAllMocks();
        mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
        mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
        mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
        mockedShouldPreventDowngrade.mockReturnValue(false);

        const validScoreAnalysis: AIContactAnalysis = {
          summary: 'Test',
          recommendedStage: 'Qualified',
          leadScore: score,
          leadStatus: 'QUALIFIED',
          confidence: 85,
          reasoning: 'Test',
        };

        let contactUpdateData: any = null;

        (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
          const mockTx = {
            contact: {
              update: jest.fn().mockImplementation(async (args: any) => {
                contactUpdateData = args.data;
                return {};
              }),
            },
            contactActivity: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return await callback(mockTx);
        });

        await autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: validScoreAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        });

        // Should remain unchanged
        expect(contactUpdateData.leadScore).toBe(score);
        expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
          mockPipelineId,
          score,
          validScoreAnalysis.leadStatus
        );
      }
    });
  });

  describe('Clamped score used in all operations', () => {
    it('should use clamped score in contact update, activity log, and stage matching', async () => {
      const outOfRangeAnalysis: AIContactAnalysis = {
        summary: 'Test',
        recommendedStage: 'Qualified',
        leadScore: 250, // Will be clamped to 100
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      let contactUpdateData: any = null;
      let activityLogData: any = null;

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async (args: any) => {
              contactUpdateData = args.data;
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockImplementation(async (args: any) => {
              activityLogData = args.data;
              return {};
            }),
          },
        };
        return await callback(mockTx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: outOfRangeAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      const expectedClampedScore = 100;

      // All operations should use clamped score
      expect(contactUpdateData.leadScore).toBe(expectedClampedScore);
      expect(activityLogData.metadata.leadScore).toBe(expectedClampedScore);
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        expectedClampedScore,
        outOfRangeAnalysis.leadStatus
      );
      // shouldPreventDowngrade is only called when contact has an existing stage
      // If contact has no stage, it won't be called
      if (mockContact.stage) {
        expect(mockedShouldPreventDowngrade).toHaveBeenCalledWith(
          expect.any(Number),
          expect.any(Number),
          expect.any(Number),
          expectedClampedScore, // Clamped score
          expect.any(Number)
        );
      }
    });
  });
});

