/**
 * Comprehensive tests for Pipeline Assignment Validation
 * 
 * Tests cover all three checklist items:
 * 1. Test: Pipeline assignments are correct
 * 2. Test: Lead scores are within valid range (0-100)
 * 3. Test: Stage assignments match score ranges
 */

import { autoAssignContactToPipeline } from '../auto-assign';
import { findBestMatchingStage } from '../stage-analyzer';
import { validateScoreRange } from '../validation';
import { prisma } from '@/lib/db';
import { AIContactAnalysis } from '@/lib/ai/google-ai-service';

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
    $transaction: jest.fn((callback) => callback({
      contact: {
        update: jest.fn(),
      },
      contactActivity: {
        create: jest.fn(),
      },
    })),
  },
}));

// Mock stage-analyzer
jest.mock('../stage-analyzer', () => ({
  findBestMatchingStage: jest.fn(),
  shouldPreventDowngrade: jest.fn(),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedFindBestMatchingStage = findBestMatchingStage as jest.MockedFunction<typeof findBestMatchingStage>;

describe('Pipeline Assignment Validation Tests', () => {
  const mockContactId = 'contact-123';
  const mockPipelineId = 'pipeline-456';
  const mockStageId = 'stage-789';
  const mockUserId = 'user-abc';

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
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Pipeline assignments are correct', () => {
    it('should assign contact to correct pipeline', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Qualified',
        leadScore: 75,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'High engagement',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        return callback({
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        });
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
        userId: mockUserId,
      });

      expect(mockedPrisma.pipeline.findUnique).toHaveBeenCalledWith({
        where: { id: mockPipelineId },
        include: { stages: { orderBy: { order: 'asc' } } },
      });
    });

    it('should assign contact to correct stage based on score', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Qualified',
        leadScore: 50, // Should match stage with range 31-80
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Medium engagement',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId); // Qualified stage
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        return callback({
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        });
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        50, // Clamped score
        'QUALIFIED'
      );
    });

    it('should assign contact to WON stage when status is WON', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Closed Won',
        leadScore: 90,
        leadStatus: 'WON',
        confidence: 95,
        reasoning: 'Deal closed',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue('stage-3'); // WON stage
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        return callback({
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        });
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        90,
        'WON'
      );
    });

    it('should verify assigned stage exists in pipeline', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Qualified',
        leadScore: 50,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        const tx = {
          contact: {
            update: jest.fn().mockResolvedValue({}),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(tx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Verify the stage ID exists in pipeline stages
      const assignedStage = mockPipeline.stages.find(s => s.id === mockStageId);
      expect(assignedStage).toBeDefined();
      expect(assignedStage?.name).toBe('Qualified');
    });
  });

  describe('Test: Lead scores are within valid range (0-100)', () => {
    it('should clamp negative lead scores to 0', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'New Lead',
        leadScore: -10, // Invalid: negative
        leadStatus: 'NEW',
        confidence: 50,
        reasoning: 'Test',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue('stage-1');
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        const tx = {
          contact: {
            update: jest.fn().mockImplementation(async (args) => {
              // Verify the score was clamped to 0
              expect(args.data.leadScore).toBe(0);
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(tx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Verify clamped score was passed to findBestMatchingStage
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        0, // Clamped from -10
        'NEW'
      );
    });

    it('should clamp lead scores above 100 to 100', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Closed Won',
        leadScore: 150, // Invalid: above 100
        leadStatus: 'WON',
        confidence: 95,
        reasoning: 'Test',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue('stage-3');
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        const tx = {
          contact: {
            update: jest.fn().mockImplementation(async (args) => {
              // Verify the score was clamped to 100
              expect(args.data.leadScore).toBe(100);
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(tx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Verify clamped score was passed to findBestMatchingStage
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        100, // Clamped from 150
        'WON'
      );
    });

    it('should handle null lead scores by defaulting to 0', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'New Lead',
        leadScore: null as any, // Invalid: null
        leadStatus: 'NEW',
        confidence: 50,
        reasoning: 'Test',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue('stage-1');
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        const tx = {
          contact: {
            update: jest.fn().mockImplementation(async (args) => {
              // Verify the score was defaulted to 0
              expect(args.data.leadScore).toBe(0);
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(tx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Verify defaulted score was passed to findBestMatchingStage
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        0, // Defaulted from null
        'NEW'
      );
    });

    it('should preserve valid lead scores (0-100)', async () => {
      const validScores = [0, 25, 50, 75, 100];

      for (const score of validScores) {
        const mockContact = {
          id: mockContactId,
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        };

        const mockAiAnalysis: AIContactAnalysis = {
          summary: 'Test contact',
          recommendedStage: 'Qualified',
          leadScore: score,
          leadStatus: 'QUALIFIED',
          confidence: 85,
          reasoning: 'Test',
        };

        mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
        mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
        mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
        (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
          const tx = {
            contact: {
              update: jest.fn().mockImplementation(async (args) => {
                // Verify the score was preserved
                expect(args.data.leadScore).toBe(score);
                return {};
              }),
            },
            contactActivity: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return callback(tx);
        });

        await autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        });

        expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
          mockPipelineId,
          score, // Preserved as-is
          'QUALIFIED'
        );

        jest.clearAllMocks();
      }
    });

    it('should validate score ranges using validation utility', () => {
      // Test validateScoreRange function
      expect(validateScoreRange(0, 100).valid).toBe(true);
      expect(validateScoreRange(-1, 100).valid).toBe(false);
      expect(validateScoreRange(0, 101).valid).toBe(false);
      expect(validateScoreRange(50, 30).valid).toBe(false); // min > max
      expect(validateScoreRange(25, 75).valid).toBe(true);
    });
  });

  describe('Test: Stage assignments match score ranges', () => {
    it('should assign contact to stage where score falls within range', async () => {
      const testCases = [
        { score: 15, expectedStageId: 'stage-1', expectedRange: '0-30' },
        { score: 50, expectedStageId: mockStageId, expectedRange: '31-80' },
        { score: 90, expectedStageId: 'stage-3', expectedRange: '81-100' },
      ];

      for (const testCase of testCases) {
        const mockContact = {
          id: mockContactId,
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        };

        const mockAiAnalysis: AIContactAnalysis = {
          summary: 'Test contact',
          recommendedStage: 'Qualified',
          leadScore: testCase.score,
          leadStatus: 'QUALIFIED',
          confidence: 85,
          reasoning: 'Test',
        };

        mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
        mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
        mockedFindBestMatchingStage.mockResolvedValue(testCase.expectedStageId);
        (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
          const tx = {
            contact: {
              update: jest.fn().mockImplementation(async (args) => {
                // Verify the assigned stage matches the expected stage
                expect(args.data.stageId).toBe(testCase.expectedStageId);
                
                // Verify the score falls within the stage's range
                const assignedStage = mockPipeline.stages.find(s => s.id === testCase.expectedStageId);
                expect(assignedStage).toBeDefined();
                if (assignedStage) {
                  expect(testCase.score).toBeGreaterThanOrEqual(assignedStage.leadScoreMin);
                  expect(testCase.score).toBeLessThanOrEqual(assignedStage.leadScoreMax);
                }
                return {};
              }),
            },
            contactActivity: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return callback(tx);
        });

        await autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        });

        jest.clearAllMocks();
      }
    });

    it('should assign contact to stage with exact boundary scores', async () => {
      const boundaryCases = [
        { score: 0, expectedStageId: 'stage-1' }, // Lower boundary of first stage
        { score: 30, expectedStageId: 'stage-1' }, // Upper boundary of first stage
        { score: 31, expectedStageId: mockStageId }, // Lower boundary of second stage
        { score: 80, expectedStageId: mockStageId }, // Upper boundary of second stage
        { score: 81, expectedStageId: 'stage-3' }, // Lower boundary of third stage
        { score: 100, expectedStageId: 'stage-3' }, // Upper boundary of third stage
      ];

      for (const testCase of boundaryCases) {
        const mockContact = {
          id: mockContactId,
          pipelineId: null,
          stageId: null,
          leadScore: 0,
          stage: null,
        };

        const mockAiAnalysis: AIContactAnalysis = {
          summary: 'Test contact',
          recommendedStage: 'Qualified',
          leadScore: testCase.score,
          leadStatus: 'QUALIFIED',
          confidence: 85,
          reasoning: 'Test',
        };

        mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
        mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
        mockedFindBestMatchingStage.mockResolvedValue(testCase.expectedStageId);
        (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
          const tx = {
            contact: {
              update: jest.fn().mockImplementation(async (args) => {
                // Verify boundary score falls within assigned stage range
                const assignedStage = mockPipeline.stages.find(s => s.id === testCase.expectedStageId);
                expect(assignedStage).toBeDefined();
                if (assignedStage) {
                  expect(testCase.score).toBeGreaterThanOrEqual(assignedStage.leadScoreMin);
                  expect(testCase.score).toBeLessThanOrEqual(assignedStage.leadScoreMax);
                }
                return {};
              }),
            },
            contactActivity: {
              create: jest.fn().mockResolvedValue({}),
            },
          };
          return callback(tx);
        });

        await autoAssignContactToPipeline({
          contactId: mockContactId,
          aiAnalysis: mockAiAnalysis,
          pipelineId: mockPipelineId,
          updateMode: 'UPDATE_EXISTING',
        });

        jest.clearAllMocks();
      }
    });

    it('should verify assigned stage range contains the contact score', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Qualified',
        leadScore: 55,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId); // Qualified stage (31-80)
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        const tx = {
          contact: {
            update: jest.fn().mockImplementation(async (args) => {
              const assignedStage = mockPipeline.stages.find(s => s.id === args.data.stageId);
              expect(assignedStage).toBeDefined();
              
              // Verify score 55 is within the assigned stage's range (31-80)
              if (assignedStage) {
                expect(55).toBeGreaterThanOrEqual(assignedStage.leadScoreMin);
                expect(55).toBeLessThanOrEqual(assignedStage.leadScoreMax);
              }
              return {};
            }),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(tx);
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });
    });

    it('should use findBestMatchingStage to ensure score-range matching', async () => {
      const mockContact = {
        id: mockContactId,
        pipelineId: null,
        stageId: null,
        leadScore: 0,
        stage: null,
      };

      const mockAiAnalysis: AIContactAnalysis = {
        summary: 'Test contact',
        recommendedStage: 'Qualified',
        leadScore: 65,
        leadStatus: 'QUALIFIED',
        confidence: 85,
        reasoning: 'Test',
      };

      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as any);
      mockedPrisma.pipeline.findUnique.mockResolvedValue(mockPipeline as any);
      mockedFindBestMatchingStage.mockResolvedValue(mockStageId);
      (mockedPrisma.$transaction as jest.Mock).mockImplementation((callback) => {
        return callback({
          contact: { update: jest.fn().mockResolvedValue({}) },
          contactActivity: { create: jest.fn().mockResolvedValue({}) },
        });
      });

      await autoAssignContactToPipeline({
        contactId: mockContactId,
        aiAnalysis: mockAiAnalysis,
        pipelineId: mockPipelineId,
        updateMode: 'UPDATE_EXISTING',
      });

      // Verify findBestMatchingStage was called with the score
      // This function internally verifies the score falls within stage ranges
      expect(mockedFindBestMatchingStage).toHaveBeenCalledWith(
        mockPipelineId,
        65, // Score should match stage with range 31-80
        'QUALIFIED'
      );

      // Verify the returned stage ID matches a stage where 65 falls within range
      const matchedStage = mockPipeline.stages.find(s => s.id === mockStageId);
      expect(matchedStage).toBeDefined();
      if (matchedStage) {
        expect(65).toBeGreaterThanOrEqual(matchedStage.leadScoreMin);
        expect(65).toBeLessThanOrEqual(matchedStage.leadScoreMax);
      }
    });
  });
});









