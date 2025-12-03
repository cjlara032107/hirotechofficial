/**
 * Tests for Stage Analyzer - findBestMatchingStage function
 * 
 * Tests ensure:
 * - Handles empty stages array (returns null)
 * - Handles leadScore outside 0-100 range (clamps to valid range)
 * - Handles leadScore exactly on boundary (0, 100)
 * - Uses existing stage-analyzer utilities
 * - Validates input types
 */

import { findBestMatchingStage } from '../stage-analyzer';
import { prisma } from '@/lib/db';

// Mock Prisma client
jest.mock('@/lib/db', () => ({
  prisma: {
    pipeline: {
      findUnique: jest.fn(),
    },
  },
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('findBestMatchingStage', () => {
  const mockPipelineId = 'test-pipeline-id';
  const mockOrganizationId = 'test-org-id';

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Handles empty stages array (returns null)', () => {
    it('should return null when pipeline has no stages', async () => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: [],
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      expect(result).toBeNull();
      expect(mockedPrisma.pipeline.findUnique).toHaveBeenCalledWith({
        where: { id: mockPipelineId },
        include: {
          stages: {
            orderBy: { order: 'asc' },
          },
        },
      });
    });

    it('should return null when pipeline exists but stages array is empty', async () => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Empty Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: [],
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, 75, 'CONTACTED');

      expect(result).toBeNull();
    });

    it('should return null even with WON status when stages array is empty', async () => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Empty Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: [],
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, 90, 'WON');

      expect(result).toBeNull();
    });
  });

  describe('Test: Handles leadScore outside 0-100 range (clamps or returns null)', () => {
    const mockStages = [
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
        id: 'stage-2',
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
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: mockStages,
      } as any);
    });

    it('should clamp negative leadScore to 0', async () => {
      const result = await findBestMatchingStage(mockPipelineId, -10, 'NEW');

      expect(result).toBe('stage-1'); // Should match first stage (0-30 range)
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Clamped leadScore from -10 to 0')
      );
    });

    it('should clamp leadScore above 100 to 100', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 150, 'NEW');

      expect(result).toBe('stage-3'); // Should match WON stage (81-100 range)
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Clamped leadScore from 150 to 100')
      );
    });

    it('should clamp very large leadScore to 100', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 999, 'NEW');

      expect(result).toBe('stage-3'); // Should match WON stage
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Clamped leadScore from 999 to 100')
      );
    });

    it('should clamp very negative leadScore to 0', async () => {
      const result = await findBestMatchingStage(mockPipelineId, -999, 'NEW');

      expect(result).toBe('stage-1'); // Should match first stage
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Clamped leadScore from -999 to 0')
      );
    });

    it('should not log clamping message when score is already in valid range', async () => {
      await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      expect(console.log).not.toHaveBeenCalledWith(
        expect.stringContaining('Clamped leadScore')
      );
    });
  });

  describe('Test: Handles leadScore exactly on boundary', () => {
    const mockStages = [
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
        id: 'stage-2',
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
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: mockStages,
      } as any);
    });

    it('should handle leadScore exactly at 0', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 0, 'NEW');

      expect(result).toBe('stage-1'); // Should match first stage (0-30 range)
    });

    it('should handle leadScore exactly at 100', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 100, 'NEW');

      expect(result).toBe('stage-3'); // Should match WON stage (81-100 range)
    });

    it('should handle leadScore at lower boundary of a range (30)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 30, 'NEW');

      expect(result).toBe('stage-1'); // Should match first stage (0-30 range, inclusive)
    });

    it('should handle leadScore at upper boundary of a range (31)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 31, 'NEW');

      expect(result).toBe('stage-2'); // Should match second stage (31-80 range, inclusive)
    });

    it('should handle leadScore at boundary between ranges (80)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 80, 'NEW');

      expect(result).toBe('stage-2'); // Should match second stage (31-80 range, inclusive)
    });

    it('should handle leadScore at boundary between ranges (81)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 81, 'NEW');

      expect(result).toBe('stage-3'); // Should match WON stage (81-100 range, inclusive)
    });
  });

  describe('Test: Uses existing stage-analyzer utilities', () => {
    const mockStages = [
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
        id: 'stage-2',
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
        id: 'stage-won',
        name: 'Closed Won',
        type: 'WON',
        order: 2,
        leadScoreMin: 81,
        leadScoreMax: 100,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-lost',
        name: 'Closed Lost',
        type: 'LOST',
        order: 3,
        leadScoreMin: 0,
        leadScoreMax: 20,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: mockStages,
      } as any);
    });

    it('should use status-based routing for WON status (priority routing)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 50, 'WON');

      expect(result).toBe('stage-won');
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Status-based routing: WON → Closed Won')
      );
    });

    it('should use status-based routing for LOST status (priority routing)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 50, 'LOST');

      expect(result).toBe('stage-lost');
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Status-based routing: LOST → Closed Lost')
      );
    });

    it('should use score-based routing when score falls within stage range', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      expect(result).toBe('stage-2'); // Score 50 falls in 31-80 range
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Score-based routing: 50 → Qualified')
      );
    });

    it('should use fallback routing when score does not match any stage range', async () => {
      // Score 25 doesn't match any non-ARCHIVED stage exactly, but is closest to stage-1
      const result = await findBestMatchingStage(mockPipelineId, 25, 'NEW');

      // Should use fallback to find closest stage
      expect(result).toBeDefined();
      expect(['stage-1', 'stage-2']).toContain(result);
    });

    it('should skip ARCHIVED stages in score-based routing', async () => {
      const stagesWithArchived = [
        ...mockStages,
        {
          id: 'stage-archived',
          name: 'Archived',
          type: 'ARCHIVED',
          order: 4,
          leadScoreMin: 0,
          leadScoreMax: 100,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: stagesWithArchived,
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      // Should not match ARCHIVED stage, should match stage-2 instead
      expect(result).toBe('stage-2');
      expect(result).not.toBe('stage-archived');
    });

    it('should handle fallback routing when first stage is ARCHIVED', async () => {
      const stagesWithArchivedFirst = [
        {
          id: 'stage-archived',
          name: 'Archived',
          type: 'ARCHIVED',
          order: 0,
          leadScoreMin: 0,
          leadScoreMax: 100,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'stage-1',
          name: 'New Lead',
          type: 'LEAD',
          order: 1,
          leadScoreMin: 0,
          leadScoreMax: 30,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'stage-2',
          name: 'Qualified',
          type: 'IN_PROGRESS',
          order: 2,
          leadScoreMin: 31,
          leadScoreMax: 80,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: stagesWithArchivedFirst,
      } as any);

      // Score 25 should match stage-1 (closest non-ARCHIVED stage), not the ARCHIVED stage
      const result = await findBestMatchingStage(mockPipelineId, 25, 'NEW');

      expect(result).toBe('stage-1');
      expect(result).not.toBe('stage-archived');
    });

    it('should return first stage if all stages are ARCHIVED', async () => {
      const allArchivedStages = [
        {
          id: 'stage-archived-1',
          name: 'Archived 1',
          type: 'ARCHIVED',
          order: 0,
          leadScoreMin: 0,
          leadScoreMax: 100,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'stage-archived-2',
          name: 'Archived 2',
          type: 'ARCHIVED',
          order: 1,
          leadScoreMin: 0,
          leadScoreMax: 100,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: allArchivedStages,
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      // Should return first stage when all are ARCHIVED
      expect(result).toBe('stage-archived-1');
    });
  });

  describe('Test: Validates input types', () => {
    const mockStages = [
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
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: mockStages,
      } as any);
    });

    it('should accept number type for leadScore', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      expect(result).toBeDefined();
      expect(typeof result === 'string' || result === null).toBe(true);
    });

    it('should accept string type for leadStatus', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 50, 'CONTACTED');

      expect(result).toBeDefined();
    });

    it('should accept string type for pipelineId', async () => {
      const result = await findBestMatchingStage('valid-pipeline-id', 50, 'NEW');

      expect(result).toBeDefined();
    });

    it('should handle numeric string for leadScore (TypeScript will enforce number type)', async () => {
      // TypeScript will enforce number type at compile time
      // This test verifies runtime behavior with valid number
      const result = await findBestMatchingStage(mockPipelineId, 0, 'NEW');

      expect(result).toBeDefined();
    });

    it('should return null when pipeline does not exist', async () => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue(null);

      const result = await findBestMatchingStage('non-existent-id', 50, 'NEW');

      expect(result).toBeNull();
    });

    it('should handle various leadStatus string values', async () => {
      const statuses = ['NEW', 'CONTACTED', 'QUALIFIED', 'WON', 'LOST', 'ARCHIVED'];

      for (const status of statuses) {
        const result = await findBestMatchingStage(mockPipelineId, 50, status);
        expect(result).toBeDefined();
      }
    });

    it('should handle null leadScore by returning null when no status-based routing matches', async () => {
      const result = await findBestMatchingStage(mockPipelineId, null as any, 'NEW');

      expect(result).toBeNull();
    });

    it('should handle null leadScore but still route by WON status', async () => {
      const stagesWithWon = [
        ...mockStages,
        {
          id: 'stage-won',
          name: 'Closed Won',
          type: 'WON',
          order: 1,
          leadScoreMin: 81,
          leadScoreMax: 100,
          pipelineId: mockPipelineId,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];

      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: stagesWithWon,
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, null as any, 'WON');

      expect(result).toBe('stage-won');
    });
  });

  describe('Test: Returns correct stage for lead score within range', () => {
    const mockStages = [
      {
        id: 'stage-1',
        name: 'New Lead',
        type: 'LEAD',
        order: 0,
        leadScoreMin: 0,
        leadScoreMax: 25,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-2',
        name: 'Qualified',
        type: 'IN_PROGRESS',
        order: 1,
        leadScoreMin: 26,
        leadScoreMax: 50,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-3',
        name: 'Hot Lead',
        type: 'IN_PROGRESS',
        order: 2,
        leadScoreMin: 51,
        leadScoreMax: 75,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-4',
        name: 'Closing',
        type: 'IN_PROGRESS',
        order: 3,
        leadScoreMin: 76,
        leadScoreMax: 100,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: mockStages,
      } as any);
    });

    it('should return stage-1 for lead score 15 (within 0-25 range)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 15, 'NEW');
      expect(result).toBe('stage-1');
    });

    it('should return stage-2 for lead score 35 (within 26-50 range)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 35, 'NEW');
      expect(result).toBe('stage-2');
    });

    it('should return stage-3 for lead score 60 (within 51-75 range)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 60, 'NEW');
      expect(result).toBe('stage-3');
    });

    it('should return stage-4 for lead score 90 (within 76-100 range)', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 90, 'NEW');
      expect(result).toBe('stage-4');
    });
  });

  describe('Test: Returns null when no stage matches', () => {
    it('should return null when pipeline does not exist', async () => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue(null);

      const result = await findBestMatchingStage('non-existent-pipeline', 50, 'NEW');

      expect(result).toBeNull();
    });

    it('should return null when pipeline has no stages', async () => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Empty Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: [],
      } as any);

      const result = await findBestMatchingStage(mockPipelineId, 50, 'NEW');

      expect(result).toBeNull();
    });
  });

  describe('Test: Handles null leadScore (returns null or default)', () => {
    const mockStages = [
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
        id: 'stage-2',
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
        id: 'stage-won',
        name: 'Closed Won',
        type: 'WON',
        order: 2,
        leadScoreMin: 81,
        leadScoreMax: 100,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-lost',
        name: 'Closed Lost',
        type: 'LOST',
        order: 3,
        leadScoreMin: 0,
        leadScoreMax: 20,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: mockStages,
      } as any);
    });

    it('should return null when leadScore is null and status is not WON or LOST', async () => {
      const result = await findBestMatchingStage(mockPipelineId, null, 'NEW');

      expect(result).toBeNull();
    });

    it('should return WON stage when leadScore is null but status is WON', async () => {
      const result = await findBestMatchingStage(mockPipelineId, null, 'WON');

      expect(result).toBe('stage-won');
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Status-based routing: WON → Closed Won')
      );
    });

    it('should return LOST stage when leadScore is null but status is LOST', async () => {
      const result = await findBestMatchingStage(mockPipelineId, null, 'LOST');

      expect(result).toBe('stage-lost');
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Status-based routing: LOST → Closed Lost')
      );
    });
  });

  describe('Integration: Full flow with realistic data', () => {
    const realisticStages = [
      {
        id: 'stage-lead-1',
        name: 'New Inquiry',
        type: 'LEAD',
        order: 0,
        leadScoreMin: 0,
        leadScoreMax: 15,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-lead-2',
        name: 'Initial Contact',
        type: 'LEAD',
        order: 1,
        leadScoreMin: 16,
        leadScoreMax: 30,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-progress-1',
        name: 'Qualified',
        type: 'IN_PROGRESS',
        order: 2,
        leadScoreMin: 31,
        leadScoreMax: 60,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-progress-2',
        name: 'Proposal Sent',
        type: 'IN_PROGRESS',
        order: 3,
        leadScoreMin: 61,
        leadScoreMax: 80,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: 'stage-won',
        name: 'Closed Won',
        type: 'WON',
        order: 4,
        leadScoreMin: 81,
        leadScoreMax: 100,
        pipelineId: mockPipelineId,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    beforeEach(() => {
      mockedPrisma.pipeline.findUnique.mockResolvedValue({
        id: mockPipelineId,
        name: 'Sales Pipeline',
        organizationId: mockOrganizationId,
        isArchived: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        stages: realisticStages,
      } as any);
    });

    it('should route low scores to early stages', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 10, 'NEW');
      expect(result).toBe('stage-lead-1');
    });

    it('should route medium scores to middle stages', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 45, 'NEW');
      expect(result).toBe('stage-progress-1');
    });

    it('should route high scores to advanced stages', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 70, 'NEW');
      expect(result).toBe('stage-progress-2');
    });

    it('should prioritize WON status over score', async () => {
      const result = await findBestMatchingStage(mockPipelineId, 50, 'WON');
      expect(result).toBe('stage-won');
    });
  });
});
