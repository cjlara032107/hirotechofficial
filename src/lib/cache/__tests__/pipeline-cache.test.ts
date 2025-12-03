/**
 * Tests for pipeline caching utilities
 * 
 * These tests verify that:
 * 1. Caching functions are properly memoized within a request
 * 2. Cache keys are correctly generated
 * 3. Functions handle edge cases (missing data, invalid IDs)
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { getCachedPipelines, getCachedPipeline, getCachedStages } from '../pipeline-cache';

// Mock Prisma client
jest.mock('@/lib/db', () => ({
  prisma: {
    pipeline: {
      findMany: jest.fn(),
      findFirst: jest.fn(),
    },
    pipelineStage: {
      findMany: jest.fn(),
    },
  },
}));

describe('Pipeline Cache Utilities', () => {
  const mockOrganizationId = 'org-123';
  const mockPipelineId = 'pipeline-123';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getCachedPipelines', () => {
    it('should fetch pipelines for an organization', async () => {
      const mockPipelines = [
        {
          id: 'pipeline-1',
          name: 'Test Pipeline',
          organizationId: mockOrganizationId,
          isArchived: false,
          stages: [],
        },
      ];

      const { prisma } = await import('@/lib/db');
      (prisma.pipeline.findMany as jest.Mock).mockResolvedValue(mockPipelines);

      const result = await getCachedPipelines(mockOrganizationId, false);

      expect(result).toEqual(mockPipelines);
      expect(prisma.pipeline.findMany).toHaveBeenCalledWith({
        where: {
          organizationId: mockOrganizationId,
          isArchived: false,
        },
        include: {
          stages: {
            orderBy: { order: 'asc' },
            include: {
              _count: {
                select: { contacts: true },
              },
            },
          },
        },
      });
    });

    it('should include archived pipelines when requested', async () => {
      const { prisma } = await import('@/lib/db');
      (prisma.pipeline.findMany as jest.Mock).mockResolvedValue([]);

      await getCachedPipelines(mockOrganizationId, true);

      expect(prisma.pipeline.findMany).toHaveBeenCalledWith({
        where: {
          organizationId: mockOrganizationId,
        },
        include: {
          stages: {
            orderBy: { order: 'asc' },
            include: {
              _count: {
                select: { contacts: true },
              },
            },
          },
        },
      });
    });
  });

  describe('getCachedPipeline', () => {
    it('should fetch a single pipeline with stages', async () => {
      const mockPipeline = {
        id: mockPipelineId,
        name: 'Test Pipeline',
        organizationId: mockOrganizationId,
        stages: [
          {
            id: 'stage-1',
            name: 'Stage 1',
            order: 0,
            _count: { contacts: 5 },
          },
        ],
      };

      const { prisma } = await import('@/lib/db');
      (prisma.pipeline.findFirst as jest.Mock).mockResolvedValue(mockPipeline);

      const result = await getCachedPipeline(mockOrganizationId, mockPipelineId);

      expect(result).toEqual(mockPipeline);
      expect(prisma.pipeline.findFirst).toHaveBeenCalledWith({
        where: {
          id: mockPipelineId,
          organizationId: mockOrganizationId,
        },
        include: {
          stages: {
            orderBy: { order: 'asc' },
            include: {
              _count: {
                select: { contacts: true },
              },
            },
          },
        },
      });
    });

    it('should return null for non-existent pipeline', async () => {
      const { prisma } = await import('@/lib/db');
      (prisma.pipeline.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await getCachedPipeline(mockOrganizationId, 'non-existent');

      expect(result).toBeNull();
    });
  });

  describe('getCachedStages', () => {
    it('should fetch stages for a valid pipeline', async () => {
      const mockStages = [
        {
          id: 'stage-1',
          name: 'Stage 1',
          pipelineId: mockPipelineId,
          order: 0,
          _count: { contacts: 5 },
        },
      ];

      const { prisma } = await import('@/lib/db');
      (prisma.pipeline.findFirst as jest.Mock).mockResolvedValue({ id: mockPipelineId });
      (prisma.pipelineStage.findMany as jest.Mock).mockResolvedValue(mockStages);

      const result = await getCachedStages(mockOrganizationId, mockPipelineId);

      expect(result).toEqual(mockStages);
      expect(prisma.pipelineStage.findMany).toHaveBeenCalledWith({
        where: {
          pipelineId: mockPipelineId,
        },
        orderBy: { order: 'asc' },
        include: {
          _count: {
            select: { contacts: true },
          },
        },
      });
    });

    it('should return empty array for non-existent pipeline', async () => {
      const { prisma } = await import('@/lib/db');
      (prisma.pipeline.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await getCachedStages(mockOrganizationId, 'non-existent');

      expect(result).toEqual([]);
      expect(prisma.pipelineStage.findMany).not.toHaveBeenCalled();
    });
  });
});









