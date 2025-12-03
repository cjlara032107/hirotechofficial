import { cache } from 'react';
import { prisma } from '@/lib/db';

/**
 * Cache key generator for pipeline data
 */
function getPipelineCacheKey(organizationId: string, includeArchived = false): string {
  return `pipelines:${organizationId}:${includeArchived ? 'all' : 'active'}`;
}

function getPipelineDetailCacheKey(organizationId: string, pipelineId: string): string {
  return `pipeline:${organizationId}:${pipelineId}`;
}

function getStagesCacheKey(organizationId: string, pipelineId: string): string {
  return `stages:${organizationId}:${pipelineId}`;
}

/**
 * Cached function to fetch all pipelines for an organization
 * Uses React cache() for request-level memoization
 */
export const getCachedPipelines = cache(async (organizationId: string, includeArchived = false) => {
  return prisma.pipeline.findMany({
    where: {
      organizationId,
      ...(includeArchived ? {} : { isArchived: false }),
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

/**
 * Cached function to fetch a single pipeline with stages
 */
export const getCachedPipeline = cache(async (organizationId: string, pipelineId: string) => {
  return prisma.pipeline.findFirst({
    where: {
      id: pipelineId,
      organizationId,
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

/**
 * Cached function to fetch stages for a pipeline
 */
export const getCachedStages = cache(async (organizationId: string, pipelineId: string) => {
  // First verify the pipeline belongs to the organization
  const pipeline = await prisma.pipeline.findFirst({
    where: {
      id: pipelineId,
      organizationId,
    },
    select: { id: true },
  });

  if (!pipeline) {
    return [];
  }

  return prisma.pipelineStage.findMany({
    where: {
      pipelineId,
    },
    orderBy: { order: 'asc' },
    include: {
      _count: {
        select: { contacts: true },
      },
    },
  });
});

/**
 * Invalidate cache for a pipeline (call after updates)
 * Note: React cache() is request-scoped, so this is mainly for documentation
 * In production, consider using Redis for cross-request caching
 */
export function invalidatePipelineCache(organizationId: string, pipelineId?: string) {
  // React cache() is request-scoped, so invalidation happens automatically
  // on the next request. For cross-request caching, implement Redis invalidation here.
  if (process.env.NODE_ENV === 'development') {
    console.log(`[Cache] Invalidated pipeline cache for org: ${organizationId}${pipelineId ? `, pipeline: ${pipelineId}` : ''}`);
  }
}









