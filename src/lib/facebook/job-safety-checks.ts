import { prisma } from '@/lib/db';
import { SyncJobStatus, AnalysisJobStatus } from '@prisma/client';

/**
 * Comprehensive job status check - verifies job is still active
 * Returns true if job should continue, false if it should stop
 */
export async function isJobActive(
  jobId: string,
  jobType: 'sync' | 'analysis'
): Promise<{ active: boolean; status?: string; reason?: string }> {
  try {
    if (jobType === 'sync') {
      const job = await prisma.syncJob.findUnique({
        where: { id: jobId },
        select: { status: true },
      });

      if (!job) {
        return { active: false, reason: 'Job not found' };
      }

      // Job should only continue if it's IN_PROGRESS
      // If it's been changed to CANCELLED, FAILED, or COMPLETED externally, stop
      if (job.status !== 'IN_PROGRESS') {
        return {
          active: false,
          status: job.status,
          reason: `Job status changed to ${job.status}`,
        };
      }

      return { active: true, status: job.status };
    } else {
      const job = await prisma.analysisJob.findUnique({
        where: { id: jobId },
        select: { status: true },
      });

      if (!job) {
        return { active: false, reason: 'Job not found' };
      }

      if (job.status !== 'IN_PROGRESS') {
        return {
          active: false,
          status: job.status,
          reason: `Job status changed to ${job.status}`,
        };
      }

      return { active: true, status: job.status };
    }
  } catch (error) {
    console.error(`[Job Safety] Error checking job status for ${jobId}:`, error);
    // On error, assume job should continue (fail open)
    return { active: true };
  }
}

/**
 * Verifies that a Facebook page still exists and is accessible
 * Returns the page if it exists, null if deleted or not found
 */
export async function verifyPageExists(
  facebookPageId: string
): Promise<{ exists: boolean; page?: any; reason?: string }> {
  try {
    const page = await prisma.facebookPage.findUnique({
      where: { id: facebookPageId },
      select: {
        id: true,
        pageId: true,
        pageAccessToken: true,
        instagramAccountId: true,
        organizationId: true,
        autoPipelineId: true,
        autoPipeline: {
          include: {
            stages: { orderBy: { order: 'asc' } },
          },
        },
      },
    });

    if (!page) {
      return { exists: false, reason: 'Page not found - may have been deleted' };
    }

    return { exists: true, page };
  } catch (error) {
    console.error(`[Job Safety] Error verifying page ${facebookPageId}:`, error);
    return { exists: false, reason: 'Error checking page existence' };
  }
}

/**
 * Verifies that a pipeline still exists and is accessible
 * Returns the pipeline if it exists, null if deleted or not found
 */
export async function verifyPipelineExists(
  pipelineId: string,
  organizationId: string
): Promise<{ exists: boolean; pipeline?: any; reason?: string }> {
  try {
    const pipeline = await prisma.pipeline.findFirst({
      where: {
        id: pipelineId,
        organizationId,
      },
      include: {
        stages: { orderBy: { order: 'asc' } },
      },
    });

    if (!pipeline) {
      return { exists: false, reason: 'Pipeline not found - may have been deleted' };
    }

    return { exists: true, pipeline };
  } catch (error) {
    console.error(`[Job Safety] Error verifying pipeline ${pipelineId}:`, error);
    return { exists: false, reason: 'Error checking pipeline existence' };
  }
}

/**
 * Checks if an access token has expired based on API error
 * This is a helper to standardize token expiration detection
 */
export function isTokenExpiredError(error: unknown): boolean {
  // Check if it's a FacebookApiError with code 190
  if (error && typeof error === 'object' && 'code' in error) {
    const code = (error as any).code;
    return code === 190;
  }

  // Check if error has isTokenExpired property
  if (error && typeof error === 'object' && 'isTokenExpired' in error) {
    return (error as any).isTokenExpired === true;
  }

  return false;
}

/**
 * Marks a sync job as failed due to page deletion
 */
export async function markJobFailedDueToPageDeletion(
  jobId: string,
  reason: string
): Promise<void> {
  try {
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [
          {
            error: reason,
            timestamp: new Date().toISOString(),
          },
        ],
        completedAt: new Date(),
      },
    });
  } catch (error) {
    console.error(`[Job Safety] Failed to mark job ${jobId} as failed:`, error);
  }
}

/**
 * Marks a sync job as failed due to pipeline deletion
 */
export async function markJobFailedDueToPipelineDeletion(
  jobId: string,
  reason: string
): Promise<void> {
  try {
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [
          {
            error: reason,
            timestamp: new Date().toISOString(),
          },
        ],
        completedAt: new Date(),
      },
    });
  } catch (error) {
    console.error(`[Job Safety] Failed to mark job ${jobId} as failed:`, error);
  }
}

/**
 * Marks a job as failed due to token expiration
 */
export async function markJobFailedDueToTokenExpiration(
  jobId: string,
  jobType: 'sync' | 'analysis',
  reason: string
): Promise<void> {
  try {
    if (jobType === 'sync') {
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          status: 'FAILED',
          tokenExpired: true,
          errors: [
            {
              error: reason,
              timestamp: new Date().toISOString(),
            },
          ],
          completedAt: new Date(),
        },
      });
    } else {
      await prisma.analysisJob.update({
        where: { id: jobId },
        data: {
          status: 'FAILED',
          errors: [
            {
              error: reason,
              timestamp: new Date().toISOString(),
            },
          ],
          completedAt: new Date(),
        },
      });
    }
  } catch (error) {
    console.error(`[Job Safety] Failed to mark job ${jobId} as failed:`, error);
  }
}









