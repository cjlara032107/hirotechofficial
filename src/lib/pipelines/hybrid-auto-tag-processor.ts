import { prisma } from '@/lib/db';
import { logger } from '@/lib/utils/logger';

interface AutoTagJob {
  contactId: string;
  stageId: string;
  organizationId: string;
  userId: string;
}

interface ProcessingOptions {
  contactCount: number;
  operationType: 'single' | 'bulk' | 'batch';
  priority?: 'high' | 'normal' | 'low';
  sync?: boolean;
}

/**
 * HYBRID PROCESSOR - Intelligently routes to best approach
 */
export class HybridAutoTagProcessor {
  private static readonly THRESHOLDS = {
    SINGLE: 1,
    SMALL_BULK: 50,
    MEDIUM_BULK: 200,
    LARGE_BULK: 1000,
  };

  static async process(
    jobs: AutoTagJob[],
    options: ProcessingOptions
  ): Promise<{ processed: number; failed: number; method: string }> {
    const count = jobs.length;

    if (count === 1 || options.sync) {
      logger.debug('Using immediate processing', { count });
      const result = await this.processImmediate(jobs[0]!);
      return {
        processed: result ? 1 : 0,
        failed: result ? 0 : 1,
        method: 'immediate',
      };
    }

    if (count <= this.THRESHOLDS.SMALL_BULK) {
      logger.debug('Using batch processing', { count });
      return await this.processBatch(jobs, options);
    }

    if (count <= this.THRESHOLDS.MEDIUM_BULK) {
      logger.debug('Using hybrid queue+batch processing', { count });
      return await this.processHybrid(jobs);
    }

    logger.debug('Using queue-based async processing', { count });
    return await this.processQueueAsync(jobs);
  }

  private static async processImmediate(job: AutoTagJob): Promise<boolean> {
    try {
      const stage = await prisma.pipelineStage.findUnique({
        where: { id: job.stageId },
        select: {
          autoTagEnabled: true,
          autoTagToAdd: true,
          autoTagToRemove: true,
        },
      });

      if (!stage || !stage.autoTagEnabled) return true;

      const contact = await prisma.contact.findUnique({
        where: { id: job.contactId },
        select: { tags: true },
      });

      if (!contact) return false;

      const result = await this.applyAutoTags(
        job.contactId,
        contact.tags || [],
        stage,
        job.organizationId,
        job.userId
      );

      return result.success;
    } catch (error) {
      logger.error('Immediate processing error', { error, job });
      return false;
    }
  }

  private static async processBatch(
    jobs: AutoTagJob[],
    options: ProcessingOptions
  ): Promise<{ processed: number; failed: number; method: string }> {
    const chunkSize = options.operationType === 'bulk' ? 25 : 10;
    let processed = 0;
    let failed = 0;

    const jobsByStage = new Map<string, AutoTagJob[]>();
    for (const job of jobs) {
      if (!jobsByStage.has(job.stageId)) {
        jobsByStage.set(job.stageId, []);
      }
      jobsByStage.get(job.stageId)!.push(job);
    }

    for (const [stageId, stageJobs] of jobsByStage) {
      const stage = await prisma.pipelineStage.findUnique({
        where: { id: stageId },
        select: {
          autoTagEnabled: true,
          autoTagToAdd: true,
          autoTagToRemove: true,
        },
      });

      if (!stage || !stage.autoTagEnabled) {
        processed += stageJobs.length;
        continue;
      }

      for (let i = 0; i < stageJobs.length; i += chunkSize) {
        const chunk = stageJobs.slice(i, i + chunkSize);
        
        try {
          const results = await Promise.allSettled(
            chunk.map(job => this.processJobWithStage(job, stage))
          );

          results.forEach((result) => {
            if (result.status === 'fulfilled' && result.value) {
              processed++;
            } else {
              failed++;
            }
          });
        } catch (error) {
          logger.error('Batch chunk error', { error, chunkIndex: i });
          failed += chunk.length;
        }

        if (i + chunkSize < stageJobs.length) {
          await new Promise(resolve => setTimeout(resolve, 50));
        }
      }
    }

    return { processed, failed, method: 'batch' };
  }

  private static async processHybrid(
    jobs: AutoTagJob[]
  ): Promise<{ processed: number; failed: number; method: string }> {
    this.processQueueAsync(jobs).catch(error => {
      logger.error('Hybrid async processing error', { error });
    });

    return {
      processed: jobs.length,
      failed: 0,
      method: 'hybrid-queue',
    };
  }

  private static async processQueueAsync(
    jobs: AutoTagJob[]
  ): Promise<{ processed: number; failed: number; method: string }> {
    const jobsByStage = new Map<string, AutoTagJob[]>();
    for (const job of jobs) {
      if (!jobsByStage.has(job.stageId)) {
        jobsByStage.set(job.stageId, []);
      }
      jobsByStage.get(job.stageId)!.push(job);
    }

    let totalProcessed = 0;
    let totalFailed = 0;

    for (const [stageId, stageJobs] of jobsByStage) {
      try {
        const result = await this.processBulkForStage(
          stageId,
          stageJobs
        );
        totalProcessed += result.processed;
        totalFailed += result.failed;
      } catch (error) {
        logger.error('Bulk stage processing error', { error, stageId });
        totalFailed += stageJobs.length;
      }
    }

    return { processed: totalProcessed, failed: totalFailed, method: 'queue-bulk' };
  }

  private static async processBulkForStage(
    stageId: string,
    jobs: AutoTagJob[]
  ): Promise<{ processed: number; failed: number }> {
    const stage = await prisma.pipelineStage.findUnique({
      where: { id: stageId },
      select: {
        autoTagEnabled: true,
        autoTagToAdd: true,
        autoTagToRemove: true,
      },
    });

    if (!stage || !stage.autoTagEnabled) {
      return { processed: jobs.length, failed: 0 };
    }

    const contactIds = jobs.map(j => j.contactId);
    const organizationId = jobs[0]?.organizationId;

    if (!organizationId) {
      return { processed: 0, failed: jobs.length };
    }

    try {
      await prisma.$transaction(async (tx) => {
        const contacts = await tx.contact.findMany({
          where: {
            id: { in: contactIds },
            organizationId,
          },
          select: {
            id: true,
            tags: true,
          },
        });

        const updates: Array<{ id: string; tags: string[] }> = [];
        const tagAddCounts = new Map<string, number>();
        const tagRemoveCounts = new Map<string, number>();

        for (const contact of contacts) {
          const currentTags = contact.tags || [];
          const newTags = [...currentTags];
          let changed = false;

          if (stage.autoTagToAdd && !currentTags.includes(stage.autoTagToAdd)) {
            newTags.push(stage.autoTagToAdd);
            changed = true;
            tagAddCounts.set(
              stage.autoTagToAdd,
              (tagAddCounts.get(stage.autoTagToAdd) || 0) + 1
            );
          }

          if (stage.autoTagToRemove && currentTags.includes(stage.autoTagToRemove)) {
            const index = newTags.indexOf(stage.autoTagToRemove);
            if (index > -1) {
              newTags.splice(index, 1);
              changed = true;
              tagRemoveCounts.set(
                stage.autoTagToRemove,
                (tagRemoveCounts.get(stage.autoTagToRemove) || 0) + 1
              );
            }
          }

          if (changed) {
            updates.push({ id: contact.id, tags: newTags });
          }
        }

        if (updates.length > 0) {
          await Promise.all(
            updates.map(update =>
              tx.contact.update({
                where: { id: update.id },
                data: { tags: update.tags },
              })
            )
          );

          if (stage.autoTagToAdd && tagAddCounts.has(stage.autoTagToAdd)) {
            await tx.tag.updateMany({
              where: {
                name: stage.autoTagToAdd,
                organizationId,
              },
              data: {
                contactCount: {
                  increment: tagAddCounts.get(stage.autoTagToAdd)!,
                },
              },
            });
          }

          if (stage.autoTagToRemove && tagRemoveCounts.has(stage.autoTagToRemove)) {
            await tx.tag.updateMany({
              where: {
                name: stage.autoTagToRemove,
                organizationId,
              },
              data: {
                contactCount: {
                  decrement: tagRemoveCounts.get(stage.autoTagToRemove)!,
                },
              },
            });
          }
        }
      });

      return { processed: contactIds.length, failed: 0 };
    } catch (error) {
      logger.error('Bulk stage transaction error', { error, stageId });
      return { processed: 0, failed: jobs.length };
    }
  }

  private static async processJobWithStage(
    job: AutoTagJob,
    stage: { autoTagEnabled: boolean; autoTagToAdd: string | null; autoTagToRemove: string | null }
  ): Promise<boolean> {
    const contact = await prisma.contact.findUnique({
      where: { id: job.contactId },
      select: { tags: true },
    });

    if (!contact) return false;

    const result = await this.applyAutoTags(
      job.contactId,
      contact.tags || [],
      stage,
      job.organizationId,
      job.userId
    );

    return result.success;
  }

  private static async applyAutoTags(
    contactId: string,
    currentTags: string[],
    stage: { autoTagEnabled: boolean; autoTagToAdd: string | null; autoTagToRemove: string | null },
    organizationId: string,
    userId: string
  ): Promise<{ success: boolean; tagsChanged: boolean }> {
    if (!stage.autoTagEnabled) {
      return { success: true, tagsChanged: false };
    }

    const newTags = [...currentTags];
    let tagsChanged = false;

    if (stage.autoTagToAdd && !currentTags.includes(stage.autoTagToAdd)) {
      newTags.push(stage.autoTagToAdd);
      tagsChanged = true;
    }

    if (stage.autoTagToRemove && currentTags.includes(stage.autoTagToRemove)) {
      const index = newTags.indexOf(stage.autoTagToRemove);
      if (index > -1) {
        newTags.splice(index, 1);
        tagsChanged = true;
      }
    }

    if (!tagsChanged) {
      return { success: true, tagsChanged: false };
    }

    try {
      await prisma.$transaction(async (tx) => {
        await tx.contact.update({
          where: { id: contactId },
          data: { tags: newTags },
        });

        if (stage.autoTagToAdd) {
          await tx.tag.updateMany({
            where: {
              name: stage.autoTagToAdd,
              organizationId,
            },
            data: {
              contactCount: { increment: 1 },
            },
          });

          await tx.contactActivity.create({
            data: {
              contactId,
              type: 'TAG_ADDED',
              title: `Tag "${stage.autoTagToAdd}" added automatically`,
              userId,
            },
          });
        }

        if (stage.autoTagToRemove) {
          await tx.tag.updateMany({
            where: {
              name: stage.autoTagToRemove,
              organizationId,
            },
            data: {
              contactCount: { decrement: 1 },
            },
          });

          await tx.contactActivity.create({
            data: {
              contactId,
              type: 'TAG_REMOVED',
              title: `Tag "${stage.autoTagToRemove}" removed automatically`,
              userId,
            },
          });
        }
      });

      return { success: true, tagsChanged: true };
    } catch (error) {
      logger.error('Apply auto-tags error', { error, contactId });
      return { success: false, tagsChanged: false };
    }
  }
}

export async function processAutoTagForContact(
  contactId: string,
  stageId: string,
  organizationId: string,
  userId: string
): Promise<boolean> {
  const result = await HybridAutoTagProcessor.process(
    [{ contactId, stageId, organizationId, userId }],
    { contactCount: 1, operationType: 'single', sync: true }
  );
  return result.processed === 1;
}

export async function processAutoTagsBulk(
  jobs: AutoTagJob[]
): Promise<{ processed: number; failed: number }> {
  const result = await HybridAutoTagProcessor.process(
    jobs,
    {
      contactCount: jobs.length,
      operationType: jobs.length > 200 ? 'bulk' : 'batch',
    }
  );
  return { processed: result.processed, failed: result.failed };
}

export type { AutoTagJob };

