import { prisma } from '@/lib/db';
import { withRetry } from '@/lib/db-retry';
import { ActivityType, ContactActivity, Prisma } from '@prisma/client';

export interface CreateActivityLogOptions {
  contactId: string;
  stageId: string | null;
  previousStageId: string | null;
  reason: string;
  metadata?: Record<string, unknown>;
  userId?: string;
}

/**
 * Creates an activity log entry when contacts are assigned to pipeline stages.
 * 
 * This function handles:
 * - Creating activity log entries for stage changes
 * - Handling null stageId (removal case)
 * - Handling null previousStageId (initial assignment)
 * - Database errors gracefully (logs, doesn't throw)
 * 
 * @param options - Activity log creation options
 * @returns Created activity log entry or void if creation fails
 */
export async function createActivityLog(
  options: CreateActivityLogOptions
): Promise<ContactActivity | void> {
  const { contactId, stageId, previousStageId, reason, metadata, userId } = options;

  try {
    return await withRetry(async () => {
      return await prisma.contactActivity.create({
        data: {
          contactId,
          type: 'STAGE_CHANGED' as ActivityType,
          title: stageId 
            ? (previousStageId ? 'Contact moved to new stage' : 'Contact assigned to stage')
            : 'Contact removed from stage',
          description: reason,
          toStageId: stageId || undefined,
          fromStageId: previousStageId || undefined,
          userId: userId || undefined,
          metadata: (metadata || undefined) as Prisma.InputJsonValue | undefined,
        },
      });
    });
  } catch (error) {
    // Log error but don't throw - activity logging is non-critical
    console.error(
      '[Create Activity Log] Failed to create activity log entry:',
      {
        contactId,
        stageId,
        previousStageId,
        error: error instanceof Error ? error.message : String(error),
      }
    );
    // Return void to indicate failure without throwing
    return;
  }
}

