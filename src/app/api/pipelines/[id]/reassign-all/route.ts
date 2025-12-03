import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { findBestMatchingStage } from '@/lib/pipelines/stage-analyzer';

/**
 * POST /api/pipelines/[id]/reassign-all
 * Bulk re-assign all contacts in a pipeline based on their lead scores
 * Uses updated score ranges to place contacts in correct stages
 */
export async function POST(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id: pipelineId } = await props.params;
    const session = await auth();

    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Verify pipeline belongs to user's organization
    const pipeline = await prisma.pipeline.findFirst({
      where: {
        id: pipelineId,
        organizationId: session.user.organizationId,
      },
      include: {
        stages: {
          orderBy: { order: 'asc' },
        },
        contacts: true,
      },
    });

    if (!pipeline) {
      return NextResponse.json({ error: 'Pipeline not found' }, { status: 404 });
    }

    console.log(`[Reassign All] Starting bulk re-assignment for ${pipeline.contacts.length} contacts in pipeline: ${pipeline.name}`);

    let reassigned = 0;
    let skipped = 0;

    // Re-assign each contact based on their score
    for (const contact of pipeline.contacts) {
      try {
        // Find best matching stage using intelligent routing
        const targetStageId = await findBestMatchingStage(
          pipelineId,
          contact.leadScore,
          contact.leadStatus
        );

        if (!targetStageId) {
          console.warn(`[Reassign All] No matching stage found for contact ${contact.id}`);
          skipped++;
          continue;
        }

        // Only update if stage actually changes
        if (targetStageId !== contact.stageId) {
          const oldStageId = contact.stageId;

          // Use transaction to ensure atomicity: contact update and activity log must both succeed or both fail
          await prisma.$transaction(async (tx) => {
            await tx.contact.update({
              where: { id: contact.id },
              data: {
                stageId: targetStageId,
                stageEnteredAt: new Date(),
              },
            });

            // Log activity for audit trail within the same transaction
            await tx.contactActivity.create({
              data: {
                contactId: contact.id,
                type: 'STAGE_CHANGED',
                title: 'Bulk re-assigned based on lead score',
                description: `Automatically moved to match lead score range. Score: ${contact.leadScore}, Status: ${contact.leadStatus}`,
                fromStageId: oldStageId,
                toStageId: targetStageId,
                metadata: {
                  bulkReassignment: true,
                  leadScore: contact.leadScore,
                  leadStatus: contact.leadStatus,
                },
              },
            });
          });

          reassigned++;
          console.log(`[Reassign All] Contact ${contact.id} (score: ${contact.leadScore}) → Stage ${targetStageId}`);
        } else {
          skipped++;
        }
      } catch (error) {
        console.error(`[Reassign All] Failed to reassign contact ${contact.id}:`, error);
        skipped++;
      }
    }

    console.log(`[Reassign All] Complete: ${reassigned} reassigned, ${skipped} skipped`);

    return NextResponse.json({
      success: true,
      reassigned,
      skipped,
      total: pipeline.contacts.length,
    });
  } catch (error) {
    console.error('[Reassign All] Error:', error);
    return NextResponse.json(
      { error: 'Failed to re-assign contacts' },
      { status: 500 }
    );
  }
}

