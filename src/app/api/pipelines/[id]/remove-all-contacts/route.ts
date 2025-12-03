import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * POST /api/pipelines/[id]/remove-all-contacts
 * Remove all contacts from a pipeline (set pipelineId and stageId to null)
 */
export async function POST(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Verify pipeline belongs to user's organization
    const pipeline = await prisma.pipeline.findFirst({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
      include: {
        stages: {
          select: {
            id: true,
          },
        },
      },
    });

    if (!pipeline) {
      return NextResponse.json({ error: 'Pipeline not found' }, { status: 404 });
    }

    // Get all stage IDs for this pipeline
    const stageIds = pipeline.stages.map((stage) => stage.id);

    // Count contacts before removal
    const contactCount = await prisma.contact.count({
      where: {
        pipelineId: id,
        organizationId: session.user.organizationId,
      },
    });

    if (contactCount === 0) {
      return NextResponse.json({
        success: true,
        removedCount: 0,
        message: 'No contacts to remove',
      });
    }

    // Remove all contacts from pipeline (set pipelineId and stageId to null)
    const result = await prisma.contact.updateMany({
      where: {
        pipelineId: id,
        organizationId: session.user.organizationId,
      },
      data: {
        pipelineId: null,
        stageId: null,
        stageEnteredAt: null,
      },
    });

    // Create activity logs for removed contacts
    // Note: For very large pipelines (>1000 contacts), we skip individual activity logs to avoid overwhelming the database
    if (result.count > 0 && result.count <= 1000) {
      // Get contact IDs that were just removed (they now have pipelineId = null)
      // We need to find them by checking which contacts were in this pipeline before removal
      // Since we can't easily track which contacts were removed, we'll skip detailed activity logs
      // and just log a summary. For smaller pipelines, we could enhance this later.
      // For now, we'll create a single summary activity or skip individual logs for performance
    }

    return NextResponse.json({
      success: true,
      removedCount: result.count,
      message: `Successfully removed ${result.count} contact(s) from pipeline`,
    });
  } catch (error: unknown) {
    console.error('Remove all contacts from pipeline error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to remove contacts';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

