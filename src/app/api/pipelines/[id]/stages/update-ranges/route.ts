import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateScoreRange, detectScoreRangeOverlaps } from '@/lib/pipelines/validation';
import { validateBodySize, BodySizeLimits } from '@/lib/api/validate-body-size';
import { RateLimitPresets } from '@/lib/api/rate-limit';

interface StageRange {
  stageId: string;
  leadScoreMin: number;
  leadScoreMax: number;
}

/**
 * POST /api/pipelines/[id]/stages/update-ranges
 * Update lead score ranges for multiple stages
 */
export async function POST(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    // Apply rate limiting
    const rateLimitResponse = await RateLimitPresets.standard(request);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    // Validate body size
    const bodySizeResponse = await validateBodySize(request, {
      maxSizeBytes: BodySizeLimits.MEDIUM,
    });
    if (bodySizeResponse) {
      return bodySizeResponse;
    }

    const { id } = await props.params;
    const session = await auth();

    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { stageRanges } = body as { stageRanges: StageRange[] };

    if (!Array.isArray(stageRanges) || stageRanges.length === 0) {
      return NextResponse.json(
        { error: 'Invalid stage ranges provided' },
        { status: 400 }
      );
    }

    // Validate each score range
    for (const range of stageRanges) {
      const validation = validateScoreRange(range.leadScoreMin, range.leadScoreMax);
      if (!validation.valid) {
        return NextResponse.json(
          { error: validation.errors.join(', ') },
          { status: 400 }
        );
      }
    }

    // Verify pipeline belongs to user's organization
    const pipeline = await prisma.pipeline.findFirst({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
    });

    if (!pipeline) {
      return NextResponse.json({ error: 'Pipeline not found' }, { status: 404 });
    }

    console.log(`[Update Ranges] Updating ${stageRanges.length} stage ranges for pipeline ${id}`);

    // Fetch current stages to check for overlaps
    const stages = await prisma.pipelineStage.findMany({
      where: { pipelineId: id },
      select: { id: true, name: true, leadScoreMin: true, leadScoreMax: true, type: true }
    });

    // Update ranges with new values for overlap check
    const updatedStages = stages.map(stage => {
      const newRange = stageRanges.find(r => r.stageId === stage.id);
      return newRange
        ? { ...stage, leadScoreMin: newRange.leadScoreMin, leadScoreMax: newRange.leadScoreMax }
        : stage;
    });

    // Check for overlaps and warn
    const overlaps = detectScoreRangeOverlaps(updatedStages);
    if (overlaps.length > 0) {
      console.warn(`[Update Ranges] Warning: Detected ${overlaps.length} overlapping score ranges`);
    }

    // Update each stage's score range
    await Promise.all(
      stageRanges.map(range =>
        prisma.pipelineStage.update({
          where: { id: range.stageId },
          data: {
            leadScoreMin: range.leadScoreMin,
            leadScoreMax: range.leadScoreMax,
          },
        })
      )
    );

    console.log(`[Update Ranges] Successfully updated all stage ranges`);

    return NextResponse.json({ 
      success: true,
      updated: stageRanges.length,
      warnings: overlaps.length > 0 ? overlaps : undefined
    });
  } catch (error) {
    console.error('[Update Ranges] Error:', error);
    return NextResponse.json(
      { error: 'Failed to update score ranges' },
      { status: 500 }
    );
  }
}

