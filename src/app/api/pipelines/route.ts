import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { StageType } from '@prisma/client';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';
import { getCachedPipelines } from '@/lib/cache/pipeline-cache';

// Enable ISR with 60 second revalidation
export const revalidate = 60;

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Use cached pipeline fetch
    const pipelines = await getCachedPipelines(session.user.organizationId, false);

    return NextResponse.json(pipelines, {
      headers: {
        'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
      },
    });
  } catch (error: unknown) {
    console.error('Get pipelines error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch pipelines';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

interface PipelineStage {
  name: string;
  color: string;
  type: StageType;
}

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json() as {
      name: string;
      description?: string;
      color?: string;
      stages: PipelineStage[];
    };
    const { name, description, color, stages } = body;

    const pipeline = await prisma.pipeline.create({
      data: {
        name,
        description,
        color: color || '#3b82f6',
        organizationId: session.user.organizationId,
        stages: {
          create: stages.map((stage, index: number) => ({
            name: stage.name,
            color: stage.color,
            type: stage.type,
            order: index,
          })),
        },
      },
      include: { stages: true },
    });

    // AUTO-GENERATE intelligent score ranges for all stages
    console.log(`[Pipeline Create] Auto-generating score ranges for ${pipeline.name}...`);
    await applyStageScoreRanges(pipeline.id);
    console.log(`[Pipeline Create] Score ranges applied successfully`);

    // Fetch updated pipeline with score ranges
    const updatedPipeline = await prisma.pipeline.findUnique({
      where: { id: pipeline.id },
      include: { stages: true }
    });

    return NextResponse.json(updatedPipeline || pipeline);
  } catch (error: unknown) {
    console.error('Create pipeline error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to create pipeline';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}
