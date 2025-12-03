import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { generatePipelineFromContacts, type PipelineGenerationLogic } from '@/lib/ai/pipeline-generator';

/**
 * POST /api/pipelines/generate-ai
 * Generate an AI-created pipeline based on contact analysis
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json() as {
      facebookPageId?: string;
      stageCount?: number;
      detailLevel?: number;
      logic?: PipelineGenerationLogic;
      enableBusinessIntelligence?: boolean;
      allowAIStageDecision?: boolean;
      minContactsPerStage?: number;
      customInstructions?: string;
    };

    const { 
      facebookPageId, 
      stageCount, 
      detailLevel,
      logic = 'HYBRID', // Default to HYBRID
      enableBusinessIntelligence = true, // Default: ON
      allowAIStageDecision = true, // Default: AI decides
      minContactsPerStage = 2,
      customInstructions
    } = body;

    // Generate pipeline suggestion with selected logic
    // Use new options-based signature: (organizationId, facebookPageId, options)
    const suggestion = await generatePipelineFromContacts(
      session.user.organizationId,
      facebookPageId,
      {
        logic,
        requestedStageCount: stageCount,
        minContactsPerStage,
        enableAutoGeneration: true,
        enableBusinessIntelligence,
        allowAIStageDecision,
        detailLevel: detailLevel || 5,
        customInstructions: customInstructions?.trim() || undefined
      }
    );

    return NextResponse.json(suggestion);
  } catch (error: unknown) {
    console.error('Generate AI pipeline error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to generate AI pipeline';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

