import { prisma } from '@/lib/db';
import { AIContactAnalysis } from '@/lib/ai/google-ai-service';
import { LeadStatus } from '@prisma/client';

interface AutoAssignOptions {
  contactId: string;
  aiAnalysis: AIContactAnalysis;
  pipelineId: string;
  updateMode: 'SKIP_EXISTING' | 'UPDATE_EXISTING';
  userId?: string;
}

export async function autoAssignContactToPipeline(options: AutoAssignOptions) {
  const { contactId, aiAnalysis, pipelineId, updateMode, userId } = options;

  // Get contact with current assignment
  const contact = await prisma.contact.findUnique({
    where: { id: contactId },
    select: { pipelineId: true, stageId: true }
  });

  if (!contact) return;

  // Check if should skip
  if (updateMode === 'SKIP_EXISTING' && contact.pipelineId) {
    console.log(`[Auto-Assign] Skipping contact ${contactId} - already assigned`);
    return;
  }

  // Get pipeline stages
  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: { stages: { orderBy: { order: 'asc' } } }
  });

  if (!pipeline) {
    console.error(`[Auto-Assign] Pipeline ${pipelineId} not found`);
    return;
  }

  // Find matching stage
  let targetStage = pipeline.stages.find(
    s => s.name.toLowerCase() === aiAnalysis.recommendedStage.toLowerCase()
  );

  // Fallback: if exact match not found, use first stage
  if (!targetStage) {
    console.warn(`[Auto-Assign] Stage "${aiAnalysis.recommendedStage}" not found, using first stage`);
    targetStage = pipeline.stages[0];
  }

  // Update contact
  await prisma.contact.update({
    where: { id: contactId },
    data: {
      pipelineId,
      stageId: targetStage.id,
      stageEnteredAt: new Date(),
      leadScore: aiAnalysis.leadScore,
      leadStatus: aiAnalysis.leadStatus as LeadStatus,
    }
  });

  // Log activity
  await prisma.contactActivity.create({
    data: {
      contactId,
      type: 'STAGE_CHANGED',
      title: 'AI auto-assigned to pipeline',
      description: aiAnalysis.reasoning,
      toStageId: targetStage.id,
      fromStageId: contact.stageId || undefined,
      userId,
      metadata: {
        confidence: aiAnalysis.confidence,
        aiRecommendation: aiAnalysis.recommendedStage,
        leadScore: aiAnalysis.leadScore,
        leadStatus: aiAnalysis.leadStatus
      }
    }
  });

  console.log(`[Auto-Assign] Contact ${contactId} → ${pipeline.name} → ${targetStage.name} (score: ${aiAnalysis.leadScore}, confidence: ${aiAnalysis.confidence}%)`);
}

