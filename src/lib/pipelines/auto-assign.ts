import { prisma } from '@/lib/db';
import { AIContactAnalysis } from '@/lib/ai/google-ai-service';
import { LeadStatus } from '@prisma/client';
import { findBestMatchingStage, shouldPreventDowngrade } from './stage-analyzer';

interface AutoAssignOptions {
  contactId: string;
  aiAnalysis: AIContactAnalysis;
  pipelineId: string;
  updateMode: 'SKIP_EXISTING' | 'UPDATE_EXISTING';
  userId?: string;
}

export async function autoAssignContactToPipeline(options: AutoAssignOptions) {
  const { contactId, aiAnalysis, pipelineId, updateMode, userId } = options;

  // Get contact with current assignment and score
  const contact = await prisma.contact.findUnique({
    where: { id: contactId },
    select: { 
      pipelineId: true, 
      stageId: true,
      leadScore: true,
      stage: {
        select: {
          order: true,
          leadScoreMin: true,
          name: true
        }
      }
    }
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

  // Validate pipeline has stages
  if (!pipeline.stages || pipeline.stages.length === 0) {
    console.error(`[Auto-Assign] ⚠️ Pipeline ${pipelineId} has no stages - cannot assign contact`);
    return;
  }

  // INTELLIGENT STAGE MATCHING
  // Priority 1: Use AI-powered stage analyzer with score ranges and status routing
  // Clamp leadScore to valid range (0-100) to ensure it's always within bounds
  // Handle null/undefined values gracefully
  const rawScore = aiAnalysis?.leadScore ?? null;
  const clampedLeadScore = rawScore === null || rawScore === undefined 
    ? 0 
    : Math.max(0, Math.min(100, rawScore));
  const leadStatus = aiAnalysis?.leadStatus || 'NEW';
  const targetStageId = await findBestMatchingStage(
    pipelineId,
    clampedLeadScore,
    leadStatus
  );

  let proposedStage = pipeline.stages.find(s => s.id === targetStageId);

  // Priority 2: Try exact name match from AI recommendation
  if (!proposedStage && aiAnalysis?.recommendedStage) {
    proposedStage = pipeline.stages.find(
      s => s.name.toLowerCase() === aiAnalysis.recommendedStage.toLowerCase()
    );

    if (proposedStage) {
      console.log(`[Auto-Assign] Using AI-recommended stage by name: ${proposedStage.name}`);
    }
  }

  // Fallback: Use first stage if nothing matched
  if (!proposedStage) {
    console.warn(`[Auto-Assign] No matching stage found, using first stage`);
    proposedStage = pipeline.stages[0];
  }

  // DOWNGRADE PROTECTION: Prevent high-score contacts from being moved to low stages
  if (proposedStage && contact.stage) {
    const shouldBlock = shouldPreventDowngrade(
      contact.stage.order,
      proposedStage.order,
      contact.leadScore || 0,
      clampedLeadScore,
      proposedStage.leadScoreMin
    );

    if (shouldBlock) {
      console.log(`[Auto-Assign] Keeping contact in current stage (${contact.stage.name}) - preventing downgrade from score ${clampedLeadScore}`);
      return; // Don't reassign - keep in current stage
    }
  }

  const targetStage = proposedStage;

  // Use transaction to ensure atomicity: contact update and activity log must both succeed or both fail
  await prisma.$transaction(async (tx) => {
    // Update contact
    await tx.contact.update({
      where: { id: contactId },
      data: {
        pipelineId,
        stageId: targetStage.id,
        stageEnteredAt: new Date(),
        leadScore: clampedLeadScore,
        leadStatus: leadStatus as LeadStatus,
      }
    });

    // Log activity within the same transaction
    await tx.contactActivity.create({
      data: {
        contactId,
        type: 'STAGE_CHANGED',
        title: 'AI auto-assigned to pipeline',
        description: aiAnalysis?.reasoning || 'AI analysis completed',
        toStageId: targetStage.id,
        fromStageId: contact.stageId || undefined,
        userId,
      metadata: {
        confidence: aiAnalysis?.confidence ?? 0,
        aiRecommendation: aiAnalysis?.recommendedStage || 'Unknown',
        leadScore: clampedLeadScore,
        leadStatus: leadStatus
      }
      }
    });
  });

  console.log(`[Auto-Assign] Contact ${contactId} → ${pipeline.name} → ${targetStage.name} (score: ${clampedLeadScore}, confidence: ${aiAnalysis?.confidence ?? 0}%)`);
}

