/**
 * Cost-Benefit Analysis System
 * Determines if pipeline updates are worth the resource cost
 */

import { prisma } from '@/lib/db';
import type { ActivityScore } from './activity-scorer';

export interface UpdateCostBenefit {
  estimatedCost: number; // API calls, processing time (normalized 0-1)
  estimatedBenefit: number; // Expected value from updates (normalized 0-1)
  roi: number; // Return on investment (benefit / cost)
  shouldProceed: boolean;
  estimatedApiCalls: number;
  estimatedProcessingTime: number; // seconds
  expectedUpdates: number;
  highValueContacts: number;
}

/**
 * Analyze cost-benefit of updating a pipeline
 */
export async function analyzeCostBenefit(
  pipelineId: string,
  activityScore: ActivityScore
): Promise<UpdateCostBenefit> {
  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: { 
      contacts: {
        select: {
          id: true,
          leadScore: true,
          stageId: true,
          updatedAt: true
        }
      }
    }
  });

  if (!pipeline) {
    return {
      estimatedCost: 0,
      estimatedBenefit: 0,
      roi: 0,
      shouldProceed: false,
      estimatedApiCalls: 0,
      estimatedProcessingTime: 0,
      expectedUpdates: 0,
      highValueContacts: 0
    };
  }

  const contactCount = pipeline.contacts.length;
  
  // Estimate cost (API calls, processing)
  // Batch size is typically 50 contacts per API call
  const estimatedApiCalls = Math.ceil(contactCount / 50);
  
  // Processing time: ~0.1 seconds per contact (AI analysis + DB operations)
  const estimatedProcessingTime = contactCount * 0.1;
  
  // Normalized cost (0-1 scale)
  // Higher cost for more contacts and API calls
  const maxContacts = 1000; // Normalize against max expected
  const normalizedContactCost = Math.min(1, contactCount / maxContacts);
  const normalizedApiCost = Math.min(1, estimatedApiCalls / 20); // Max 20 API calls
  const estimatedCost = (normalizedContactCost * 0.6) + (normalizedApiCost * 0.4);

  // Estimate benefit (based on activity score and lead quality)
  const highValueContacts = pipeline.contacts.filter(c => (c.leadScore || 0) >= 70).length;
  const avgLeadScore = contactCount > 0
    ? pipeline.contacts.reduce((sum, c) => sum + (c.leadScore || 0), 0) / contactCount
    : 0;
  
  // Expected number of contacts that will be updated
  // Based on activity score (higher score = more likely to have updates)
  const expectedUpdates = Math.floor(contactCount * (activityScore.totalScore / 100));
  
  // Benefit calculation:
  // - High-value contacts are worth more (0.1 points each)
  // - Expected updates indicate value (0.05 points each)
  // - Activity score indicates pipeline health (0.3 weight)
  // - Average lead score indicates quality (0.2 weight)
  const highValueBenefit = (highValueContacts / Math.max(1, contactCount)) * 0.4;
  const updateBenefit = (expectedUpdates / Math.max(1, contactCount)) * 0.3;
  const activityBenefit = (activityScore.totalScore / 100) * 0.2;
  const qualityBenefit = (avgLeadScore / 100) * 0.1;
  
  const estimatedBenefit = Math.min(1, 
    highValueBenefit + updateBenefit + activityBenefit + qualityBenefit
  );

  // Calculate ROI
  const roi = estimatedBenefit / Math.max(0.001, estimatedCost);
  
  // Should proceed if:
  // - ROI >= 1.0 (benefit >= cost)
  // - Activity score >= 20 (some activity)
  // - Has contacts to process
  const shouldProceed = (
    roi >= 1.0 && 
    activityScore.totalScore >= 20 && 
    contactCount > 0
  );

  return {
    estimatedCost: Math.round(estimatedCost * 1000) / 1000,
    estimatedBenefit: Math.round(estimatedBenefit * 1000) / 1000,
    roi: Math.round(roi * 100) / 100,
    shouldProceed,
    estimatedApiCalls,
    estimatedProcessingTime: Math.round(estimatedProcessingTime * 10) / 10,
    expectedUpdates,
    highValueContacts
  };
}

/**
 * Batch analyze cost-benefit for multiple pipelines
 */
export async function analyzeCostBenefitBatch(
  pipelineScores: Map<string, ActivityScore>
): Promise<Map<string, UpdateCostBenefit>> {
  const results = new Map<string, UpdateCostBenefit>();
  
  // Process in parallel with concurrency limit
  const batchSize = 10;
  const pipelineIds = Array.from(pipelineScores.keys());
  
  for (let i = 0; i < pipelineIds.length; i += batchSize) {
    const batch = pipelineIds.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (id) => {
        try {
          const score = pipelineScores.get(id);
          if (!score) {
            return { id, result: null };
          }
          const result = await analyzeCostBenefit(id, score);
          return { id, result };
        } catch (error) {
          console.error(`[Cost-Benefit] Error analyzing pipeline ${id}:`, error);
          return { id, result: null };
        }
      })
    );
    
    batchResults.forEach(({ id, result }) => {
      if (result) {
        results.set(id, result);
      }
    });
  }
  
  return results;
}

