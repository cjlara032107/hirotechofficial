/**
 * Advanced Activity Scoring System
 * Multi-factor analysis to determine pipeline update priority and scheduling
 */

import { prisma } from '@/lib/db';
import type { Pipeline, Contact, ContactActivity, PipelineStage } from '@prisma/client';

export interface ActivityScore {
  totalScore: number; // 0-100
  factors: {
    recency: number;        // Weight: 30%
    engagement: number;      // Weight: 25%
    leadQuality: number;    // Weight: 20%
    pipelineVelocity: number; // Weight: 15%
    stageProgression: number; // Weight: 10%
  };
  shouldUpdate: boolean;
  priority: 'high' | 'medium' | 'low' | 'paused';
  nextUpdateInterval: number; // minutes
  lastActivityTime: Date | null;
  hoursSinceLastActivity: number;
}

interface PipelineWithContacts extends Pipeline {
  contacts: (Contact & {
    activities: ContactActivity[];
    stage: PipelineStage | null;
  })[];
  stages: PipelineStage[];
}

/**
 * Calculate comprehensive activity score for a pipeline
 */
export async function calculateActivityScore(pipelineId: string): Promise<ActivityScore> {
  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: {
      contacts: {
        include: {
          activities: {
            orderBy: { createdAt: 'desc' },
            take: 100
          },
          stage: true
        }
      },
      stages: true
    }
  });

  if (!pipeline) {
    return getDefaultScore('paused');
  }

  const now = new Date();
  const contacts = pipeline.contacts;
  const totalContacts = contacts.length;

  // If no contacts, return low priority
  if (totalContacts === 0) {
    return getDefaultScore('paused');
  }

  // Factor 1: Recency (30% weight)
  const recentActivities = contacts.flatMap(c => c.activities)
    .filter(a => {
      const hoursAgo = (now.getTime() - a.createdAt.getTime()) / (1000 * 60 * 60);
      return hoursAgo <= 24;
    });
  
  const recencyScore = Math.min(100, (recentActivities.length / Math.max(1, totalContacts)) * 100);
  const latestActivity = recentActivities.length > 0
    ? recentActivities[0].createdAt
    : contacts.flatMap(c => c.activities)[0]?.createdAt || null;
  
  const hoursSinceLastActivity = latestActivity 
    ? (now.getTime() - latestActivity.getTime()) / (1000 * 60 * 60)
    : Infinity;

  // Factor 2: Engagement (25% weight)
  const engagementTypes: string[] = ['MESSAGE_SENT', 'MESSAGE_RECEIVED', 'CALL_MADE', 'EMAIL_SENT'];
  const engagementCount = recentActivities.filter(a => 
    engagementTypes.includes(a.type)
  ).length;
  const engagementScore = Math.min(100, (engagementCount / Math.max(1, totalContacts)) * 200);

  // Factor 3: Lead Quality (20% weight)
  const avgLeadScore = contacts.length > 0
    ? contacts.reduce((sum, c) => sum + (c.leadScore || 0), 0) / contacts.length
    : 0;
  const highValueContacts = contacts.filter(c => (c.leadScore || 0) >= 70).length;
  const leadQualityScore = (avgLeadScore * 0.7) + ((highValueContacts / Math.max(1, totalContacts)) * 30);

  // Factor 4: Pipeline Velocity (15% weight)
  const stageChanges = recentActivities.filter(a => a.type === 'STAGE_CHANGED');
  const velocityScore = Math.min(100, (stageChanges.length / Math.max(1, totalContacts)) * 500);

  // Factor 5: Stage Progression (10% weight)
  const progressedContacts = contacts.filter(c => {
    const stageOrder = c.stage?.order || 0;
    return stageOrder > 0; // Not in first stage
  }).length;
  const progressionScore = (progressedContacts / Math.max(1, totalContacts)) * 100;

  // Calculate weighted total
  const totalScore = (
    recencyScore * 0.30 +
    engagementScore * 0.25 +
    leadQualityScore * 0.20 +
    velocityScore * 0.15 +
    progressionScore * 0.10
  );

  // Determine priority and update interval
  let priority: 'high' | 'medium' | 'low' | 'paused';
  let nextUpdateInterval: number;

  if (totalScore >= 70) {
    priority = 'high';
    nextUpdateInterval = 5; // 5 minutes
  } else if (totalScore >= 40) {
    priority = 'medium';
    nextUpdateInterval = 15; // 15 minutes
  } else if (totalScore >= 20) {
    priority = 'low';
    nextUpdateInterval = 60; // 1 hour
  } else {
    priority = 'paused';
    nextUpdateInterval = 1440; // 24 hours (check daily)
  }

  // Override: If no activity for 24+ hours, force pause
  if (hoursSinceLastActivity >= 24) {
    priority = 'paused';
    nextUpdateInterval = 1440;
  }

  return {
    totalScore: Math.round(totalScore * 100) / 100,
    factors: {
      recency: Math.round(recencyScore * 100) / 100,
      engagement: Math.round(engagementScore * 100) / 100,
      leadQuality: Math.round(leadQualityScore * 100) / 100,
      pipelineVelocity: Math.round(velocityScore * 100) / 100,
      stageProgression: Math.round(progressionScore * 100) / 100
    },
    shouldUpdate: priority !== 'paused',
    priority,
    nextUpdateInterval,
    lastActivityTime: latestActivity,
    hoursSinceLastActivity: Math.round(hoursSinceLastActivity * 100) / 100
  };
}

/**
 * Get default score for edge cases
 */
function getDefaultScore(priority: 'high' | 'medium' | 'low' | 'paused'): ActivityScore {
  const intervals = {
    high: 5,
    medium: 15,
    low: 60,
    paused: 1440
  };

  return {
    totalScore: 0,
    factors: {
      recency: 0,
      engagement: 0,
      leadQuality: 0,
      pipelineVelocity: 0,
      stageProgression: 0
    },
    shouldUpdate: priority !== 'paused',
    priority,
    nextUpdateInterval: intervals[priority],
    lastActivityTime: null,
    hoursSinceLastActivity: Infinity
  };
}

/**
 * Batch calculate activity scores for multiple pipelines
 */
export async function calculateActivityScoresBatch(
  pipelineIds: string[]
): Promise<Map<string, ActivityScore>> {
  const scores = new Map<string, ActivityScore>();
  
  // Process in parallel with concurrency limit
  const batchSize = 10;
  for (let i = 0; i < pipelineIds.length; i += batchSize) {
    const batch = pipelineIds.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (id) => {
        try {
          const score = await calculateActivityScore(id);
          return { id, score };
        } catch (error) {
          console.error(`[Activity Scorer] Error calculating score for pipeline ${id}:`, error);
          return { id, score: getDefaultScore('paused') };
        }
      })
    );
    
    batchResults.forEach(({ id, score }) => {
      scores.set(id, score);
    });
  }
  
  return scores;
}

