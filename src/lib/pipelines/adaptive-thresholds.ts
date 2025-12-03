/**
 * Adaptive Threshold System
 * Calculates dynamic thresholds based on pipeline characteristics
 */

import type { Pipeline, Contact, PipelineStage } from '@prisma/client';

interface PipelineWithContacts extends Pipeline {
  contacts: Contact[];
  stages: PipelineStage[];
}

export interface AdaptiveThresholds {
  inactivityHours: number; // Dynamic based on pipeline type
  minUpdateInterval: number; // minutes
  maxUpdateInterval: number; // minutes
  activityDecayRate: number; // How quickly activity score decays
  priorityMultiplier: number; // Multiplier for priority-based scheduling
}

/**
 * Calculates adaptive thresholds based on pipeline characteristics
 */
export function calculateAdaptiveThresholds(
  pipeline: PipelineWithContacts
): AdaptiveThresholds {
  const contactCount = pipeline.contacts.length;
  const avgLeadScore = pipeline.contacts.length > 0
    ? pipeline.contacts.reduce((sum, c) => sum + (c.leadScore || 0), 0) / pipeline.contacts.length
    : 0;

  // High-value pipelines (high scores, many contacts) need more frequent updates
  let baseInactivityHours = 24;
  if (avgLeadScore >= 70 && contactCount >= 50) {
    baseInactivityHours = 12; // High-value: 12 hours
  } else if (avgLeadScore >= 50 || contactCount >= 100) {
    baseInactivityHours = 18; // Medium: 18 hours
  } else if (contactCount < 10) {
    baseInactivityHours = 48; // Small pipeline: 48 hours
  }

  // Calculate decay rate (how quickly activity becomes stale)
  // More contacts = slower decay (activity persists longer)
  const decayRate = contactCount > 0 
    ? Math.max(0.5, Math.min(2.0, 100 / contactCount))
    : 1.0;

  // Minimum update interval based on lead quality
  const minUpdateInterval = avgLeadScore >= 70 ? 5 : 15; // minutes

  // Maximum update interval based on pipeline size
  const maxUpdateInterval = contactCount < 10 ? 120 : 60; // minutes

  // Priority multiplier: high-value pipelines get priority boost
  const priorityMultiplier = avgLeadScore >= 70 ? 1.5 : 1.0;

  return {
    inactivityHours: baseInactivityHours,
    minUpdateInterval,
    maxUpdateInterval,
    activityDecayRate: Math.round(decayRate * 100) / 100,
    priorityMultiplier: Math.round(priorityMultiplier * 100) / 100
  };
}

/**
 * Apply adaptive thresholds to activity score
 */
export function applyAdaptiveThresholds(
  activityScore: { totalScore: number; priority: string; nextUpdateInterval: number },
  thresholds: AdaptiveThresholds
): { adjustedPriority: string; adjustedInterval: number } {
  let adjustedPriority = activityScore.priority;
  let adjustedInterval = activityScore.nextUpdateInterval;

  // Adjust interval based on thresholds
  adjustedInterval = Math.max(
    thresholds.minUpdateInterval,
    Math.min(thresholds.maxUpdateInterval, adjustedInterval)
  );

  // Boost priority for high-value pipelines
  if (thresholds.priorityMultiplier > 1.0) {
    if (activityScore.priority === 'medium' && activityScore.totalScore >= 60) {
      adjustedPriority = 'high';
      adjustedInterval = Math.min(adjustedInterval, 10); // Cap at 10 minutes for high priority
    }
  }

  // Apply decay rate to interval (slower decay = longer intervals acceptable)
  adjustedInterval = Math.ceil(adjustedInterval * thresholds.activityDecayRate);

  return {
    adjustedPriority: adjustedPriority as 'high' | 'medium' | 'low' | 'paused',
    adjustedInterval
  };
}

