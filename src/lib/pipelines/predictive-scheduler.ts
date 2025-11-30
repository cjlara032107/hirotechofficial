/**
 * Predictive Scheduling System
 * Uses historical patterns to predict optimal update times
 */

import { prisma } from '@/lib/db';

export interface PredictiveSchedule {
  predictedNextActivity: Date | null;
  confidence: number; // 0-1
  recommendedUpdateTime: Date;
  urgency: 'critical' | 'high' | 'normal' | 'low';
  peakActivityHour: number | null; // 0-23
  averageIntervalHours: number | null;
}

/**
 * Predicts when pipeline will need updates based on historical patterns
 */
export async function predictNextUpdate(pipelineId: string): Promise<PredictiveSchedule> {
  // Analyze historical activity patterns
  const historicalActivities = await prisma.contactActivity.findMany({
    where: {
      contact: { pipelineId }
    },
    orderBy: { createdAt: 'desc' },
    take: 1000,
    select: {
      createdAt: true
    }
  });

  if (historicalActivities.length < 10) {
    // Not enough data for prediction
    const now = new Date();
    return {
      predictedNextActivity: null,
      confidence: 0,
      recommendedUpdateTime: new Date(now.getTime() + 24 * 60 * 60 * 1000), // 24 hours from now
      urgency: 'low',
      peakActivityHour: null,
      averageIntervalHours: null
    };
  }

  // Analyze time-of-day patterns
  const hourDistribution = new Array(24).fill(0);
  historicalActivities.forEach(activity => {
    const hour = activity.createdAt.getHours();
    hourDistribution[hour]++;
  });

  // Find peak activity hour
  const maxCount = Math.max(...hourDistribution);
  const peakActivityHour = hourDistribution.indexOf(maxCount);

  // Calculate average interval between activities
  const intervals: number[] = [];
  for (let i = 0; i < historicalActivities.length - 1; i++) {
    const interval = historicalActivities[i].createdAt.getTime() - 
                     historicalActivities[i + 1].createdAt.getTime();
    intervals.push(interval / (1000 * 60 * 60)); // Convert to hours
  }
  
  const averageIntervalHours = intervals.length > 0
    ? intervals.reduce((sum, val) => sum + val, 0) / intervals.length
    : null;

  // Calculate variance for confidence
  const variance = intervals.length > 0
    ? intervals.reduce((sum, val) => {
        const diff = val - (averageIntervalHours || 0);
        return sum + (diff * diff);
      }, 0) / intervals.length
    : 0;

  // Confidence based on pattern consistency
  // Lower variance = higher confidence
  const baseConfidence = averageIntervalHours 
    ? Math.max(0, Math.min(1, 1 - (variance / Math.max(1, (averageIntervalHours * averageIntervalHours)))))
    : 0.3;

  // Boost confidence if there's a clear peak hour
  const peakHourStrength = maxCount / Math.max(1, historicalActivities.length / 24);
  const confidence = Math.min(1, baseConfidence * 0.7 + (peakHourStrength > 0.5 ? 0.3 : 0));

  // Predict next activity window
  const now = new Date();
  let predictedNextActivity: Date | null = null;
  
  if (peakActivityHour !== null && confidence > 0.3) {
    predictedNextActivity = new Date(now);
    predictedNextActivity.setHours(peakActivityHour, 0, 0, 0);
    
    // If peak hour already passed today, predict for tomorrow
    if (predictedNextActivity <= now) {
      predictedNextActivity.setDate(predictedNextActivity.getDate() + 1);
    }
    
    // Adjust based on average interval if available
    if (averageIntervalHours && averageIntervalHours < 24) {
      const hoursUntilPeak = (predictedNextActivity.getTime() - now.getTime()) / (1000 * 60 * 60);
      if (hoursUntilPeak > averageIntervalHours * 2) {
        // If peak is too far, use average interval instead
        predictedNextActivity = new Date(now.getTime() + averageIntervalHours * 60 * 60 * 1000);
      }
    }
  } else if (averageIntervalHours) {
    // Use average interval if no clear peak
    predictedNextActivity = new Date(now.getTime() + averageIntervalHours * 60 * 60 * 1000);
  }

  // Recommend update 30 minutes before predicted activity (or now if within 30 min)
  let recommendedUpdateTime: Date;
  if (predictedNextActivity) {
    const timeBeforeActivity = predictedNextActivity.getTime() - (30 * 60 * 1000);
    recommendedUpdateTime = new Date(Math.max(now.getTime(), timeBeforeActivity));
  } else {
    // Fallback: recommend update in 6 hours
    recommendedUpdateTime = new Date(now.getTime() + 6 * 60 * 60 * 1000);
  }

  // Determine urgency
  const hoursUntilUpdate = (recommendedUpdateTime.getTime() - now.getTime()) / (1000 * 60 * 60);
  let urgency: 'critical' | 'high' | 'normal' | 'low';
  if (hoursUntilUpdate <= 2) urgency = 'critical';
  else if (hoursUntilUpdate <= 6) urgency = 'high';
  else if (hoursUntilUpdate <= 12) urgency = 'normal';
  else urgency = 'low';

  return {
    predictedNextActivity,
    confidence: Math.round(confidence * 100) / 100,
    recommendedUpdateTime,
    urgency,
    peakActivityHour: peakActivityHour !== null ? peakActivityHour : null,
    averageIntervalHours: averageIntervalHours ? Math.round(averageIntervalHours * 10) / 10 : null
  };
}

/**
 * Batch predict updates for multiple pipelines
 */
export async function predictNextUpdatesBatch(
  pipelineIds: string[]
): Promise<Map<string, PredictiveSchedule>> {
  const predictions = new Map<string, PredictiveSchedule>();
  
  // Process in parallel with concurrency limit
  const batchSize = 10;
  for (let i = 0; i < pipelineIds.length; i += batchSize) {
    const batch = pipelineIds.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (id) => {
        try {
          const prediction = await predictNextUpdate(id);
          return { id, prediction };
        } catch (error) {
          console.error(`[Predictive Scheduler] Error predicting for pipeline ${id}:`, error);
          // Return default prediction
          const now = new Date();
          return {
            id,
            prediction: {
              predictedNextActivity: null,
              confidence: 0,
              recommendedUpdateTime: new Date(now.getTime() + 24 * 60 * 60 * 1000),
              urgency: 'low',
              peakActivityHour: null,
              averageIntervalHours: null
            }
          };
        }
      })
    );
    
    batchResults.forEach(({ id, prediction }) => {
      predictions.set(id, prediction as PredictiveSchedule);
    });
  }
  
  return predictions;
}

