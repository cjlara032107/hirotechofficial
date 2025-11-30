/**
 * Intelligent Pipeline Updater
 * Orchestrates all advanced update strategies:
 * - Multi-factor activity scoring
 * - Adaptive thresholds
 * - Cost-benefit analysis
 * - Predictive scheduling
 * - Smart queue management with dynamic concurrency
 */

import { prisma } from '@/lib/db';
import { getCachedConcurrencyLimits } from '@/lib/ai/dynamic-concurrency';
import { startPipelineAnalysis } from '@/lib/facebook/pipeline-analyzer';
import { calculateActivityScore, calculateActivityScoresBatch, type ActivityScore } from './activity-scorer';
import { calculateAdaptiveThresholds, applyAdaptiveThresholds, type AdaptiveThresholds } from './adaptive-thresholds';
import { analyzeCostBenefit, analyzeCostBenefitBatch, type UpdateCostBenefit } from './cost-benefit-analyzer';
import { predictNextUpdate, predictNextUpdatesBatch, type PredictiveSchedule } from './predictive-scheduler';
import type { Pipeline, Contact, PipelineStage } from '@prisma/client';

interface QueuedUpdate {
  pipelineId: string;
  priority: 'high' | 'medium' | 'low' | 'paused';
  scheduledTime: Date;
  activityScore: ActivityScore;
  costBenefit: UpdateCostBenefit;
  prediction: PredictiveSchedule;
  thresholds: AdaptiveThresholds;
  facebookPageId: string | null;
}

interface UpdateResult {
  pipelineId: string;
  success: boolean;
  error?: string;
  contactsProcessed?: number;
  duration?: number;
}

interface QueueStatus {
  total: number;
  high: number;
  medium: number;
  low: number;
  paused: number;
  ready: number;
}

export class IntelligentPipelineUpdater {
  private queue: Map<string, QueuedUpdate> = new Map();
  private activityScores: Map<string, ActivityScore> = new Map();
  private concurrencyLimits: Awaited<ReturnType<typeof getCachedConcurrencyLimits>> | null = null;

  /**
   * Main entry point: Schedule updates for all active pipelines
   */
  async scheduleUpdates(): Promise<{
    scheduled: number;
    skipped: number;
    queueStatus: QueueStatus;
  }> {
    console.log('[Intelligent Updater] Starting update scheduling...');

    // Get all active pipelines with their Facebook pages
    const pipelines = await prisma.pipeline.findMany({
      where: { 
        isArchived: false 
      },
      include: { 
        contacts: {
          select: {
            id: true,
            leadScore: true,
            stageId: true,
            updatedAt: true
          }
        },
        stages: true,
        facebookPages: {
          select: {
            id: true,
            autoPipelineId: true
          }
        }
      }
    });

    console.log(`[Intelligent Updater] Found ${pipelines.length} active pipelines`);

    // Get current concurrency limits
    this.concurrencyLimits = await getCachedConcurrencyLimits();

    // Calculate activity scores for all pipelines in parallel (batched)
    const pipelineIds = pipelines.map(p => p.id);
    const activityScores = await calculateActivityScoresBatch(pipelineIds);
    this.activityScores = activityScores;

    // Calculate cost-benefit for all pipelines
    const costBenefits = await analyzeCostBenefitBatch(activityScores);

    // Get predictions for all pipelines
    const predictions = await predictNextUpdatesBatch(pipelineIds);

    let scheduled = 0;
    let skipped = 0;

    // Process each pipeline
    for (const pipeline of pipelines) {
      const activityScore = activityScores.get(pipeline.id);
      const costBenefit = costBenefits.get(pipeline.id);
      const prediction = predictions.get(pipeline.id);

      if (!activityScore || !costBenefit || !prediction) {
        console.warn(`[Intelligent Updater] Missing data for pipeline ${pipeline.id}`);
        skipped++;
        continue;
      }

      // Calculate adaptive thresholds
      const thresholds = calculateAdaptiveThresholds(pipeline as any);
      
      // Apply adaptive thresholds to activity score
      const adjusted = applyAdaptiveThresholds(activityScore, thresholds);

      // Determine if should update
      if (!activityScore.shouldUpdate || !costBenefit.shouldProceed) {
        console.log(`[Intelligent Updater] Skipping pipeline ${pipeline.id} - shouldUpdate: ${activityScore.shouldUpdate}, shouldProceed: ${costBenefit.shouldProceed}`);
        skipped++;
        continue;
      }

      // Find associated Facebook page
      const facebookPage = pipeline.facebookPages.find(
        page => page.autoPipelineId === pipeline.id
      );

      if (!facebookPage) {
        console.log(`[Intelligent Updater] Pipeline ${pipeline.id} has no associated Facebook page`);
        skipped++;
        continue;
      }

      // Calculate optimal update time
      const now = new Date();
      let nextUpdateTime = new Date(
        now.getTime() + adjusted.adjustedInterval * 60 * 1000
      );

      // Adjust based on prediction if confidence is high
      if (prediction.confidence >= 0.7 && prediction.recommendedUpdateTime > now) {
        const predictedTime = prediction.recommendedUpdateTime.getTime();
        const calculatedTime = nextUpdateTime.getTime();
        
        // Use prediction if it's sooner or within 2 hours of calculated time
        if (predictedTime < calculatedTime || (predictedTime - calculatedTime) < 2 * 60 * 60 * 1000) {
          nextUpdateTime = prediction.recommendedUpdateTime;
        }
      }

      // Enqueue with adjusted priority
      this.queue.set(pipeline.id, {
        pipelineId: pipeline.id,
        priority: adjusted.adjustedPriority,
        scheduledTime: nextUpdateTime,
        activityScore,
        costBenefit,
        prediction,
        thresholds,
        facebookPageId: facebookPage.id
      });

      scheduled++;
    }

    const queueStatus = this.getQueueStatus();

    console.log(`[Intelligent Updater] Scheduled ${scheduled} updates, skipped ${skipped}`);
    console.log(`[Intelligent Updater] Queue status:`, queueStatus);

    return {
      scheduled,
      skipped,
      queueStatus
    };
  }

  /**
   * Process the queue and execute updates respecting concurrency limits
   */
  async processQueue(): Promise<UpdateResult[]> {
    console.log('[Intelligent Updater] Processing queue...');

    // Get ready updates (scheduled time has passed)
    const now = new Date();
    const readyUpdates = Array.from(this.queue.values())
      .filter(item => item.scheduledTime <= now && item.priority !== 'paused')
      .sort((a, b) => {
        // Sort by priority, then by scheduled time
        const priorityOrder = { high: 0, medium: 1, low: 2, paused: 3 };
        const priorityDiff = priorityOrder[a.priority] - priorityOrder[b.priority];
        if (priorityDiff !== 0) return priorityDiff;
        return a.scheduledTime.getTime() - b.scheduledTime.getTime();
      });

    if (readyUpdates.length === 0) {
      console.log('[Intelligent Updater] No updates ready to process');
      return [];
    }

    // Get concurrency limits
    if (!this.concurrencyLimits) {
      this.concurrencyLimits = await getCachedConcurrencyLimits();
    }

    // Use 70% of available analysis concurrency for pipeline updates
    // This leaves 30% for other operations
    const maxConcurrent = Math.max(1, Math.floor(this.concurrencyLimits.analysisConcurrency * 0.7));

    console.log(`[Intelligent Updater] Processing ${Math.min(readyUpdates.length, maxConcurrent)} updates (max concurrent: ${maxConcurrent})`);

    // Process up to concurrency limit
    const toProcess = readyUpdates.slice(0, maxConcurrent);
    
    const results = await Promise.allSettled(
      toProcess.map(item => this.executeUpdate(item))
    );

    // Process results
    const updateResults: UpdateResult[] = [];
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        updateResults.push(result.value);
      } else {
        const item = toProcess[index];
        updateResults.push({
          pipelineId: item.pipelineId,
          success: false,
          error: result.reason?.message || 'Unknown error'
        });
      }
    });

    // Remove processed items from queue
    updateResults.forEach(result => {
      if (result.success || result.error) {
        this.queue.delete(result.pipelineId);
      }
    });

    return updateResults;
  }

  /**
   * Execute a single pipeline update
   */
  private async executeUpdate(item: QueuedUpdate): Promise<UpdateResult> {
    const startTime = Date.now();
    console.log(`[Intelligent Updater] Executing update for pipeline ${item.pipelineId}`);

    try {
      if (!item.facebookPageId) {
        throw new Error('No Facebook page associated with pipeline');
      }

      // Start pipeline analysis
      const result = await startPipelineAnalysis(
        item.facebookPageId,
        false // Don't force update existing - let the system decide
      );

      const duration = Date.now() - startTime;

      console.log(`[Intelligent Updater] Update completed for pipeline ${item.pipelineId} in ${duration}ms (jobId: ${result.jobId})`);

      // Note: Pipeline analysis runs asynchronously, so we don't have contact count here
      // The jobId can be used to track progress via the sync job status
      return {
        pipelineId: item.pipelineId,
        success: result.success,
        contactsProcessed: 0, // Will be updated when job completes
        duration
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      console.error(`[Intelligent Updater] Update failed for pipeline ${item.pipelineId}:`, errorMessage);

      return {
        pipelineId: item.pipelineId,
        success: false,
        error: errorMessage,
        duration
      };
    }
  }

  /**
   * Get current queue status
   */
  getQueueStatus(): QueueStatus {
    const items = Array.from(this.queue.values());
    const now = new Date();

    return {
      total: items.length,
      high: items.filter(i => i.priority === 'high').length,
      medium: items.filter(i => i.priority === 'medium').length,
      low: items.filter(i => i.priority === 'low').length,
      paused: items.filter(i => i.priority === 'paused').length,
      ready: items.filter(i => i.scheduledTime <= now && i.priority !== 'paused').length
    };
  }

  /**
   * Get update recommendation for a specific pipeline
   */
  async getUpdateRecommendation(pipelineId: string): Promise<{
    activityScore: ActivityScore;
    costBenefit: UpdateCostBenefit;
    prediction: PredictiveSchedule;
    thresholds: AdaptiveThresholds;
    recommendation: 'update' | 'skip' | 'schedule';
    recommendedTime: Date | null;
  } | null> {
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
        },
        stages: true
      }
    });

    if (!pipeline) {
      return null;
    }

    const activityScore = await calculateActivityScore(pipelineId);
    const costBenefit = await analyzeCostBenefit(pipelineId, activityScore);
    const prediction = await predictNextUpdate(pipelineId);
    const thresholds = calculateAdaptiveThresholds(pipeline as any);
    const adjusted = applyAdaptiveThresholds(activityScore, thresholds);

    let recommendation: 'update' | 'skip' | 'schedule';
    let recommendedTime: Date | null = null;

    if (!activityScore.shouldUpdate || !costBenefit.shouldProceed) {
      recommendation = 'skip';
    } else if (adjusted.adjustedPriority === 'high') {
      recommendation = 'update';
      recommendedTime = new Date();
    } else {
      recommendation = 'schedule';
      recommendedTime = new Date(Date.now() + adjusted.adjustedInterval * 60 * 1000);
      
      // Adjust based on prediction
      if (prediction.confidence >= 0.7 && prediction.recommendedUpdateTime > new Date()) {
        recommendedTime = prediction.recommendedUpdateTime;
      }
    }

    return {
      activityScore,
      costBenefit,
      prediction,
      thresholds,
      recommendation,
      recommendedTime
    };
  }
}

/**
 * Singleton instance
 */
let updaterInstance: IntelligentPipelineUpdater | null = null;

export function getIntelligentUpdater(): IntelligentPipelineUpdater {
  if (!updaterInstance) {
    updaterInstance = new IntelligentPipelineUpdater();
  }
  return updaterInstance;
}

