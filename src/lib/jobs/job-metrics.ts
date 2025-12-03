/**
 * Job Metrics Calculator
 * 
 * Calculates performance metrics for jobs:
 * - Job completion time (duration)
 * - Contacts processed per second
 * - AI analysis success rate
 * - API call success rate
 */

import { performanceMonitor } from '@/lib/ai/performance-monitor';

export interface JobMetrics {
  durationMs?: number;
  contactsPerSecond?: number;
  aiSuccessRate?: number;
  apiSuccessRate?: number;
}

export interface JobCompletionData {
  startedAt: Date | null;
  completedAt: Date;
  totalContacts: number;
  processedContacts: number; // analyzedContacts or syncedContacts
  failedContacts: number;
  aiSuccessCount?: number; // For analysis jobs
  aiFailureCount?: number; // For analysis jobs
  apiSuccessCount?: number; // For jobs with API calls
  apiFailureCount?: number; // For jobs with API calls
}

/**
 * Calculate job completion metrics
 */
export function calculateJobMetrics(data: JobCompletionData): JobMetrics {
  const metrics: JobMetrics = {};

  // 1. Calculate job completion time (duration)
  if (data.startedAt && data.completedAt) {
    const durationMs = data.completedAt.getTime() - data.startedAt.getTime();
    metrics.durationMs = Math.max(0, durationMs);
  }

  // 2. Calculate contacts processed per second
  if (metrics.durationMs && metrics.durationMs > 0 && data.processedContacts > 0) {
    const durationSeconds = metrics.durationMs / 1000;
    metrics.contactsPerSecond = data.processedContacts / durationSeconds;
  }

  // 3. Calculate AI analysis success rate (for analysis jobs)
  if (data.aiSuccessCount !== undefined && data.aiFailureCount !== undefined) {
    const totalAiAttempts = data.aiSuccessCount + data.aiFailureCount;
    if (totalAiAttempts > 0) {
      metrics.aiSuccessRate = (data.aiSuccessCount / totalAiAttempts) * 100;
    }
  }

  // 4. Calculate API call success rate
  if (data.apiSuccessCount !== undefined && data.apiFailureCount !== undefined) {
    const totalApiCalls = data.apiSuccessCount + data.apiFailureCount;
    if (totalApiCalls > 0) {
      metrics.apiSuccessRate = (data.apiSuccessCount / totalApiCalls) * 100;
    }
  }

  return metrics;
}

/**
 * Get API call metrics for a job time period
 */
export function getApiMetricsForPeriod(
  startTime: Date | null,
  endTime: Date
): { successCount: number; failureCount: number } {
  if (!startTime) {
    return { successCount: 0, failureCount: 0 };
  }

  const startTimestamp = startTime.getTime();
  const endTimestamp = endTime.getTime();

  // Get metrics for the job time period from performance monitor
  const metrics = performanceMonitor.getMetricsForPeriod(startTimestamp, endTimestamp);
  
  let successCount = 0;
  let failureCount = 0;
  
  for (const metric of metrics) {
    if (metric.success) {
      successCount++;
    } else {
      failureCount++;
    }
  }

  return { successCount, failureCount };
}

/**
 * Format duration for display
 */
export function formatDuration(ms?: number): string {
  if (!ms) return 'N/A';
  
  if (ms < 1000) {
    return `${ms}ms`;
  } else if (ms < 60000) {
    return `${(ms / 1000).toFixed(1)}s`;
  } else {
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  }
}

/**
 * Format rate for display
 */
export function formatRate(rate?: number, unit: string = '/s'): string {
  if (rate === undefined || rate === null) return 'N/A';
  return `${rate.toFixed(2)}${unit}`;
}

/**
 * Format percentage for display
 */
export function formatPercentage(value?: number): string {
  if (value === undefined || value === null) return 'N/A';
  return `${value.toFixed(1)}%`;
}

