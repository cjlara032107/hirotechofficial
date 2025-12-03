/**
 * Queue Health Check Utility
 * 
 * Provides health check functions for the analysis queue
 */

import { getQueueStats, isQueueEnabled } from './analyze-contact-queued';

export interface QueueHealthStatus {
  healthy: boolean;
  status: 'healthy' | 'warning' | 'critical';
  message: string;
  details: {
    queueSize: number;
    queueUtilization: number;
    processing: number;
    averageWaitTime: number;
    averageProcessTime: number;
  };
}

/**
 * Check queue health
 */
export function checkQueueHealth(): QueueHealthStatus {
  if (!isQueueEnabled()) {
    return {
      healthy: true,
      status: 'healthy',
      message: 'Queue is disabled (not in use)',
      details: {
        queueSize: 0,
        queueUtilization: 0,
        processing: 0,
        averageWaitTime: 0,
        averageProcessTime: 0,
      },
    };
  }

  const stats = getQueueStats();
  const maxQueueSize = parseInt(process.env.AI_ANALYSIS_QUEUE_MAX_SIZE || '1000', 10);
  const queueUtilization = stats.currentQueueSize / maxQueueSize;

  let status: 'healthy' | 'warning' | 'critical' = 'healthy';
  let healthy = true;
  let message = 'Queue is operating normally';

  if (queueUtilization >= 0.95) {
    status = 'critical';
    healthy = false;
    message = `Queue is critically full (${Math.round(queueUtilization * 100)}% utilization). Consider increasing queue size or processing capacity.`;
  } else if (queueUtilization >= 0.8) {
    status = 'warning';
    message = `Queue is getting full (${Math.round(queueUtilization * 100)}% utilization). Monitor closely.`;
  }

  // Check for high wait times
  if (stats.averageWaitTime > 60000) { // > 1 minute
    status = status === 'critical' ? 'critical' : 'warning';
    healthy = false;
    message += ` High average wait time: ${Math.round(stats.averageWaitTime / 1000)}s`;
  }

  return {
    healthy,
    status,
    message,
    details: {
      queueSize: stats.currentQueueSize,
      queueUtilization: Math.round(queueUtilization * 100),
      processing: stats.currentProcessing,
      averageWaitTime: stats.averageWaitTime,
      averageProcessTime: stats.averageProcessTime,
    },
  };
}









