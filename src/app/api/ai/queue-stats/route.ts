/**
 * AI Analysis Queue Statistics Endpoint
 * 
 * Provides real-time statistics about the analysis queue:
 * - Current queue size
 * - Processing status
 * - Performance metrics
 * - Health indicators
 */

import { NextResponse } from 'next/server';
import { getQueueStats, isQueueEnabled } from '@/lib/ai/analyze-contact-queued';

/**
 * Queue health status type
 */
type QueueHealth = 'healthy' | 'warning' | 'critical';

/**
 * Queue statistics response interface
 */
interface QueueStatsResponse {
  enabled: boolean;
  stats?: {
    currentQueueSize: number;
    processing: number;
    completed: number;
    failed: number;
    queueUtilization: number;
    health: QueueHealth;
    [key: string]: any; // Allow additional stats from getQueueStats
  };
  config?: {
    maxConcurrent: number;
    maxQueueSize: number;
    processInterval: number;
  };
  message?: string;
  timestamp: string;
}

/**
 * Calculate queue health based on utilization
 */
function calculateQueueHealth(utilization: number): QueueHealth {
  if (utilization >= 0.95) return 'critical';
  if (utilization >= 0.8) return 'warning';
  return 'healthy';
}

export async function GET() {
  const requestId = `queue-stats-${Date.now()}`;
  const startTime = Date.now();
  
  try {
    console.log(`[Queue Stats ${requestId}] Fetching queue statistics`);
    
    const queueEnabled = isQueueEnabled();
    
    if (!queueEnabled) {
      const response: QueueStatsResponse = {
        enabled: false,
        message: 'Analysis queue is disabled. Set USE_ANALYSIS_QUEUE=true to enable.',
        timestamp: new Date().toISOString(),
      };
      
      return NextResponse.json(response, {
        headers: {
          'Cache-Control': 'no-store, max-age=0',
        }
      });
    }

    // Get stats with error handling
    let stats;
    try {
      stats = getQueueStats();
    } catch (statsError) {
      console.error(`[Queue Stats ${requestId}] Error getting stats:`, statsError);
      throw new Error('Failed to retrieve queue statistics');
    }

    // Validate stats object
    if (!stats || typeof stats.currentQueueSize !== 'number') {
      throw new Error('Invalid queue statistics format');
    }

    // Calculate health indicators safely
    const maxQueueSize = parseInt(process.env.AI_ANALYSIS_QUEUE_MAX_SIZE || '1000', 10);
    const queueUtilization = Math.min(stats.currentQueueSize / maxQueueSize, 1); // Cap at 100%
    const health = calculateQueueHealth(queueUtilization);

    const response: QueueStatsResponse = {
      enabled: true,
      stats: {
        ...stats,
        queueUtilization: Math.round(queueUtilization * 100),
        health,
      },
      config: {
        maxConcurrent: parseInt(process.env.AI_ANALYSIS_QUEUE_CONCURRENCY || '10', 10),
        maxQueueSize,
        processInterval: parseInt(process.env.AI_ANALYSIS_QUEUE_INTERVAL || '100', 10),
      },
      timestamp: new Date().toISOString(),
    };

    const duration = Date.now() - startTime;
    console.log(`[Queue Stats ${requestId}] ✅ Stats retrieved in ${duration}ms (health: ${health})`);

    return NextResponse.json(response, {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      }
    });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    const duration = Date.now() - startTime;
    
    console.error(`[Queue Stats ${requestId}] ❌ Error after ${duration}ms:`, errorMsg);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch queue statistics',
        message: errorMsg,
        requestId,
        duration,
        timestamp: new Date().toISOString(),
      },
      { 
        status: 500,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
        }
      }
    );
  }
}









