/**
 * Comprehensive Health Check System
 * 
 * Provides detailed health status for all critical backend services:
 * - Database connectivity
 * - AI service availability
 * - API key status
 * - Cache functionality
 * - Memory usage
 * - System resources
 */

import { prisma } from '@/lib/db';
import apiKeyManager from '@/lib/ai/api-key-manager';

export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  services: {
    database: ServiceHealth;
    aiService: ServiceHealth;
    apiKeys: ServiceHealth;
    memory: ServiceHealth;
  };
  metrics: {
    responseTimeMs: number;
    memoryUsageMB: number;
    uptime: number;
  };
}

export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  message: string;
  details?: Record<string, any>;
  latencyMs?: number;
}

/**
 * Perform comprehensive health check across all services
 */
export async function performHealthCheck(): Promise<HealthCheckResult> {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  // Run all health checks in parallel for speed
  const [dbHealth, aiHealth, apiKeyHealth, memoryHealth] = await Promise.allSettled([
    checkDatabaseHealth(),
    checkAIServiceHealth(),
    checkAPIKeyHealth(),
    checkMemoryHealth(),
  ]);

  const responseTimeMs = Date.now() - startTime;

  // Extract results from settled promises
  const database = dbHealth.status === 'fulfilled' ? dbHealth.value : createUnhealthyService('Database check failed');
  const aiService = aiHealth.status === 'fulfilled' ? aiHealth.value : createUnhealthyService('AI service check failed');
  const apiKeys = apiKeyHealth.status === 'fulfilled' ? apiKeyHealth.value : createUnhealthyService('API key check failed');
  const memory = memoryHealth.status === 'fulfilled' ? memoryHealth.value : createUnhealthyService('Memory check failed');

  // Determine overall status
  const allStatuses = [database.status, aiService.status, apiKeys.status, memory.status];
  const overallStatus = allStatuses.includes('unhealthy')
    ? 'unhealthy'
    : allStatuses.includes('degraded')
    ? 'degraded'
    : 'healthy';

  // Calculate metrics
  const memoryUsage = typeof process !== 'undefined' && process.memoryUsage
    ? process.memoryUsage().heapUsed / 1024 / 1024
    : 0;
  
  const uptime = typeof process !== 'undefined' && process.uptime
    ? Math.floor(process.uptime())
    : 0;

  return {
    status: overallStatus,
    timestamp,
    services: {
      database,
      aiService,
      apiKeys,
      memory,
    },
    metrics: {
      responseTimeMs,
      memoryUsageMB: Math.round(memoryUsage * 100) / 100,
      uptime,
    },
  };
}

/**
 * Check database connectivity and performance
 */
async function checkDatabaseHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
  
  try {
    // Simple connectivity test
    await prisma.$queryRaw`SELECT 1 as health_check`;
    
    const latencyMs = Date.now() - startTime;
    
    // Check connection pool status if available
    let poolInfo = {};
    try {
      const poolStats = await prisma.$queryRaw<Array<{ count: number }>>`
        SELECT count(*) as count 
        FROM pg_stat_activity 
        WHERE datname = current_database()
      `;
      poolInfo = { activeConnections: poolStats[0]?.count || 0 };
    } catch {
      // Ignore pool check errors
    }

    if (latencyMs > 1000) {
      return {
        status: 'degraded',
        message: 'Database responding slowly',
        latencyMs,
        details: { ...poolInfo, threshold: '1000ms' },
      };
    }

    return {
      status: 'healthy',
      message: 'Database connected',
      latencyMs,
      details: poolInfo,
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'Database connection failed',
      details: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

/**
 * Check AI service availability
 */
async function checkAIServiceHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
  
  try {
    // Check if AI model is configured
    const primaryModel = process.env.AI_PRIMARY_MODEL;
    if (!primaryModel) {
      return {
        status: 'degraded',
        message: 'AI model not configured',
        details: { missing: 'AI_PRIMARY_MODEL' },
      };
    }

    // Check if API keys are available
    const hasKey = !!(process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY);
    
    const latencyMs = Date.now() - startTime;

    if (!hasKey) {
      return {
        status: 'degraded',
        message: 'No AI API keys configured',
        latencyMs,
        details: { missing: 'NVIDIA_API_KEY or GOOGLE_AI_API_KEY' },
      };
    }

    return {
      status: 'healthy',
      message: 'AI service configured',
      latencyMs,
      details: { model: primaryModel },
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'AI service check failed',
      details: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

/**
 * Check API key manager status
 */
async function checkAPIKeyHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
  
  try {
    // Get next key to verify key rotation is working
    const key = await apiKeyManager.getNextKey({ operation: 'health-check' });
    
    const latencyMs = Date.now() - startTime;

    if (!key) {
      return {
        status: 'degraded',
        message: 'No active API keys available',
        latencyMs,
        details: { available: 0 },
      };
    }

    // Get stats if available
    let keyCount = 0;
    try {
      const { ApiKeyStatus } = await import('@prisma/client');
      const count = await prisma.apiKey.count({
        where: {
          status: ApiKeyStatus.ACTIVE,
        },
      });
      keyCount = count;
    } catch {
      // Ignore count errors
    }

    return {
      status: 'healthy',
      message: 'API keys available',
      latencyMs,
      details: { available: keyCount > 0 ? keyCount : 'unknown' },
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'API key check failed',
      details: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

/**
 * Check memory usage and system resources
 */
async function checkMemoryHealth(): Promise<ServiceHealth> {
  if (typeof process === 'undefined' || !process.memoryUsage) {
    return {
      status: 'healthy',
      message: 'Memory monitoring not available',
    };
  }

  try {
    const memUsage = process.memoryUsage();
    const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
    const heapTotalMB = memUsage.heapTotal / 1024 / 1024;
    const utilization = (heapUsedMB / heapTotalMB) * 100;

    if (utilization > 90) {
      return {
        status: 'unhealthy',
        message: 'Critical memory usage',
        details: {
          heapUsedMB: Math.round(heapUsedMB),
          heapTotalMB: Math.round(heapTotalMB),
          utilizationPercent: Math.round(utilization),
        },
      };
    }

    if (utilization > 75) {
      return {
        status: 'degraded',
        message: 'High memory usage',
        details: {
          heapUsedMB: Math.round(heapUsedMB),
          heapTotalMB: Math.round(heapTotalMB),
          utilizationPercent: Math.round(utilization),
        },
      };
    }

    return {
      status: 'healthy',
      message: 'Memory usage normal',
      details: {
        heapUsedMB: Math.round(heapUsedMB),
        heapTotalMB: Math.round(heapTotalMB),
        utilizationPercent: Math.round(utilization),
      },
    };
  } catch (error) {
    return {
      status: 'degraded',
      message: 'Memory check failed',
      details: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

/**
 * Helper to create an unhealthy service result
 */
function createUnhealthyService(message: string): ServiceHealth {
  return {
    status: 'unhealthy',
    message,
  };
}

