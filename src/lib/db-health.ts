import { prisma } from './db';

/**
 * Connection pool health check utility
 * Use this to monitor database connection pool status
 */
export interface ConnectionPoolHealth {
  healthy: boolean;
  responseTime: number;
  timestamp: string;
  error?: string;
  errorCode?: string;
}

/**
 * Check if the database connection pool is healthy
 * @returns Health status with response time
 */
export async function checkConnectionPoolHealth(): Promise<ConnectionPoolHealth> {
  const start = Date.now();
  
  try {
    // Simple query to test connection availability
    await prisma.$queryRaw`SELECT 1 as health_check`;
    const duration = Date.now() - start;
    
    return {
      healthy: true,
      responseTime: duration,
      timestamp: new Date().toISOString()
    };
  } catch (error: any) {
    const duration = Date.now() - start;
    const isPoolExhausted = 
      error?.code === 'P2024' || 
      error?.message?.includes('pool') ||
      error?.message?.includes('Unable to check out process from the pool');
    
    return {
      healthy: false,
      responseTime: duration,
      timestamp: new Date().toISOString(),
      error: isPoolExhausted 
        ? 'Connection pool exhausted - all connections are in use' 
        : error?.message || 'Unknown database error',
      errorCode: error?.code
    };
  }
}

/**
 * Get connection pool statistics (if available)
 * Note: Prisma doesn't expose pool stats directly, but we can infer from errors
 */
export async function getConnectionPoolInfo() {
  const health = await checkConnectionPoolHealth();
  
  return {
    ...health,
    recommendations: !health.healthy && health.errorCode === 'P2024' 
      ? [
          'Increase connection_limit in DATABASE_URL',
          'Reduce concurrent database operations',
          'Optimize long-running queries',
          'Check for connection leaks (unclosed transactions)'
        ]
      : []
  };
}









