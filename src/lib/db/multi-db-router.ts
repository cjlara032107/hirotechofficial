import { PrismaClient } from '@prisma/client';
import { systemMonitor } from '../monitoring/system-monitor';

interface DatabaseConfig {
  client: PrismaClient;
  url: string;
  index: number;
  health: 'healthy' | 'degraded' | 'down';
  lastHealthCheck: number;
  connectionCount: number;
}

type RoutingStrategy = 'round-robin' | 'hash' | 'load-aware';

export class MultiDatabaseRouter {
  private databases: DatabaseConfig[] = [];
  private routingStrategy: RoutingStrategy;
  private roundRobinIndex = 0;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.routingStrategy = (process.env.DB_ROUTING_STRATEGY as RoutingStrategy) || 'hash';
    this.initializeDatabases();
    this.startHealthChecks();
  }

  private initializeDatabases() {
    const dbCount = parseInt(process.env.DB_COUNT || '5', 10);
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    const connectionLimit = isVercel ? 20 : 30; // Higher for multi-DB setup

    console.log(`[Multi-DB Router] 🚀 Initializing ${dbCount} databases...`);

    for (let i = 0; i < dbCount; i++) {
      const dbUrl = process.env[`DATABASE_URL_${i}`];
      const directUrl = process.env[`DIRECT_URL_${i}`];

      if (!dbUrl) {
        console.warn(`[Multi-DB Router] ⚠️ DATABASE_URL_${i} not set, skipping database ${i}`);
        continue;
      }

      // Enhance URL with connection pool settings
      const enhancedUrl = this.enhanceConnectionUrl(dbUrl, connectionLimit);

      const client = new PrismaClient({
        log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
        datasources: {
          db: {
            url: enhancedUrl,
          },
        },
      });

      // Add query monitoring
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      client.$on('query' as any, (e: any) => {
        const query = e.query || '';
        const duration = e.duration || 0;

        // Track query in system monitor
        systemMonitor.recordDatabaseQuery({
          query: query.substring(0, 500),
          duration,
          model: undefined,
          action: undefined,
          timestamp: Date.now(),
          success: true,
        });

        // Log slow queries
        if (process.env.NODE_ENV === 'development' && duration > 2000) {
          console.warn(
            `[Multi-DB Router] ⚠️ Slow query on DB${i} (${duration}ms):`,
            query.substring(0, 150) || 'N/A'
          );
        }
      });

      this.databases.push({
        client,
        url: enhancedUrl,
        index: i,
        health: 'healthy',
        lastHealthCheck: Date.now(),
        connectionCount: 0,
      });

      console.log(`[Multi-DB Router] ✅ Initialized database ${i + 1}/${dbCount}`);
    }

    if (this.databases.length === 0) {
      throw new Error('[Multi-DB Router] ❌ No databases configured! Set DATABASE_URL_0 at minimum.');
    }

    console.log(
      `[Multi-DB Router] ✅ Ready with ${this.databases.length} databases using ${this.routingStrategy} routing`
    );
  }

  private enhanceConnectionUrl(url: string, connectionLimit: number): string {
    if (url.includes('pooler.supabase.com') && !url.includes('connection_limit')) {
      const separator = url.includes('?') ? '&' : '?';
      return `${url}${separator}connection_limit=${connectionLimit}&pool_timeout=30&connect_timeout=30&statement_cache_size=0`;
    }
    return url;
  }

  /**
   * Get Prisma client based on routing strategy
   * @param key - Routing key (typically organizationId for hash-based routing)
   * @returns PrismaClient instance
   */
  getClient(key?: string): PrismaClient {
    const healthy = this.getHealthyDatabases();
    
    if (healthy.length === 0) {
      console.error('[Multi-DB Router] ❌ No healthy databases available, using first database as fallback');
      return this.databases[0]?.client || this.createFallbackClient();
    }

    switch (this.routingStrategy) {
      case 'round-robin':
        return this.getClientRoundRobin(healthy);
      case 'hash':
        if (!key) {
          console.warn('[Multi-DB Router] ⚠️ Hash routing requires key, falling back to round-robin');
          return this.getClientRoundRobin(healthy);
        }
        return this.getClientHash(key, healthy);
      case 'load-aware':
        return this.getClientLoadAware(healthy);
      default:
        return this.getClientRoundRobin(healthy);
    }
  }

  private getClientRoundRobin(healthy: DatabaseConfig[]): PrismaClient {
    const db = healthy[this.roundRobinIndex % healthy.length];
    this.roundRobinIndex = (this.roundRobinIndex + 1) % healthy.length;
    return db.client;
  }

  private getClientHash(key: string, healthy: DatabaseConfig[]): PrismaClient {
    const hash = this.hashString(key);
    const index = hash % healthy.length;
    return healthy[index].client;
  }

  private getClientLoadAware(healthy: DatabaseConfig[]): PrismaClient {
    // Sort by connection count (lowest first)
    const sorted = [...healthy].sort((a, b) => a.connectionCount - b.connectionCount);
    return sorted[0].client;
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }

  private getHealthyDatabases(): DatabaseConfig[] {
    return this.databases.filter(db => db.health === 'healthy' || db.health === 'degraded');
  }

  private createFallbackClient(): PrismaClient {
    console.error('[Multi-DB Router] ❌ Creating fallback client from DATABASE_URL');
    const fallbackUrl = process.env.DATABASE_URL || '';
    return new PrismaClient({
      datasources: { db: { url: fallbackUrl } }
    });
  }

  /**
   * Health check for all databases
   */
  private async startHealthChecks() {
    const checkHealth = async (db: DatabaseConfig, retries = 2) => {
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const startTime = Date.now();
          // Use a timeout to prevent hanging
          const queryPromise = db.client.$queryRaw`SELECT 1`;
          const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Health check timeout')), 5000)
          );
          
          await Promise.race([queryPromise, timeoutPromise]);
          const duration = Date.now() - startTime;

          if (duration > 2000) {
            db.health = 'degraded';
            console.warn(`[Multi-DB Router] ⚠️ Database ${db.index} is slow (${duration}ms)`);
          } else {
            db.health = 'healthy';
          }
          db.lastHealthCheck = Date.now();
          return; // Success, exit retry loop
        } catch (error: any) {
          const isConnectionError = 
            error?.code === 'P1001' ||
            error?.message?.includes("Can't reach database") ||
            error?.message?.includes('timeout') ||
            error?.message?.includes('Health check timeout');
          
          if (attempt === retries) {
            // Final attempt failed
            if (isConnectionError) {
              // Only log connection errors, not all errors (to reduce noise)
              console.warn(
                `[Multi-DB Router] ⚠️ Database ${db.index} unavailable (connection issue). ` +
                `Will retry on next health check. App will use available databases.`
              );
            }
            db.health = 'down';
            db.lastHealthCheck = Date.now();
          } else {
            // Wait before retry (exponential backoff)
            await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
          }
        }
      }
    };

    // Initial health check with delay to allow connections to establish
    setTimeout(async () => {
      for (const db of this.databases) {
        await checkHealth(db);
      }
    }, 2000); // 2 second delay for initial connections

    // Periodic health checks every 30 seconds
    this.healthCheckInterval = setInterval(async () => {
      for (const db of this.databases) {
        await checkHealth(db);
      }
    }, 30000);
  }

  /**
   * Get router status
   */
  getStatus() {
    const healthy = this.databases.filter(d => d.health === 'healthy').length;
    const degraded = this.databases.filter(d => d.health === 'degraded').length;
    const down = this.databases.filter(d => d.health === 'down').length;

    return {
      totalDatabases: this.databases.length,
      healthyDatabases: healthy,
      degradedDatabases: degraded,
      downDatabases: down,
      routingStrategy: this.routingStrategy,
      databases: this.databases.map(db => ({
        index: db.index,
        health: db.health,
        lastHealthCheck: db.lastHealthCheck,
        connectionCount: db.connectionCount,
      })),
    };
  }

  /**
   * Cleanup - disconnect all clients
   */
  async disconnect() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    await Promise.all(
      this.databases.map(db => 
        db.client.$disconnect().catch(err => 
          console.error(`[Multi-DB Router] Error disconnecting DB${db.index}:`, err)
        )
      )
    );
  }
}

// Singleton instance
let routerInstance: MultiDatabaseRouter | null = null;

export function getDatabaseRouter(): MultiDatabaseRouter {
  if (!routerInstance) {
    routerInstance = new MultiDatabaseRouter();
  }
  return routerInstance;
}

/**
 * Get Prisma client with automatic routing
 * @param key - Routing key (organizationId recommended for hash-based routing)
 * @returns PrismaClient instance
 */
export function getPrisma(key?: string): PrismaClient {
  return getDatabaseRouter().getClient(key);
}

/**
 * Ensure connection for multi-DB router (compatibility with existing connectPrisma)
 */
export async function connectPrisma(maxRetries = 3, retryDelay = 1000) {
  const router = getDatabaseRouter();
  const status = router.getStatus();

  if (status.healthyDatabases === 0) {
    throw new Error('[Multi-DB Router] No healthy databases available');
  }

  // Try to connect to first healthy database to verify connectivity
  const healthy = router.getStatus().databases.filter(d => d.health === 'healthy');
  if (healthy.length > 0) {
    const testClient = router.getClient();
    try {
      await testClient.$queryRaw`SELECT 1`;
      return;
    } catch (error) {
      if (maxRetries > 0) {
        await new Promise(resolve => setTimeout(resolve, retryDelay));
        return connectPrisma(maxRetries - 1, retryDelay * 2);
      }
      throw error;
    }
  }
}

