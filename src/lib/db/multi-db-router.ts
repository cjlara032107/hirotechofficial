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
    
    // Log initialization summary
    if (this.databases.length === 0) {
      throw new Error('[Multi-DB Router] ❌ No databases configured! Set DATABASE_URL_0 at minimum.');
    }
    
    if (this.databases.length === 1) {
      console.log('[Multi-DB Router] ℹ️  Only 1 database configured - effectively single-DB mode');
    }
  }

  private initializeDatabases() {
    // Skip if already initialized
    if (this.databases.length > 0) {
      return;
    }
    
    // Only initialize databases that are actually configured
    // Count how many DATABASE_URL_X variables are set
    let maxDbIndex = -1;
    const configuredDatabases: number[] = [];
    
    for (let i = 0; i < 10; i++) { // Check up to 10 databases
      if (process.env[`DATABASE_URL_${i}`]) {
        maxDbIndex = i;
        configuredDatabases.push(i);
      }
    }
    
    const dbCount = configuredDatabases.length; // Number of databases actually configured
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    const connectionLimit = isVercel ? 20 : 30; // Higher for multi-DB setup

    if (dbCount === 0) {
      throw new Error('[Multi-DB Router] ❌ No databases configured! Set DATABASE_URL_0 at minimum.');
    }

    console.log(`[Multi-DB Router] 🚀 Initializing ${dbCount} database(s)...`);

    // Only initialize databases that are configured (skip gaps)
    for (const i of configuredDatabases) {
      const dbUrl = process.env[`DATABASE_URL_${i}`];
      const directUrl = process.env[`DIRECT_URL_${i}`];

      if (!dbUrl) {
        // Should not happen since we only iterate configured ones, but safety check
        console.warn(`[Multi-DB Router] ⚠️ DATABASE_URL_${i} is not set, skipping`);
        continue;
      }

      // Validate connection string format
      if (!dbUrl.startsWith('postgresql://') && !dbUrl.startsWith('postgres://')) {
        console.error(`[Multi-DB Router] ❌ Invalid DATABASE_URL_${i} format (must start with postgresql:// or postgres://)`);
        continue; // Skip invalid URLs
      }

      try {
        // Enhance URL with connection pool settings
        const enhancedUrl = this.enhanceConnectionUrl(dbUrl, connectionLimit);

        // Suppress Prisma connection errors during initialization
        // They will be caught by health checks instead
        const client = new PrismaClient({
          log: [], // Suppress logs - we'll handle errors via health checks
          datasources: {
            db: {
              url: enhancedUrl,
            },
          },
        });

        // Add query monitoring
        // Note: Prisma $on('query') is not available in all versions
        // Using type assertion to handle version differences
        try {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (client as any).$on?.('query', (e: { query?: string; duration?: number }) => {
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
        } catch {
          // Query monitoring not available in this Prisma version
          // Continue without monitoring
        }

        this.databases.push({
          client,
          url: enhancedUrl,
          index: i,
          health: 'healthy',
          lastHealthCheck: Date.now(),
          connectionCount: 0,
        });

        console.log(`[Multi-DB Router] ✅ Initialized database ${i + 1}/${dbCount}`);
      } catch (error: any) {
        // Log error but continue with other databases
        console.error(
          `[Multi-DB Router] ❌ Failed to initialize database ${i}:`,
          error?.message || String(error)
        );
        // Don't add this database to the list - it will be skipped
        // This prevents PrismaClientInitializationError from propagating
      }
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
      const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
      // Increase timeouts for Vercel serverless (cold starts, network latency)
      // pool_timeout: how long to wait for a connection from the pool
      // connect_timeout: how long to wait for initial connection
      // Reduced timeouts to fail faster and prevent hanging
      const poolTimeout = isVercel ? 30 : 20; // 30s for Vercel (reduced from 60s), 20s for traditional
      const connectTimeout = isVercel ? 30 : 20; // 30s for Vercel (reduced from 60s), 20s for traditional
      return `${url}${separator}connection_limit=${connectionLimit}&pool_timeout=${poolTimeout}&connect_timeout=${connectTimeout}&statement_cache_size=0`;
    }
    return url;
  }

  /**
   * Get Prisma client based on routing strategy
   * @param key - Routing key (typically organizationId for hash-based routing)
   * @returns PrismaClient instance
   */
  getClient(key?: string): PrismaClient {
    // ALWAYS try to use all databases - don't exclude any
    // Health checks are advisory - databases might work even if health check fails
    // This ensures all configured databases are used, even if health checks fail
    const allDatabases = this.databases;
    
    if (allDatabases.length === 0) {
      return this.createFallbackClient();
    }
    
    // Prefer healthy databases when available, but always include all databases
    // This way, even if health check fails, we still try to use the database
    const healthyDatabases = this.getHealthyDatabases();
    // Use healthy databases if available, otherwise use all (they might work despite health check)
    const databasesToUse = healthyDatabases.length > 0 ? healthyDatabases : allDatabases;

    // Use routing strategy - always try to use all configured databases
    // Health checks are advisory - databases might work even if health check fails
    switch (this.routingStrategy) {
      case 'round-robin':
        return this.getClientRoundRobin(databasesToUse);
      case 'hash':
        if (!key) {
          console.warn('[Multi-DB Router] ⚠️ Hash routing requires key, falling back to round-robin');
          return this.getClientRoundRobin(databasesToUse);
        }
        return this.getClientHash(key, databasesToUse);
      case 'load-aware':
        return this.getClientLoadAware(databasesToUse);
      default:
        return this.getClientRoundRobin(databasesToUse);
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

  /**
   * Get all available databases for parallel routing
   * Returns all databases regardless of health status
   * Health checks are advisory - databases might work even if marked as down
   */
  private getAllAvailableDatabases(): DatabaseConfig[] {
    // Return ALL databases - don't exclude any
    // Health checks are advisory only - databases can still work even if health check fails
    return this.databases;
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
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    // Use much shorter timeout for health checks to fail fast and not block
    const healthCheckTimeout = isVercel ? 5000 : 3000; // 5s for Vercel, 3s for traditional (reduced from 15s/8s)
    
    const checkHealth = async (db: DatabaseConfig, retries = 1, silent = false) => {
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const startTime = Date.now();
          // Use a timeout to prevent hanging - fail fast
          const queryPromise = db.client.$queryRaw`SELECT 1`;
          const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Health check timeout')), healthCheckTimeout)
          );
          
          await Promise.race([queryPromise, timeoutPromise]);
          const duration = Date.now() - startTime;

          // Increase slow threshold to 5s (was 2s) to reduce false positives
          if (duration > 5000) {
            const wasHealthy = db.health === 'healthy';
            db.health = 'degraded';
            if (!silent) {
              console.warn(`[Multi-DB Router] ⚠️ Database ${db.index} is slow (${duration}ms)`);
            }
          } else {
            const wasUnhealthy = db.health === 'degraded' || db.health === 'down';
            db.health = 'healthy';
            // Only log success if it was previously unhealthy
            if (wasUnhealthy && !silent) {
              console.log(`[Multi-DB Router] ✅ Database ${db.index} is now healthy`);
            }
          }
          db.lastHealthCheck = Date.now();
          return; // Success, exit retry loop
        } catch (error: any) {
          const isConnectionError = 
            error?.code === 'P1001' ||
            error?.message?.includes("Can't reach database") ||
            error?.message?.includes('timeout') ||
            error?.message?.includes('Health check timeout') ||
            error?.message?.includes('Unable to check out process from the pool');
          
          if (attempt === retries) {
            // Final attempt failed - mark as degraded (not down) so it's still used
            // Databases might work even if health check fails (network issues, etc.)
            const wasHealthy = db.health === 'healthy';
            db.health = 'degraded';
            db.lastHealthCheck = Date.now();
            
            // Only log if it was previously healthy (to avoid spam)
            if (!silent && wasHealthy) {
              console.warn(
                `[Multi-DB Router] ⚠️ Database ${db.index} health check failed. ` +
                `Marking as degraded but will still be used. Will retry on next health check.`
              );
            }
          } else {
            // Wait before retry (shorter delay)
            await new Promise(resolve => setTimeout(resolve, 200 * (attempt + 1)));
          }
        }
      }
    };

    // Initial health check with delay to allow connections to establish
    // Use shorter delay for serverless to start faster
    const initialDelay = isVercel ? 2000 : 1000; // 2 seconds for Vercel, 1 for local (reduced)
    
    // Run initial health check asynchronously (non-blocking)
    setTimeout(async () => {
      // Run health checks in parallel but don't wait for all
      const healthCheckPromises = this.databases.map(db => 
        checkHealth(db, 1, true).catch(() => {
          // Silently fail - health checks are advisory
        })
      );
      
      // Don't await - let them run in background
      Promise.all(healthCheckPromises).then(() => {
        const healthy = this.databases.filter(d => d.health === 'healthy').length;
        const degraded = this.databases.filter(d => d.health === 'degraded').length;
        
        if (healthy > 0) {
          console.log(`[Multi-DB Router] ✅ Health check complete: ${healthy} healthy, ${degraded} degraded`);
        } else if (this.databases.length > 0) {
          console.warn(`[Multi-DB Router] ⚠️ No healthy databases found. Using all databases (health checks are advisory).`);
        }
      });
    }, initialDelay);

    // Periodic health checks every 60 seconds (increased from 30s to reduce load)
    // Check all databases to detect recovery
    this.healthCheckInterval = setInterval(async () => {
      // Run health checks in parallel but don't block
      const healthCheckPromises = this.databases.map(db => {
        const isSilent = db.health === 'degraded';
        return checkHealth(db, 1, isSilent).catch(() => {
          // Silently fail - health checks are advisory
        });
      });
      
      // Don't await - let them run in background
      Promise.all(healthCheckPromises);
    }, 60000); // Check every 60 seconds (reduced frequency)
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
   * Get all database configs (including client) for internal use
   */
  getAllDatabaseConfigs(): DatabaseConfig[] {
    return this.databases;
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

// Singleton instance with global caching to prevent re-initialization
declare global {
  // eslint-disable-next-line no-var
  var multiDbRouterInstance: MultiDatabaseRouter | undefined;
}

// Module-level cache as fallback (persists across requests in Node.js)
let moduleLevelRouterInstance: MultiDatabaseRouter | null = null;

export function getDatabaseRouter(): MultiDatabaseRouter {
  // First check globalThis (works in Node.js and persists across requests)
  if (typeof globalThis !== 'undefined' && globalThis.multiDbRouterInstance) {
    return globalThis.multiDbRouterInstance;
  }
  
  // Fallback to module-level cache (for edge cases where globalThis is reset)
  if (moduleLevelRouterInstance) {
    // Restore to globalThis if it exists
    if (typeof globalThis !== 'undefined') {
      globalThis.multiDbRouterInstance = moduleLevelRouterInstance;
    }
    return moduleLevelRouterInstance;
  }
  
  // Create new instance only if none exists
  const instance = new MultiDatabaseRouter();
  
  // Cache in both places
  if (typeof globalThis !== 'undefined') {
    globalThis.multiDbRouterInstance = instance;
  }
  moduleLevelRouterInstance = instance;
  
  return instance;
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
 * More resilient - tries all databases, not just "healthy" ones
 */
export async function connectPrisma(maxRetries = 5, retryDelay = 1000) {
  const router = getDatabaseRouter();
  const status = router.getStatus();

  // If no databases configured at all, throw error
  if (status.databases.length === 0) {
    throw new Error('[Multi-DB Router] No databases configured! Set DATABASE_URL_0 at minimum.');
  }

  // Get the actual database configs from the router (not from getStatus which doesn't include client)
  const routerDatabases = router.getAllDatabaseConfigs();
  
  if (routerDatabases.length === 0) {
    throw new Error('[Multi-DB Router] No databases initialized! Check DATABASE_URL_X configuration.');
  }

  // In serverless, try ALL databases regardless of health status
  // Health checks might not have completed yet or might be unreliable
  const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
  const healthy = routerDatabases.filter((d: DatabaseConfig) => d.health === 'healthy');
  const degraded = routerDatabases.filter((d: DatabaseConfig) => d.health === 'degraded');
  
  // For Vercel/serverless: try healthy first, then degraded, then all
  // For local: prefer healthy, fallback to all
  const databasesToTry = isVercel 
    ? (healthy.length > 0 ? healthy : degraded.length > 0 ? degraded : routerDatabases)
    : (healthy.length > 0 ? healthy : routerDatabases);

  // Increase timeout for serverless (cold starts, network latency)
  // Match the connect_timeout in connection URL (30s for Vercel, 20s for traditional)
  const connectionTimeout = isVercel ? 30000 : 20000; // 30s for Vercel (reduced from 60s), 20s for traditional

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    for (const db of databasesToTry) {
      // Check if client exists before trying to use it
      if (!db || !db.client) {
        console.warn(`[Multi-DB Router] ⚠️ Database ${db?.index ?? 'unknown'} client is undefined - skipping`);
        continue;
      }
      
      try {
        // Use timeout for connection test in serverless
        const queryPromise = db.client.$queryRaw`SELECT 1`;
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Connection test timeout')), connectionTimeout)
        );
        
        await Promise.race([queryPromise, timeoutPromise]);
        console.log(`[Multi-DB Router] ✅ Connection verified to database ${db.index}`);
        return; // Success - at least one database is working
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        // Only log on first attempt to reduce noise
        if (attempt === 0) {
          console.warn(`[Multi-DB Router] ⚠️ Database ${db.index} connection test failed: ${errorMsg}`);
        }
        // Continue to next database
      }
    }
    
    // If all databases failed and we have retries left, wait and retry
    if (attempt < maxRetries - 1) {
      const delay = retryDelay * Math.pow(2, attempt);
      console.log(`[Multi-DB Router] ⏳ All databases failed, retrying in ${delay}ms... (attempt ${attempt + 1}/${maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // If we get here, all databases failed after all retries
  // In serverless, this might be a temporary issue - log but don't throw if we have databases configured
  if (isVercel && routerDatabases.length > 0) {
    console.error('[Multi-DB Router] ⚠️ All databases failed connection test, but will continue (serverless cold start may resolve)');
    // Don't throw - let the application try to use databases anyway
    // They might work even if the connection test failed
    return;
  }
  
  console.error('[Multi-DB Router] ❌ All databases failed to connect after retries');
  throw new Error('[Multi-DB Router] No databases available after retries. Check database connections.');
}

