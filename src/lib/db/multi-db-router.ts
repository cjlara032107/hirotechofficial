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
        console.warn(`[DB Pool] ⚠️ DATABASE_URL_${i} is not set, skipping`);
        continue;
      }

      // Validate connection string format
      if (!dbUrl.startsWith('postgresql://') && !dbUrl.startsWith('postgres://')) {
        console.error(`[DB Pool] ❌ Invalid DATABASE_URL_${i} format (must start with postgresql:// or postgres://)`);
        continue; // Skip invalid URLs
      }

      try {
        // Enhance URL with connection pool settings
        const enhancedUrl = this.enhanceConnectionUrl(dbUrl, connectionLimit);
        
        // Extract host for logging (mask credentials)
        let dbHost = 'unknown';
        try {
          const urlMatch = enhancedUrl.match(/postgresql:\/\/[^@]*@([^\/]+)/);
          dbHost = urlMatch ? urlMatch[1] : 'unknown';
        } catch {
          // Ignore
        }

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

            // Log slow queries with DB index
            if (process.env.NODE_ENV === 'development' && duration > 2000) {
              console.warn(
                `[DB Pool] ⚠️ Slow query (DB index: ${i}, ${duration}ms):`,
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

        console.log(
          `[DB Pool] ✅ Initialized database ${i + 1}/${dbCount}`,
          `\n  - DB index: ${i}`,
          `\n  - Host: ${dbHost}`,
          `\n  - Connection limit: ${connectionLimit}`
        );
      } catch (error: any) {
        // Log error but continue with other databases
        console.error(
          `[DB Pool] ❌ Failed to initialize database ${i}:`,
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
      const poolTimeout = isVercel ? 60 : 30; // 60s for Vercel, 30s for traditional
      const connectTimeout = isVercel ? 60 : 30; // 60s for Vercel, 30s for traditional
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

    // Dev-only: Log routing decision
    if (process.env.NODE_ENV === 'development') {
      console.log('[Multi-DB Router] getClient called:', {
        routingStrategy: this.routingStrategy,
        key: key?.substring(0, 12) + '...',
        totalDatabases: allDatabases.length,
        healthyDatabases: healthyDatabases.length,
        usingDatabases: databasesToUse.length,
      });
    }

    // Use routing strategy - always try to use all configured databases
    // Health checks are advisory - databases might work even if health check fails
    let chosenClient: PrismaClient;
    let chosenDbIndex = -1;
    
    switch (this.routingStrategy) {
      case 'round-robin':
        chosenClient = this.getClientRoundRobin(databasesToUse);
        break;
      case 'hash':
        if (!key) {
          console.warn('[Multi-DB Router] ⚠️ Hash routing requires key, falling back to round-robin');
          chosenClient = this.getClientRoundRobin(databasesToUse);
        } else {
          chosenClient = this.getClientHash(key, databasesToUse);
        }
        break;
      case 'load-aware':
        chosenClient = this.getClientLoadAware(databasesToUse);
        break;
      default:
        chosenClient = this.getClientRoundRobin(databasesToUse);
    }
    
    // Dev-only: Log chosen database
    if (process.env.NODE_ENV === 'development') {
      const chosenConfig = this.databases.find(db => db.client === chosenClient);
      if (chosenConfig) {
        chosenDbIndex = chosenConfig.index;
        // Extract host from URL (mask credentials)
        let dbHost = 'unknown';
        try {
          const urlMatch = chosenConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
          dbHost = urlMatch ? urlMatch[1] : 'unknown';
        } catch {
          // Ignore
        }
        
        console.log('[Multi-DB Router] Chose database:', {
          dbIndex: chosenDbIndex,
          dbHost,
          health: chosenConfig.health,
        });
      }
    }
    
    return chosenClient;
  }

  private getClientRoundRobin(healthy: DatabaseConfig[]): PrismaClient {
    const db = healthy[this.roundRobinIndex % healthy.length];
    const selectedIndex = this.roundRobinIndex % healthy.length;
    this.roundRobinIndex = (this.roundRobinIndex + 1) % healthy.length;
    
    if (process.env.NODE_ENV === 'development') {
      console.log('[Multi-DB Router] Round-robin selected DB index:', selectedIndex, 'of', healthy.length);
    }
    
    return db.client;
  }

  private getClientHash(key: string, healthy: DatabaseConfig[]): PrismaClient {
    const hash = this.hashString(key);
    const index = hash % healthy.length;
    
    if (process.env.NODE_ENV === 'development') {
      console.log('[Multi-DB Router] Hash routing:', {
        key: key.substring(0, 12) + '...',
        hash,
        selectedIndex: index,
        totalDatabases: healthy.length,
      });
    }
    
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
    // Match the connect_timeout in connection URL (60s for Vercel, 30s for traditional)
    // But use shorter timeout for health checks to fail fast
    const healthCheckTimeout = isVercel ? 15000 : 8000; // 15s for Vercel, 8s for traditional
    
    const checkHealth = async (db: DatabaseConfig, retries = 2, silent = false) => {
      // Extract host for logging
      let dbHost = 'unknown';
      try {
        const urlMatch = db.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
        dbHost = urlMatch ? urlMatch[1] : 'unknown';
      } catch {
        // Ignore
      }
      
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          const startTime = Date.now();
          // Use a timeout to prevent hanging - longer for serverless
          const queryPromise = db.client.$queryRaw`SELECT 1`;
          const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Health check timeout')), healthCheckTimeout)
          );
          
          await Promise.race([queryPromise, timeoutPromise]);
          const duration = Date.now() - startTime;

          if (duration > 2000) {
            const wasHealthy = db.health === 'healthy';
            db.health = 'degraded';
            if (!silent) {
              console.warn(
                `[DB Pool] ⚠️ Health check slow`,
                `\n  - DB index: ${db.index}`,
                `\n  - Host: ${dbHost}`,
                `\n  - Duration: ${duration}ms`,
                `\n  - Status: degraded`
              );
            }
          } else {
            const wasUnhealthy = db.health === 'degraded' || db.health === 'down';
            db.health = 'healthy';
            // Only log success if it was previously unhealthy
            if (wasUnhealthy && !silent) {
              console.log(
                `[DB Pool] ✅ Health check recovered`,
                `\n  - DB index: ${db.index}`,
                `\n  - Host: ${dbHost}`,
                `\n  - Status: healthy`
              );
            }
          }
          db.lastHealthCheck = Date.now();
          return; // Success, exit retry loop
        } catch (error: any) {
          const isConnectionError = 
            error?.code === 'P1001' ||
            error?.code === 'P2024' ||
            error?.message?.includes("Can't reach database") ||
            error?.message?.includes('pool') ||
            error?.message?.includes('timeout') ||
            error?.message?.includes('Health check timeout');
          
          if (attempt === retries) {
            // Final attempt failed - mark as degraded (not down) so it's still used
            // Databases might work even if health check fails (network issues, etc.)
            const wasHealthy = db.health === 'healthy';
            db.health = 'degraded';
            db.lastHealthCheck = Date.now();
            
            // Only log if it was previously healthy (to avoid spam)
            if (!silent && wasHealthy) {
              console.warn(
                `[DB Pool] ⚠️ Health check failed`,
                `\n  - DB index: ${db.index}`,
                `\n  - Host: ${dbHost}`,
                `\n  - Error code: ${error?.code || 'N/A'}`,
                `\n  - Error: ${error?.message || String(error)}`,
                `\n  - Status: degraded (still usable)`,
                `\n  - Will retry on next health check`
              );
            }
          } else {
            // Wait before retry (exponential backoff)
            await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
          }
        }
      }
    };

    // Initial health check with delay to allow connections to establish
    // Use longer delay for serverless environments (cold starts)
    const initialDelay = isVercel ? 5000 : 2000; // 5 seconds for Vercel, 2 for local
    
    setTimeout(async () => {
      for (const db of this.databases) {
        await checkHealth(db, 2, true); // More retries, silent initial check
      }
      
      // Log summary after initial check
      const healthy = this.databases.filter(d => d.health === 'healthy').length;
      const degraded = this.databases.filter(d => d.health === 'degraded').length;
      const down = this.databases.filter(d => d.health === 'down').length;
      
      if (healthy > 0) {
        console.log(`[Multi-DB Router] ✅ Health check complete: ${healthy} healthy, ${degraded} degraded, ${down} unavailable`);
      } else if (this.databases.length > 0) {
        console.warn(`[Multi-DB Router] ⚠️ No healthy databases found. Using all databases (health checks are advisory).`);
      }
    }, initialDelay);

    // Periodic health checks every 30 seconds
    // Check all databases to detect recovery
    this.healthCheckInterval = setInterval(async () => {
      for (const db of this.databases) {
        // Check all databases periodically to detect recovery
        // Use silent mode for degraded databases to reduce noise
        const isSilent = db.health === 'degraded';
        await checkHealth(db, 1, isSilent);
      }
    }, 30000); // Check every 30 seconds
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
  // Match the connect_timeout in connection URL (60s for Vercel, 30s for traditional)
  const connectionTimeout = isVercel ? 60000 : 30000; // 60s for Vercel, 30s for traditional

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    for (const db of databasesToTry) {
      // Check if client exists before trying to use it
      if (!db || !db.client) {
        console.warn(`[DB Pool] ⚠️ Database ${db?.index ?? 'unknown'} client is undefined - skipping`);
        continue;
      }
      
      // Extract host for logging
      let dbHost = 'unknown';
      try {
        const urlMatch = db.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
        dbHost = urlMatch ? urlMatch[1] : 'unknown';
      } catch {
        // Ignore
      }
      
      try {
        // Use timeout for connection test in serverless
        const startTime = Date.now();
        const queryPromise = db.client.$queryRaw`SELECT 1`;
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Connection test timeout')), connectionTimeout)
        );
        
        await Promise.race([queryPromise, timeoutPromise]);
        const duration = Date.now() - startTime;
        
        console.log(
          `[DB Pool] ✅ Connection verified`,
          `\n  - DB index: ${db.index}`,
          `\n  - Host: ${dbHost}`,
          `\n  - Duration: ${duration}ms`,
          `\n  - Attempt: ${attempt + 1}/${maxRetries}`
        );
        return; // Success - at least one database is working
      } catch (error) {
        const errorObj = error as { code?: string; message?: string };
        const errorMsg = errorObj?.message || String(error);
        const errorCode = errorObj?.code;
        
        // Only log on first attempt to reduce noise
        if (attempt === 0) {
          console.warn(
            `[DB Pool] ⚠️ Connection test failed`,
            `\n  - DB index: ${db.index}`,
            `\n  - Host: ${dbHost}`,
            `\n  - Error code: ${errorCode || 'N/A'}`,
            `\n  - Error: ${errorMsg}`
          );
        }
        // Continue to next database
      }
    }
    
    // If all databases failed and we have retries left, wait and retry
    if (attempt < maxRetries - 1) {
      const delay = retryDelay * Math.pow(2, attempt);
      console.log(
        `[DB Pool] ⏳ All databases failed, retrying in ${delay}ms...`,
        `\n  - Attempt: ${attempt + 1}/${maxRetries}`,
        `\n  - Databases tried: ${databasesToTry.length}`
      );
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // If we get here, all databases failed after all retries
  // In serverless, this might be a temporary issue - log but don't throw if we have databases configured
  if (isVercel && routerDatabases.length > 0) {
    console.error(
      `[DB Pool] ⚠️ All databases failed connection test`,
      `\n  - Environment: Vercel/serverless`,
      `\n  - Total databases: ${routerDatabases.length}`,
      `\n  - Continuing (cold start may resolve)`
    );
    // Don't throw - let the application try to use databases anyway
    // They might work even if the connection test failed
    return;
  }
  
  console.error(
    `[DB Pool] ❌ All databases failed to connect after retries`,
    `\n  - Total databases: ${routerDatabases.length}`,
    `\n  - Max retries: ${maxRetries}`,
    `\n  - Recommendation: Check database connections and Supabase pooler URLs`
  );
  throw new Error('[DB Pool] No databases available after retries. Check database connections.');
}

