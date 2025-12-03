import { PrismaClient } from '@prisma/client';
import { systemMonitor } from './monitoring/system-monitor';

// Check if multi-DB is enabled
const ENABLE_MULTI_DB = process.env.ENABLE_MULTI_DB === 'true';
const DB_COUNT = parseInt(process.env.DB_COUNT || '1', 10);

// Single database implementation (existing code)
const prismaClientSingleton = () => {
  let databaseUrl = process.env.DATABASE_URL || '';
  
  if (databaseUrl.includes('pooler.supabase.com') && !databaseUrl.includes('connection_limit')) {
    const separator = databaseUrl.includes('?') ? '&' : '?';
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    const connectionLimit = isVercel ? 20 : 30; // Increased from 10/15 to 20/30
    // Increase timeouts for Vercel serverless (cold starts, network latency)
    const poolTimeout = isVercel ? 60 : 90; // 60s for Vercel, 90s for traditional
    const connectTimeout = isVercel ? 60 : 30; // 60s for Vercel, 30s for traditional
    
    databaseUrl = `${databaseUrl}${separator}connection_limit=${connectionLimit}&pool_timeout=${poolTimeout}&connect_timeout=${connectTimeout}&statement_cache_size=0`;
    
    // Extract host for logging (mask credentials)
    let dbHost = 'unknown';
    try {
      const urlMatch = databaseUrl.match(/postgresql:\/\/[^@]*@([^\/]+)/);
      dbHost = urlMatch ? urlMatch[1] : 'unknown';
    } catch {
      // Ignore
    }
    
    console.log(`[DB Pool] 🔧 Single-DB mode initialized`);
    console.log(`[DB Pool]   - Environment: ${isVercel ? 'Vercel/serverless' : 'traditional server'}`);
    console.log(`[DB Pool]   - Host: ${dbHost}`);
    console.log(`[DB Pool]   - connection_limit: ${connectionLimit}`);
    console.log(`[DB Pool]   - pool_timeout: ${poolTimeout}s`);
    console.log(`[DB Pool]   - connect_timeout: ${connectTimeout}s`);
  }
  
  const client = new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
  });

  // Track queries
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  client.$on('query' as any, (e: any) => {
    const query = e.query || '';
    const duration = e.duration || 0;
    
    let model: string | undefined;
    let action: string | undefined;
    
    const modelPatterns = [
      /FROM\s+"?(\w+)"?/i,
      /INTO\s+"?(\w+)"?/i,
      /UPDATE\s+"?(\w+)"?/i,
      /JOIN\s+"?(\w+)"?/i,
    ];
    
    for (const pattern of modelPatterns) {
      const match = query.match(pattern);
      if (match) {
        model = match[1];
        break;
      }
    }
    
    const actionMatch = query.match(/^\s*(\w+)/i);
    if (actionMatch) {
      action = actionMatch[1].toUpperCase();
    }
    
    systemMonitor.recordDatabaseQuery({
      query: query.substring(0, 500),
      duration,
      model,
      action,
      timestamp: Date.now(),
      success: true,
    });

    if (process.env.NODE_ENV === 'development' && duration > 2000) {
      console.warn(
        `[Prisma] ⚠️ Slow query (${duration}ms):`,
        query.substring(0, 150) || 'N/A'
      );
    }
  });

  return client;
};

declare global {
  var prismaGlobal: undefined | ReturnType<typeof prismaClientSingleton>;
  var prismaConnectionPromise: undefined | Promise<void>;
}

if (!globalThis.prismaGlobal) {
  globalThis.prismaGlobal = prismaClientSingleton();
}

const prismaClient = globalThis.prismaGlobal;

let connectionPromise: Promise<void> | undefined;
let connectionState: 'idle' | 'connecting' | 'connected' = 'idle';

// Pool usage tracking for alerting
interface PoolUsageMetrics {
  failureCount: number;
  lastFailureTime: number;
  consecutiveTimeouts: number;
  p2024Count: number;
  lastAlertTime: number;
}

const poolMetrics: PoolUsageMetrics = {
  failureCount: 0,
  lastFailureTime: 0,
  consecutiveTimeouts: 0,
  p2024Count: 0,
  lastAlertTime: 0,
};

// Alert thresholds
const POOL_ALERT_THRESHOLD = 5; // Alert after 5 failures in window
const POOL_ALERT_WINDOW_MS = 5 * 60 * 1000; // 5 minute window
const POOL_ALERT_COOLDOWN_MS = 10 * 60 * 1000; // 10 minute cooldown between alerts

/**
 * Check pool usage metrics and trigger alerts if thresholds exceeded
 */
async function checkPoolUsageAndAlert(errorCode?: string, dbIndex?: number) {
  const now = Date.now();
  
  // Track P2024 errors specifically
  if (errorCode === 'P2024') {
    poolMetrics.p2024Count++;
  }
  
  // Reset counters if outside the alert window
  if (now - poolMetrics.lastFailureTime > POOL_ALERT_WINDOW_MS) {
    poolMetrics.failureCount = 0;
    poolMetrics.consecutiveTimeouts = 0;
    poolMetrics.p2024Count = 0;
  }
  
  poolMetrics.failureCount++;
  poolMetrics.lastFailureTime = now;
  
  if (errorCode === 'P2024' || errorCode?.includes('timeout')) {
    poolMetrics.consecutiveTimeouts++;
  }
  
  // Calculate estimated pool usage percentage (rough heuristic)
  const connectionLimit = parseInt(
    process.env.DATABASE_URL?.match(/connection_limit=(\d+)/)?.[1] || '15',
    10
  );
  const estimatedUsagePercent = Math.min(
    100,
    (poolMetrics.failureCount / POOL_ALERT_THRESHOLD) * 80
  );
  
  // Log pool usage warning if high
  if (estimatedUsagePercent >= 80) {
    const dbContext = dbIndex !== undefined ? ` (DB index: ${dbIndex})` : '';
    console.warn(
      `[DB Pool] ⚠️ High pool usage detected${dbContext}:`,
      `\n  - Estimated usage: ~${estimatedUsagePercent.toFixed(0)}%`,
      `\n  - Failures in window: ${poolMetrics.failureCount}`,
      `\n  - P2024 errors: ${poolMetrics.p2024Count}`,
      `\n  - Consecutive timeouts: ${poolMetrics.consecutiveTimeouts}`,
      `\n  - Connection limit: ${connectionLimit}`
    );
  }
  
  // Trigger alert if threshold exceeded and not in cooldown
  if (
    poolMetrics.failureCount >= POOL_ALERT_THRESHOLD &&
    now - poolMetrics.lastAlertTime > POOL_ALERT_COOLDOWN_MS
  ) {
    poolMetrics.lastAlertTime = now;
    
    const dbContext = dbIndex !== undefined ? ` on DB ${dbIndex}` : '';
    console.error(
      `[DB Pool] 🚨 ALERT: Pool exhaustion threshold exceeded${dbContext}`,
      `\n  - Failures in last ${POOL_ALERT_WINDOW_MS / 1000}s: ${poolMetrics.failureCount}`,
      `\n  - P2024 errors: ${poolMetrics.p2024Count}`,
      `\n  - Connection limit: ${connectionLimit}`,
      `\n  - Recommended: Check connection pooling config and Supabase pooler URLs`
    );
    
    try {
      const { alertDatabasePoolExhaustion } = await import('@/lib/alerts/alert-service');
      await alertDatabasePoolExhaustion(connectionLimit, connectionLimit);
    } catch (alertError) {
      console.warn(`[DB Pool] Failed to send alert notification:`, alertError);
    }
  }
}

async function ensurePrismaConnected() {
  if (connectionState === 'connected') {
    return;
  }

  if (connectionState === 'connecting' && connectionPromise) {
    try {
      await connectionPromise;
      return;
    } catch (error) {
      connectionState = 'idle';
      connectionPromise = undefined;
    }
  }

  connectionState = 'connecting';
  connectionPromise = prismaClient.$connect()
    .then(() => {
      connectionState = 'connected';
      const poolInfo = process.env.DATABASE_URL?.includes('connection_limit') 
        ? ' (pool configured)' 
        : ' (using default pool)';
      console.log(`[Prisma] ✅ Connected to database${poolInfo}`);
    })
    .catch((error) => {
      console.error('[Prisma] ❌ Connection error:', error);
      connectionState = 'idle';
      connectionPromise = undefined;
      if (error?.message?.includes('forcibly closed') || 
          error?.message?.includes('ConnectionReset') ||
          error?.message?.includes('Server has closed the connection')) {
        prismaClient.$disconnect().catch(() => {});
      }
      throw error;
    });

  return connectionPromise;
}

async function connectPrismaSingle(maxRetries = 3, retryDelay = 1000) {
  let lastError: unknown;
  const connectionId = `conn-${Date.now()}`;
  
  // Extract DB info for logging
  const connectionLimit = parseInt(
    process.env.DATABASE_URL?.match(/connection_limit=(\d+)/)?.[1] || '15',
    10
  );
  let dbHost = 'unknown';
  try {
    const urlMatch = process.env.DATABASE_URL?.match(/postgresql:\/\/[^@]*@([^\/]+)/);
    dbHost = urlMatch ? urlMatch[1] : 'unknown';
  } catch {
    // Ignore
  }
  
  console.log(
    `[DB Pool] Attempting connection (maxRetries: ${maxRetries})`,
    `\n  - Connection ID: ${connectionId}`,
    `\n  - Host: ${dbHost}`,
    `\n  - Connection limit: ${connectionLimit}`
  );
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const attemptStartTime = Date.now();
    try {
      console.log(`[DB Pool] [${connectionId}] Attempt ${attempt}/${maxRetries} - Connecting...`);
      await ensurePrismaConnected();
      const attemptDuration = Date.now() - attemptStartTime;
      
      // Reset metrics on successful connection
      poolMetrics.consecutiveTimeouts = 0;
      
      if (attempt > 1) {
        console.log(`[DB Pool] [${connectionId}] ============================================`);
        console.log(`[DB Pool] [${connectionId}] ✅ CONNECTED AFTER ${attempt} ATTEMPT(S)`);
        console.log(`[DB Pool] [${connectionId}]   - Duration: ${attemptDuration}ms`);
        console.log(`[DB Pool] [${connectionId}]   - Host: ${dbHost}`);
        console.log(`[DB Pool] [${connectionId}]   - Connection State: ${connectionState}`);
        console.log(`[DB Pool] [${connectionId}] ============================================`);
      } else {
        console.log(`[DB Pool] [${connectionId}] ✅ Connected successfully in ${attemptDuration}ms`);
      }
      return;
    } catch (error: unknown) {
      lastError = error;
      const attemptDuration = Date.now() - attemptStartTime;
      const errorObj = error as { code?: string; message?: string };
      
      const isConnectionError = errorObj?.code === 'P1001' || 
        errorObj?.code === 'P2024' ||
        errorObj?.message?.includes("Can't reach database") ||
        errorObj?.message?.includes('connection') ||
        errorObj?.message?.includes('pool') ||
        errorObj?.message?.includes('timeout') ||
        errorObj?.message?.includes('forcibly closed') ||
        errorObj?.message?.includes('ConnectionReset') ||
        errorObj?.message?.includes('Server has closed the connection');
      
      const isPoolError = errorObj?.code === 'P2024' || errorObj?.message?.includes('pool');
      const isTimeout = errorObj?.message?.includes('timeout');
      
      console.error(`[DB Pool] [${connectionId}] ============================================`);
      console.error(`[DB Pool] [${connectionId}] ❌ CONNECTION ATTEMPT ${attempt}/${maxRetries} FAILED`);
      console.error(`[DB Pool] [${connectionId}]   - Duration: ${attemptDuration}ms`);
      console.error(`[DB Pool] [${connectionId}]   - Host: ${dbHost}`);
      console.error(`[DB Pool] [${connectionId}]   - Error Code: ${errorObj?.code || 'N/A'}`);
      console.error(`[DB Pool] [${connectionId}]   - Error Type: ${isPoolError ? 'Pool Exhaustion' : isTimeout ? 'Timeout' : 'Connection Error'}`);
      console.error(`[DB Pool] [${connectionId}]   - Error Message: ${errorObj?.message || String(error)}`);
      console.error(`[DB Pool] [${connectionId}]   - Connection State: ${connectionState}`);
      console.error(`[DB Pool] [${connectionId}]   - Connection Limit: ${connectionLimit}`);
      
      // Track pool usage and trigger alerts
      if (isPoolError || isTimeout) {
        await checkPoolUsageAndAlert(errorObj?.code);
      }
      
      if (!isConnectionError || attempt === maxRetries) {
        console.error(`[DB Pool] [${connectionId}] ============================================`);
        connectionState = 'idle';
        connectionPromise = undefined;
        throw error;
      }
      
      const delay = retryDelay * Math.pow(2, attempt - 1);
      console.error(`[DB Pool] [${connectionId}]   - Will retry in ${delay}ms...`);
      console.error(`[DB Pool] [${connectionId}] ============================================`);
      
      if (errorObj?.message?.includes('forcibly closed') || 
          errorObj?.message?.includes('ConnectionReset') ||
          errorObj?.message?.includes('Server has closed the connection')) {
        try {
          console.log(`[DB Pool] [${connectionId}] Disconnecting stale connection before retry`);
          await prismaClient.$disconnect();
        } catch (disconnectError) {
          console.warn(`[DB Pool] [${connectionId}] Disconnect error (ignoring):`, disconnectError);
        }
      }
      
      connectionState = 'idle';
      connectionPromise = undefined;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  console.error(
    `[DB Pool] [${connectionId}] ❌ All ${maxRetries} connection attempts failed`,
    `\n  - Host: ${dbHost}`,
    `\n  - Connection limit: ${connectionLimit}`,
    `\n  - Pool metrics:`,
    `\n    • Failures in window: ${poolMetrics.failureCount}`,
    `\n    • P2024 errors: ${poolMetrics.p2024Count}`,
    `\n    • Consecutive timeouts: ${poolMetrics.consecutiveTimeouts}`
  );
  throw lastError;
}

if (typeof window === 'undefined') {
  ensurePrismaConnected().catch(() => {
    // Silently fail on initial connection
  });
}

// Always export prisma - use multi-DB router if enabled, otherwise single DB
let prismaInstance: PrismaClient;
let connectPrismaInstance: (maxRetries?: number, retryDelay?: number) => Promise<void>;
let getPrismaExport: ((key?: string) => PrismaClient) | undefined;
let getDatabaseRouterExport: (() => unknown) | undefined;

if (ENABLE_MULTI_DB && DB_COUNT > 1) {
  // Multi-DB mode: use router
  const router = require('./db/multi-db-router');
  prismaInstance = router.getPrisma();
  connectPrismaInstance = router.connectPrisma;
  getPrismaExport = router.getPrisma;
  getDatabaseRouterExport = router.getDatabaseRouter;
  
  console.log('[DB] ✅ Multi-database routing enabled');
} else {
  // Single DB mode
  prismaInstance = prismaClient;
  connectPrismaInstance = connectPrismaSingle;
  console.log('[DB] ✅ Single database mode');
}

// Always export these for TypeScript compatibility
export const prisma = prismaInstance;
export const connectPrisma = connectPrismaInstance;

// Conditionally export multi-DB functions (using type assertion to avoid TS1184)
export const getPrisma = getPrismaExport as typeof getPrismaExport | undefined;
export const getDatabaseRouter = getDatabaseRouterExport as typeof getDatabaseRouterExport | undefined;
