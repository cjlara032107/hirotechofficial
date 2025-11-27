import { PrismaClient } from '@prisma/client';

const prismaClientSingleton = () => {
  // Enhance DATABASE_URL with connection pool settings if not already present
  let databaseUrl = process.env.DATABASE_URL || '';
  
  // Add connection pool parameters if using Supabase pooler
  if (databaseUrl.includes('pooler.supabase.com') && !databaseUrl.includes('connection_limit')) {
    const separator = databaseUrl.includes('?') ? '&' : '?';
    
    // OPTIMIZED: For Vercel/serverless, use connection_limit=5
    // This allows multiple concurrent queries per function instance without exhausting the pool
    // Supabase pooler can handle 60-200 connections (depending on tier), so 5 per instance is safe
    // Previous limit of 1 was causing timeouts when multiple queries ran concurrently
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    const connectionLimit = isVercel ? 5 : 10; // 5 for serverless (allows concurrent queries), 10 for traditional servers
    
    // pool_timeout: 90 - gives more time to get a connection under high load
    // connect_timeout: 30 - more time for initial connection
    // statement_cache_size: 0 - disable statement caching to reduce memory usage
    databaseUrl = `${databaseUrl}${separator}connection_limit=${connectionLimit}&pool_timeout=90&connect_timeout=30&statement_cache_size=0`;
    
    console.log(`[Prisma] 🔧 Connection pool settings (${isVercel ? 'Vercel/serverless' : 'traditional server'}):`);
    console.log(`[Prisma]   - connection_limit: ${connectionLimit} ${isVercel ? '(serverless - pooler handles pooling)' : ''}`);
    console.log(`[Prisma]   - pool_timeout: 90s`);
    console.log(`[Prisma]   - connect_timeout: 30s`);
  }
  
  return new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
    datasources: {
      db: {
        url: databaseUrl,
      },
    },
  });
};

declare global {
  var prismaGlobal: undefined | ReturnType<typeof prismaClientSingleton>;
  var prismaConnectionPromise: undefined | Promise<void>;
}

const prismaClient = globalThis.prismaGlobal ?? prismaClientSingleton();

// Ensure Prisma is connected before use (critical for serverless environments)
// In serverless, connections can be lost between requests, so we need to reconnect
let connectionPromise: Promise<void> | undefined;
let connectionState: 'idle' | 'connecting' | 'connected' = 'idle';

async function ensurePrismaConnected() {
  // If already connected, return immediately
  if (connectionState === 'connected') {
    return;
  }

  // If connection is in progress, wait for it
  if (connectionState === 'connecting' && connectionPromise) {
    try {
      await connectionPromise;
      return;
    } catch (error) {
      // Connection failed, reset and retry
      connectionState = 'idle';
      connectionPromise = undefined;
    }
  }

  // Start new connection
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
      throw error;
    });

  return connectionPromise;
}

// Helper to ensure connection before queries (call at start of API routes)
// Includes retry logic for transient connection failures (P1001 errors)
export async function connectPrisma(maxRetries = 3, retryDelay = 1000) {
  let lastError: unknown;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
  try {
    await ensurePrismaConnected();
      // Connection successful
      if (attempt > 1) {
        console.log(`[Prisma] ✅ Connected after ${attempt} attempt(s)`);
      }
      return;
    } catch (error: unknown) {
      lastError = error;
      const errorObj = error as { code?: string; message?: string };
      
      // Check if it's a connection error (P1001) or pool exhaustion (P2024)
      const isConnectionError = errorObj?.code === 'P1001' || 
        errorObj?.code === 'P2024' ||
        errorObj?.message?.includes("Can't reach database") ||
        errorObj?.message?.includes('connection') ||
        errorObj?.message?.includes('pool') ||
        errorObj?.message?.includes('timeout');
      
      // If it's not a connection error or we've exhausted retries, throw immediately
      if (!isConnectionError || attempt === maxRetries) {
        if (errorObj?.code === 'P2024' || errorObj?.message?.includes('pool')) {
          console.error(
            `[Prisma] ❌ Connection pool exhausted (attempt ${attempt}/${maxRetries}): ` +
            `All connections are in use. Consider increasing connection_limit or reducing concurrent operations.`
          );
        } else {
          console.error(`[Prisma] ❌ Failed to connect (attempt ${attempt}/${maxRetries}):`, error);
        }
        // Reset state to allow retry on next call
        connectionState = 'idle';
        connectionPromise = undefined;
        throw error;
      }
      
      // Connection error - retry with exponential backoff
      const delay = retryDelay * Math.pow(2, attempt - 1);
      console.warn(`[Prisma] ⚠️ Connection failed (attempt ${attempt}/${maxRetries}), retrying in ${delay}ms...`);
      
      // Reset state before retry
      connectionState = 'idle';
      connectionPromise = undefined;
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  // Should never reach here, but TypeScript needs it
  throw lastError;
}

// Initialize connection on module load (for serverless warm starts)
if (typeof window === 'undefined') {
  // Only run on server side
  ensurePrismaConnected().catch(() => {
    // Silently fail on initial connection - will retry on first query
  });
}

// Export prisma client - Prisma handles connections automatically
// but we ensure connection is established before first use
export const prisma = prismaClient;

if (process.env.NODE_ENV !== 'production') {
  globalThis.prismaGlobal = prismaClient;
}

