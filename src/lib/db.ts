import { PrismaClient } from '@prisma/client';

const prismaClientSingleton = () => {
  // Enhance DATABASE_URL with connection pool settings if not already present
  let databaseUrl = process.env.DATABASE_URL || '';
  
  // Add connection pool parameters if using Supabase pooler
  if (databaseUrl.includes('pooler.supabase.com') && !databaseUrl.includes('connection_limit')) {
    const separator = databaseUrl.includes('?') ? '&' : '?';
    // Increased timeouts for better reliability
    databaseUrl = `${databaseUrl}${separator}connection_limit=10&pool_timeout=30&connect_timeout=15`;
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
      console.log('[Prisma] ✅ Connected to database');
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
      
      // Check if it's a connection error (P1001)
      const isConnectionError = errorObj?.code === 'P1001' || 
        errorObj?.message?.includes("Can't reach database") ||
        errorObj?.message?.includes('connection');
      
      // If it's not a connection error or we've exhausted retries, throw immediately
      if (!isConnectionError || attempt === maxRetries) {
        console.error(`[Prisma] ❌ Failed to connect (attempt ${attempt}/${maxRetries}):`, error);
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

