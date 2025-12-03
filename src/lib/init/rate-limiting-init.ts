/**
 * Rate Limiting Initialization
 * 
 * Initialize rate limiting components on application startup
 */

import { logAIStartup, startPeriodicKeyHealthCheck } from '../ai/startup-logger';

let initialized = false;

/**
 * Initialize all rate limiting components
 * Should be called once during application startup
 */
export async function initializeRateLimiting(): Promise<void> {
  if (initialized) {
    console.log('[Rate Limiting] Already initialized, skipping...');
    return;
  }

  console.log('[Rate Limiting] Initializing...');
  
  try {
    // Log AI key pool status
    await logAIStartup();
    
    // Start periodic health checks
    if (process.env.NODE_ENV === 'production' || process.env.AI_ENABLE_HEALTH_CHECK === 'true') {
      startPeriodicKeyHealthCheck();
    }
    
    console.log('[Rate Limiting] ✅ Initialization complete');
    initialized = true;
  } catch (error) {
    console.error('[Rate Limiting] ❌ Initialization failed:', error);
    // Don't throw - allow app to continue even if rate limiting init fails
  }
}

/**
 * Check if rate limiting has been initialized
 */
export function isInitialized(): boolean {
  return initialized;
}

