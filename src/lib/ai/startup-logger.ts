/**
 * AI Service Startup Logger
 * 
 * Logs key pool size and configuration on startup
 * Warns if key count is below recommended threshold
 */

import apiKeyManager from './api-key-manager';

const MIN_RECOMMENDED_KEYS = 20;
const OPTIMAL_KEY_RANGE = [20, 30];

/**
 * Log AI service startup information
 * Should be called during application initialization
 */
export async function logAIStartup(): Promise<void> {
  try {
    const keyCount = await apiKeyManager.getKeyCount();
    
    console.log('[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`[AI Keys] Loaded ${keyCount} keys`);
    console.log(`[AI Keys] Min expected: ${MIN_RECOMMENDED_KEYS}`);
    console.log(`[AI Keys] Optimal range: ${OPTIMAL_KEY_RANGE[0]}-${OPTIMAL_KEY_RANGE[1]} keys for enterprise`);
    
    if (keyCount < MIN_RECOMMENDED_KEYS) {
      const missing = MIN_RECOMMENDED_KEYS - keyCount;
      console.warn('[AI Keys] ⚠️  WARNING: Key pool below recommended threshold');
      console.warn(`[AI Keys] ⚠️  Consider adding ${missing} more keys for optimal performance`);
      console.warn('[AI Keys] ⚠️  Low key count may lead to rate limiting under high load');
    } else if (keyCount >= OPTIMAL_KEY_RANGE[0] && keyCount <= OPTIMAL_KEY_RANGE[1]) {
      console.log('[AI Keys] ✅ Key pool is in optimal range');
    } else if (keyCount > OPTIMAL_KEY_RANGE[1]) {
      console.log('[AI Keys] ✅ Key pool exceeds optimal range (excellent for high load)');
    } else {
      console.log('[AI Keys] ℹ️  Key pool is adequate but below optimal range');
    }
    
    // Get rate limit stats
    const stats = await apiKeyManager.getRateLimitUsageStats();
    
    console.log(`[AI Keys] Status breakdown:`);
    console.log(`[AI Keys]   • Active: ${stats.summary.activeKeys}`);
    console.log(`[AI Keys]   • Rate Limited: ${stats.summary.rateLimitedKeys}`);
    console.log(`[AI Keys]   • Disabled: ${stats.summary.disabledKeys}`);
    
    if (stats.summary.rateLimitedKeys > 0) {
      console.warn(`[AI Keys] ⚠️  ${stats.summary.rateLimitedKeys} keys are currently rate-limited`);
    }
    
    if (stats.summary.disabledKeys > 0) {
      console.warn(`[AI Keys] ⚠️  ${stats.summary.disabledKeys} keys are disabled (check API Keys settings)`);
    }
    
    // Log total historical usage
    if (stats.summary.totalRequests > 0) {
      console.log(`[AI Keys] Historical usage:`);
      console.log(`[AI Keys]   • Total requests: ${stats.summary.totalRequests}`);
      console.log(`[AI Keys]   • Success rate: ${stats.summary.successRate}%`);
    }
    
    console.log('[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  } catch (error) {
    console.error('[AI Keys] ❌ Error during startup logging:', error);
  }
}

/**
 * Periodic health check for key pool
 * Runs every 30 minutes to monitor key health
 */
export function startPeriodicKeyHealthCheck(): void {
  const HEALTH_CHECK_INTERVAL = 30 * 60 * 1000; // 30 minutes
  
  setInterval(async () => {
    try {
      const keyCount = await apiKeyManager.getKeyCount();
      const stats = await apiKeyManager.getRateLimitUsageStats();
      
      // Only log if there are issues
      if (keyCount < MIN_RECOMMENDED_KEYS || 
          stats.summary.rateLimitedKeys > 0 || 
          stats.summary.disabledKeys > 0) {
        
        console.log('[AI Keys] Health Check ━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(`[AI Keys] Active keys: ${stats.summary.activeKeys}/${keyCount}`);
        
        if (keyCount < MIN_RECOMMENDED_KEYS) {
          console.warn(`[AI Keys] ⚠️  Key pool below threshold (${keyCount}/${MIN_RECOMMENDED_KEYS})`);
        }
        
        if (stats.summary.rateLimitedKeys > 0) {
          console.warn(`[AI Keys] ⚠️  ${stats.summary.rateLimitedKeys} keys rate-limited`);
        }
        
        if (stats.summary.disabledKeys > 0) {
          console.warn(`[AI Keys] ⚠️  ${stats.summary.disabledKeys} keys disabled`);
        }
        
        console.log('[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      }
    } catch (error) {
      console.error('[AI Keys] ❌ Health check failed:', error);
    }
  }, HEALTH_CHECK_INTERVAL);
  
  console.log('[AI Keys] ✅ Periodic health check started (every 30 minutes)');
}

