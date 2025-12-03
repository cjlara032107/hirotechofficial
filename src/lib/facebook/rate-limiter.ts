/**
 * Facebook API Rate Limiter
 * 
 * Implements:
 * - Per-user rate tracking (200 calls/hour per user)
 * - Global rate tracking
 * - Request batching
 * - Response caching (5-10 minutes)
 * - Throttling warnings at 80% quota
 */

export interface FacebookRateLimit {
  userId: string;
  callsLastHour: number;
  lastReset: number;
  warnings: number;
}

export interface FacebookRateLog {
  endpoint: string;
  userId: string;
  priority: 'high' | 'low';
  cacheHit: boolean;
  timestamp: number;
  elapsedMs?: number;
  success?: boolean;
  errorCode?: string;
  retryCount?: number;
}

/**
 * Response cache entry
 */
interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

/**
 * Facebook API Rate Limiter
 * Tracks per-user and global usage, implements caching and batching
 */
class FacebookRateLimiter {
  private userRateLimits = new Map<string, FacebookRateLimit>();
  private globalCalls = 0;
  private globalLastReset = Date.now();
  private responseCache = new Map<string, CacheEntry<any>>();
  
  private readonly HOUR_WINDOW = 60 * 60 * 1000; // 60 minutes
  private readonly USER_LIMIT_PER_HOUR = 200;
  private readonly WARNING_THRESHOLD = 0.8; // 80%
  private readonly DEFAULT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  private readonly METADATA_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

  /**
   * Get or initialize rate limit for a user
   */
  private getUserLimit(userId: string): FacebookRateLimit {
    let limit = this.userRateLimits.get(userId);
    
    if (!limit) {
      limit = {
        userId,
        callsLastHour: 0,
        lastReset: Date.now(),
        warnings: 0,
      };
      this.userRateLimits.set(userId, limit);
    }

    // Reset counter if hour has passed
    const now = Date.now();
    const elapsed = now - limit.lastReset;
    
    if (elapsed >= this.HOUR_WINDOW) {
      limit.callsLastHour = 0;
      limit.lastReset = now;
      limit.warnings = 0;
    }

    return limit;
  }

  /**
   * Reset global counter if hour has passed
   */
  private resetGlobalIfNeeded(): void {
    const now = Date.now();
    const elapsed = now - this.globalLastReset;
    
    if (elapsed >= this.HOUR_WINDOW) {
      this.globalCalls = 0;
      this.globalLastReset = now;
    }
  }

  /**
   * Check if request should be allowed
   * Returns { allowed: boolean, reason?: string }
   */
  checkRateLimit(userId: string, priority: 'high' | 'low' = 'high'): {
    allowed: boolean;
    reason?: string;
    waitTimeMs?: number;
  } {
    const userLimit = this.getUserLimit(userId);
    
    // Check user limit
    if (userLimit.callsLastHour >= this.USER_LIMIT_PER_HOUR) {
      // For low priority, deny immediately
      if (priority === 'low') {
        const waitTime = this.HOUR_WINDOW - (Date.now() - userLimit.lastReset);
        return {
          allowed: false,
          reason: 'User rate limit exceeded (low priority request denied)',
          waitTimeMs: waitTime,
        };
      }
      
      // For high priority, warn but allow (emergency bypass)
      console.warn(
        `[FB Rate] ⚠️  User ${userId.substring(0, 8)}... exceeded rate limit but allowing HIGH priority request | ` +
        `calls: ${userLimit.callsLastHour}/${this.USER_LIMIT_PER_HOUR}`
      );
    }
    
    return { allowed: true };
  }

  /**
   * Generate cache key for a request
   */
  private getCacheKey(endpoint: string, params: Record<string, any>): string {
    const sortedParams = Object.keys(params)
      .sort()
      .map(k => `${k}=${JSON.stringify(params[k])}`)
      .join('&');
    return `${endpoint}?${sortedParams}`;
  }

  /**
   * Get cached response if available
   */
  getCachedResponse<T>(endpoint: string, params: Record<string, any>): T | null {
    const cacheKey = this.getCacheKey(endpoint, params);
    const cached = this.responseCache.get(cacheKey);
    
    if (!cached) {
      return null;
    }
    
    const now = Date.now();
    if (now - cached.timestamp > cached.ttl) {
      // Cache expired
      this.responseCache.delete(cacheKey);
      return null;
    }
    
    return cached.data as T;
  }

  /**
   * Set cached response
   */
  setCachedResponse<T>(endpoint: string, params: Record<string, any>, data: T, ttl?: number): void {
    const cacheKey = this.getCacheKey(endpoint, params);
    const cacheTtl = ttl || (endpoint.includes('metadata') ? this.METADATA_CACHE_TTL : this.DEFAULT_CACHE_TTL);
    
    this.responseCache.set(cacheKey, {
      data,
      timestamp: Date.now(),
      ttl: cacheTtl,
    });
  }

  /**
   * Log request start
   */
  logRequestStart(params: {
    endpoint: string;
    userId: string;
    priority: 'high' | 'low';
    cacheHit: boolean;
  }): void {
    const { endpoint, userId, priority, cacheHit } = params;
    
    console.log(
      `[FB Rate] Request start | endpoint: ${endpoint} | userId: ${userId.substring(0, 8)}... | ` +
      `priority: ${priority} | cacheHit: ${cacheHit}`
    );
    
    if (!cacheHit) {
      // Track usage only for actual API calls
      const userLimit = this.getUserLimit(userId);
      userLimit.callsLastHour++;
      
      this.resetGlobalIfNeeded();
      this.globalCalls++;
      
      // Check thresholds
      this.checkThresholds(userLimit);
    }
  }

  /**
   * Log request completion
   */
  logRequestComplete(params: {
    endpoint: string;
    userId: string;
    elapsedMs: number;
    success: boolean;
    errorCode?: string;
    retryCount?: number;
  }): void {
    const { endpoint, userId, elapsedMs, success, errorCode, retryCount } = params;
    
    const status = success ? 'Success' : 'Fail';
    const errorInfo = errorCode ? ` | errorCode: ${errorCode}` : '';
    const retryInfo = retryCount !== undefined && retryCount > 0 ? ` | retries: ${retryCount}` : '';
    
    console.log(
      `[FB Rate] ${status} | endpoint: ${endpoint} | userId: ${userId.substring(0, 8)}... | ` +
      `elapsed: ${elapsedMs}ms${retryInfo}${errorInfo}`
    );
  }

  /**
   * Log throttle warning
   */
  logThrottle(userId: string, callsLastHour: number): void {
    console.warn(
      `[FB Rate] Throttle | userId: ${userId.substring(0, 8)}... | ` +
      `callsLastHour: ${callsLastHour}/${this.USER_LIMIT_PER_HOUR} | ` +
      `bucket usage: ${((callsLastHour / this.USER_LIMIT_PER_HOUR) * 100).toFixed(1)}%`
    );
  }

  /**
   * Check thresholds and log warnings
   */
  private checkThresholds(userLimit: FacebookRateLimit): void {
    const usage = userLimit.callsLastHour / this.USER_LIMIT_PER_HOUR;
    
    // Warn at 80%, 90%, 95%
    if (usage >= 0.95 && userLimit.callsLastHour % 5 === 0) {
      console.warn(
        `[FB Rate] ⚠️  CRITICAL usage | userId: ${userLimit.userId.substring(0, 8)}... | ` +
        `calls: ${userLimit.callsLastHour}/${this.USER_LIMIT_PER_HOUR} (${(usage * 100).toFixed(1)}%)`
      );
      userLimit.warnings++;
    } else if (usage >= 0.9 && userLimit.callsLastHour % 10 === 0) {
      console.warn(
        `[FB Rate] ⚠️  Very high usage | userId: ${userLimit.userId.substring(0, 8)}... | ` +
        `calls: ${userLimit.callsLastHour}/${this.USER_LIMIT_PER_HOUR} (${(usage * 100).toFixed(1)}%)`
      );
      userLimit.warnings++;
    } else if (usage >= this.WARNING_THRESHOLD && userLimit.callsLastHour % 20 === 0) {
      console.warn(
        `[FB Rate] ⚠️  High usage | userId: ${userLimit.userId.substring(0, 8)}... | ` +
        `calls: ${userLimit.callsLastHour}/${this.USER_LIMIT_PER_HOUR} (${(usage * 100).toFixed(1)}%)`
      );
      userLimit.warnings++;
    }
  }

  /**
   * Get current usage stats for all users
   */
  getAllUsageStats(): FacebookRateLimit[] {
    return Array.from(this.userRateLimits.values());
  }

  /**
   * Get usage stats for a specific user
   */
  getUserUsageStats(userId: string): FacebookRateLimit | null {
    return this.userRateLimits.get(userId) || null;
  }

  /**
   * Get aggregated summary for monitoring
   */
  getSummary(): {
    totalUsers: number;
    activeUsers: number;
    totalCalls: number;
    globalCalls: number;
    avgCallsPerUser: number;
    usersNearLimit: number;
    cacheSize: number;
    cacheHitRate: number;
    timestamp: number;
  } {
    const users = Array.from(this.userRateLimits.values());
    const activeUsers = users.filter(u => u.callsLastHour > 0);
    
    const totalCalls = users.reduce((sum, u) => sum + u.callsLastHour, 0);
    
    const usersNearLimit = users.filter(u => {
      const usage = u.callsLastHour / this.USER_LIMIT_PER_HOUR;
      return usage >= this.WARNING_THRESHOLD;
    }).length;

    return {
      totalUsers: users.length,
      activeUsers: activeUsers.length,
      totalCalls,
      globalCalls: this.globalCalls,
      avgCallsPerUser: users.length > 0 ? totalCalls / users.length : 0,
      usersNearLimit,
      cacheSize: this.responseCache.size,
      cacheHitRate: 0, // Would need separate tracking for accurate hit rate
      timestamp: Date.now(),
    };
  }

  /**
   * Clear cache (for testing or manual cleanup)
   */
  clearCache(): void {
    this.responseCache.clear();
  }

  /**
   * Clear all usage stats (for testing)
   */
  clear(): void {
    this.userRateLimits.clear();
    this.globalCalls = 0;
    this.globalLastReset = Date.now();
    this.responseCache.clear();
  }
}

// Singleton instance
export const facebookRateLimiter = new FacebookRateLimiter();

// Start periodic summary logging (every 5 minutes in production)
if (process.env.NODE_ENV === 'production' || process.env.FB_ENABLE_RATE_SUMMARY === 'true') {
  const SUMMARY_INTERVAL = 5 * 60 * 1000; // 5 minutes
  
  setInterval(() => {
    const summary = facebookRateLimiter.getSummary();
    
    if (summary.activeUsers > 0) {
      console.log('[FB Rate] Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`[FB Rate] Total Users: ${summary.totalUsers} | Active: ${summary.activeUsers}`);
      console.log(`[FB Rate] Total Calls: ${summary.totalCalls} | Global: ${summary.globalCalls}`);
      console.log(`[FB Rate] Avg Calls/User: ${summary.avgCallsPerUser.toFixed(1)}`);
      console.log(`[FB Rate] Cache Size: ${summary.cacheSize} entries`);
      
      if (summary.usersNearLimit > 0) {
        console.warn(`[FB Rate] ⚠️  Users Near Limit: ${summary.usersNearLimit}`);
      }
      
      // Log per-user breakdown if there are warnings
      const allUsage = facebookRateLimiter.getAllUsageStats();
      const usersWithWarnings = allUsage.filter(u => u.warnings > 0);
      
      if (usersWithWarnings.length > 0) {
        console.log('[FB Rate] Per-User Breakdown:');
        usersWithWarnings.forEach(usage => {
          const pct = (usage.callsLastHour / 200 * 100).toFixed(1);
          console.log(
            `[FB Rate]   • ${usage.userId.substring(0, 12)}... | ` +
            `Calls: ${usage.callsLastHour}/200 (${pct}%) | ` +
            `Warnings: ${usage.warnings}`
          );
        });
      }
      
      console.log('[FB Rate] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    }
  }, SUMMARY_INTERVAL);
}

