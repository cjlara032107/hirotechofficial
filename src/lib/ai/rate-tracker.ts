/**
 * Per-Key Rate Tracker
 * 
 * Tracks rate usage per API key for Google AI service
 * Logs when approaching limits (>80% of quota)
 * 
 * Google AI Rate Limits (per key):
 * - 15 requests/minute
 * - 32k tokens/minute
 * - 1500 requests/day
 */

export interface RateUsage {
  keyId: string;
  requestsPerMinute: number;
  tokensPerMinute: number;
  requestsPerDay: number;
  lastReset: number;
  warnings: number;
}

export interface RateTrackingLog {
  keyId: string;
  operation: string;
  priority: string;
  tokens: number;
  reqId: string;
  timestamp: number;
  elapsedMs?: number;
  success?: boolean;
  errorCode?: string;
  retryCount?: number;
  delayMs?: number;
  attempt?: number;
}

/**
 * Rate Tracker for AI API Keys
 * Monitors usage and warns when approaching limits
 */
class RateTracker {
  private keyUsage = new Map<string, RateUsage>();
  private readonly MINUTE_WINDOW = 60 * 1000; // 60 seconds
  private readonly DAY_WINDOW = 24 * 60 * 60 * 1000; // 24 hours
  private readonly REQUEST_LIMIT_PER_MINUTE = 15;
  private readonly TOKEN_LIMIT_PER_MINUTE = 32000;
  private readonly REQUEST_LIMIT_PER_DAY = 1500;
  private readonly WARNING_THRESHOLD = 0.8; // 80%

  /**
   * Get or initialize usage stats for a key
   */
  private getUsage(keyId: string): RateUsage {
    let usage = this.keyUsage.get(keyId);
    
    if (!usage) {
      usage = {
        keyId,
        requestsPerMinute: 0,
        tokensPerMinute: 0,
        requestsPerDay: 0,
        lastReset: Date.now(),
        warnings: 0,
      };
      this.keyUsage.set(keyId, usage);
    }

    // Reset counters if window has passed
    const now = Date.now();
    const minuteElapsed = now - usage.lastReset;
    
    if (minuteElapsed >= this.MINUTE_WINDOW) {
      // Reset minute counters
      usage.requestsPerMinute = 0;
      usage.tokensPerMinute = 0;
      usage.lastReset = now;
    }

    if (minuteElapsed >= this.DAY_WINDOW) {
      // Reset day counters
      usage.requestsPerDay = 0;
    }

    return usage;
  }

  /**
   * Log request start
   */
  logRequestStart(params: {
    keyId: string;
    operation: string;
    priority: string;
    tokens: number;
    reqId: string;
  }): void {
    const { keyId, operation, priority, tokens, reqId } = params;
    
    console.log(`[AI Rate] Request start | keyId: ${keyId.substring(0, 12)}... | operation: ${operation} | priority: ${priority} | tokens: ${tokens} | reqId: ${reqId}`);
    
    // Track usage
    const usage = this.getUsage(keyId);
    usage.requestsPerMinute++;
    usage.tokensPerMinute += tokens;
    usage.requestsPerDay++;

    // Check for warnings
    this.checkThresholds(usage);
  }

  /**
   * Log request completion
   */
  logRequestComplete(params: {
    keyId: string;
    operation: string;
    elapsedMs: number;
    success: boolean;
    errorCode?: string;
    retryCount?: number;
    reqId: string;
  }): void {
    const { keyId, operation, elapsedMs, success, errorCode, retryCount, reqId } = params;
    
    const status = success ? 'Success' : 'Fail';
    const errorInfo = errorCode ? ` | errorCode: ${errorCode}` : '';
    const retryInfo = retryCount !== undefined && retryCount > 0 ? ` | retries: ${retryCount}` : '';
    
    console.log(`[AI Rate] ${status} | keyId: ${keyId.substring(0, 12)}... | operation: ${operation} | elapsed: ${elapsedMs}ms${retryInfo}${errorInfo} | reqId: ${reqId}`);
  }

  /**
   * Log backoff/retry
   */
  logBackoff(params: {
    keyId: string;
    operation: string;
    delayMs: number;
    attempt: number;
    reqId: string;
  }): void {
    const { keyId, operation, delayMs, attempt, reqId } = params;
    
    console.log(`[AI Rate] Backoff | keyId: ${keyId.substring(0, 12)}... | operation: ${operation} | delay: ${delayMs}ms | attempt: ${attempt} | reqId: ${reqId}`);
  }

  /**
   * Check thresholds and log warnings
   */
  private checkThresholds(usage: RateUsage): void {
    const reqPerMinPct = usage.requestsPerMinute / this.REQUEST_LIMIT_PER_MINUTE;
    const tokensPerMinPct = usage.tokensPerMinute / this.TOKEN_LIMIT_PER_MINUTE;
    const reqPerDayPct = usage.requestsPerDay / this.REQUEST_LIMIT_PER_DAY;

    // Warn if approaching limits
    if (reqPerMinPct >= this.WARNING_THRESHOLD && usage.requestsPerMinute % 5 === 0) {
      console.warn(
        `[AI Rate] ⚠️  High usage | keyId: ${usage.keyId.substring(0, 12)}... | ` +
        `requests/min: ${usage.requestsPerMinute}/${this.REQUEST_LIMIT_PER_MINUTE} (${(reqPerMinPct * 100).toFixed(1)}%)`
      );
      usage.warnings++;
    }

    if (tokensPerMinPct >= this.WARNING_THRESHOLD && usage.tokensPerMinute % 10000 === 0) {
      console.warn(
        `[AI Rate] ⚠️  High token usage | keyId: ${usage.keyId.substring(0, 12)}... | ` +
        `tokens/min: ${usage.tokensPerMinute}/${this.TOKEN_LIMIT_PER_MINUTE} (${(tokensPerMinPct * 100).toFixed(1)}%)`
      );
      usage.warnings++;
    }

    if (reqPerDayPct >= this.WARNING_THRESHOLD && usage.requestsPerDay % 100 === 0) {
      console.warn(
        `[AI Rate] ⚠️  High daily usage | keyId: ${usage.keyId.substring(0, 12)}... | ` +
        `requests/day: ${usage.requestsPerDay}/${this.REQUEST_LIMIT_PER_DAY} (${(reqPerDayPct * 100).toFixed(1)}%)`
      );
      usage.warnings++;
    }
  }

  /**
   * Get current usage stats for all keys
   */
  getAllUsageStats(): RateUsage[] {
    return Array.from(this.keyUsage.values());
  }

  /**
   * Get usage stats for a specific key
   */
  getKeyUsageStats(keyId: string): RateUsage | null {
    return this.keyUsage.get(keyId) || null;
  }

  /**
   * Get aggregated summary for monitoring
   */
  getSummary(): {
    totalKeys: number;
    activeKeys: number;
    totalRequests: number;
    totalTokens: number;
    avgRequestsPerKey: number;
    avgTokensPerKey: number;
    keysNearLimit: number;
    timestamp: number;
  } {
    const keys = Array.from(this.keyUsage.values());
    const activeKeys = keys.filter(k => k.requestsPerMinute > 0 || k.tokensPerMinute > 0);
    
    const totalRequests = keys.reduce((sum, k) => sum + k.requestsPerMinute, 0);
    const totalTokens = keys.reduce((sum, k) => sum + k.tokensPerMinute, 0);
    
    const keysNearLimit = keys.filter(k => {
      const reqPct = k.requestsPerMinute / this.REQUEST_LIMIT_PER_MINUTE;
      const tokenPct = k.tokensPerMinute / this.TOKEN_LIMIT_PER_MINUTE;
      return reqPct >= this.WARNING_THRESHOLD || tokenPct >= this.WARNING_THRESHOLD;
    }).length;

    return {
      totalKeys: keys.length,
      activeKeys: activeKeys.length,
      totalRequests,
      totalTokens,
      avgRequestsPerKey: keys.length > 0 ? totalRequests / keys.length : 0,
      avgTokensPerKey: keys.length > 0 ? totalTokens / keys.length : 0,
      keysNearLimit,
      timestamp: Date.now(),
    };
  }

  /**
   * Clear all usage stats (for testing)
   */
  clear(): void {
    this.keyUsage.clear();
  }
}

// Singleton instance
export const rateTracker = new RateTracker();

// Start periodic summary logging (every 5 minutes in production)
if (process.env.NODE_ENV === 'production' || process.env.AI_ENABLE_RATE_SUMMARY === 'true') {
  const SUMMARY_INTERVAL = 5 * 60 * 1000; // 5 minutes
  
  setInterval(() => {
    const summary = rateTracker.getSummary();
    
    if (summary.activeKeys > 0) {
      console.log('[AI Rate] Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`[AI Rate] Total Keys: ${summary.totalKeys} | Active: ${summary.activeKeys}`);
      console.log(`[AI Rate] Total Req/Min: ${summary.totalRequests} | Total Tokens/Min: ${summary.totalTokens}`);
      console.log(`[AI Rate] Avg Req/Key: ${summary.avgRequestsPerKey.toFixed(1)} | Avg Tokens/Key: ${summary.avgTokensPerKey.toFixed(0)}`);
      
      if (summary.keysNearLimit > 0) {
        console.warn(`[AI Rate] ⚠️  Keys Near Limit: ${summary.keysNearLimit}`);
      }
      
      // Log per-key breakdown if there are warnings
      const allUsage = rateTracker.getAllUsageStats();
      const keysWithWarnings = allUsage.filter(k => k.warnings > 0);
      
      if (keysWithWarnings.length > 0) {
        console.log('[AI Rate] Per-Key Breakdown:');
        keysWithWarnings.forEach(usage => {
          console.log(
            `[AI Rate]   • ${usage.keyId.substring(0, 12)}... | ` +
            `Req: ${usage.requestsPerMinute}/15 | Tokens: ${usage.tokensPerMinute}/32k | ` +
            `Daily: ${usage.requestsPerDay}/1500 | Warnings: ${usage.warnings}`
          );
        });
      }
      
      console.log('[AI Rate] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    }
  }, SUMMARY_INTERVAL);
}

