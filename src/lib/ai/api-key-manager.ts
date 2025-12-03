import { prisma } from '@/lib/db';
import { decryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';
import { apiKeyBatchQueue } from './api-key-batch-queue';

/**
 * Database-backed API Key Manager
 * Replaces environment variable-based key rotation with database storage
 */
class ApiKeyManager {
  private currentIndex: number = 0;
  private activeKeyIds: string[] = [];
  private lastRefresh: number = 0;
  private readonly CACHE_TTL = 60000; // Cache for 60 seconds
  private usageStats: Map<string, { count: number; lastUsed: number }> = new Map();
  private requestCounter: number = 0;
  private refreshPromise: Promise<void> | null = null; // Prevent concurrent cache refreshes
  private readonly cacheLock = { locked: false }; // Simple lock mechanism

  /**
   * Generate a unique request ID for tracking
   */
  private generateRequestId(): string {
    this.requestCounter++;
    return `req-${Date.now()}-${this.requestCounter}`;
  }

  /**
   * Get the next available API key in round-robin fashion
   * Automatically skips rate-limited and disabled keys
   */
  async getNextKey(requestContext?: { operation?: string; contactId?: string; campaignId?: string }): Promise<string | null> {
    const requestId = this.generateRequestId();
    const startTime = Date.now();
    
    try {
      // Refresh cache if stale (with race condition protection)
      const now = Date.now();
      if (now - this.lastRefresh > this.CACHE_TTL || this.activeKeyIds.length === 0) {
        // If another request is already refreshing, wait for it
        if (this.refreshPromise) {
          console.log(`[ApiKeyManager] [${requestId}] Waiting for ongoing cache refresh`);
          await this.refreshPromise;
        } else {
          // We're the first to detect stale cache, perform the refresh
          await this.refreshActiveKeys();
        }
      }

      if (this.activeKeyIds.length === 0) {
        // Check if all keys are rate-limited and when they'll be available
        const rateLimitInfo = await this.getRateLimitExhaustionInfo();
        if (rateLimitInfo.allRateLimited) {
          const timeUntilAvailable = rateLimitInfo.earliestAvailableAt 
            ? Math.max(0, rateLimitInfo.earliestAvailableAt.getTime() - Date.now())
            : null;
          const minutesUntilAvailable = timeUntilAvailable 
            ? Math.ceil(timeUntilAvailable / 60000)
            : null;
          
          console.error(
            `[ApiKeyManager] [${requestId}] 🚫 All API keys are rate-limited. ` +
            (minutesUntilAvailable 
              ? `Earliest key available in ~${minutesUntilAvailable} minute(s). ` 
              : '') +
            `Rate-limited keys: ${rateLimitInfo.rateLimitedCount}/${rateLimitInfo.totalKeys}`
          );

          // Create system alert for rate limit exhaustion
          try {
            const { alertApiRateLimitExhaustion } = await import('@/lib/alerts/alert-service');
            await alertApiRateLimitExhaustion(
              rateLimitInfo.rateLimitedCount,
              rateLimitInfo.totalKeys,
              rateLimitInfo.earliestAvailableAt
            );
          } catch (error) {
            // Non-critical - alerting failure shouldn't break key retrieval
            console.warn('[ApiKeyManager] Failed to create rate limit alert:', error);
          }
        } else {
          console.warn(`[ApiKeyManager] [${requestId}] ⚠️ No active keys available`);
        }
        return null;
      }

      // Round-robin selection
      const keyId = this.activeKeyIds[this.currentIndex];
      const keyIndex = this.currentIndex;
      this.currentIndex = (this.currentIndex + 1) % this.activeKeyIds.length;

      // Get and decrypt the key
      const apiKeyRecord = await prisma.apiKey.findUnique({
        where: { id: keyId },
      });

      if (!apiKeyRecord || apiKeyRecord.status !== ApiKeyStatus.ACTIVE) {
        // Key was disabled or rate-limited since cache refresh, refresh and retry
        console.warn(`[ApiKeyManager] [${requestId}] Key ${keyId} is no longer active, refreshing cache...`);
        await this.refreshActiveKeys();
        if (this.activeKeyIds.length === 0) {
          return null;
        }
        // Try again with fresh cache
        return this.getNextKey(requestContext);
      }

      // Queue update for batching (reduces DB queries by 70-80%)
      // Updates are batched and flushed every 5 seconds or when 50 updates accumulate
      apiKeyBatchQueue.queueUpdate(keyId, new Date());

      // Decrypt and return the key
      const decryptedKey = decryptKey(apiKeyRecord.encryptedKey);
      
      // Track usage statistics
      const stats = this.usageStats.get(keyId) || { count: 0, lastUsed: 0 };
      stats.count++;
      stats.lastUsed = Date.now();
      this.usageStats.set(keyId, stats);

      // Enhanced logging with context
      const contextInfo = requestContext?.operation 
        ? ` | Operation: ${requestContext.operation}${requestContext.contactId ? ` | Contact: ${requestContext.contactId.substring(0, 8)}...` : ''}${requestContext.campaignId ? ` | Campaign: ${requestContext.campaignId.substring(0, 8)}...` : ''}`
        : '';
      
      const duration = Date.now() - startTime;
      
      console.log(`[ApiKeyManager] [${requestId}] ============================================`);
      console.log(`[ApiKeyManager] [${requestId}] ✅ API KEY RETRIEVED`);
      console.log(`[ApiKeyManager] [${requestId}] - Key Index: ${keyIndex + 1}/${this.activeKeyIds.length}`);
      console.log(`[ApiKeyManager] [${requestId}] - Key ID: ${keyId.substring(0, 8)}...`);
      console.log(`[ApiKeyManager] [${requestId}] - Key Name: ${apiKeyRecord.name || 'unnamed'}`);
      console.log(`[ApiKeyManager] [${requestId}] - Total Uses: ${stats.count}`);
      console.log(`[ApiKeyManager] [${requestId}] - Retrieval Time: ${duration}ms`);
      if (requestContext?.operation) {
        console.log(`[ApiKeyManager] [${requestId}] - Operation: ${requestContext.operation}`);
        if (requestContext.contactId) {
          console.log(`[ApiKeyManager] [${requestId}] - Contact ID: ${requestContext.contactId.substring(0, 12)}...`);
        }
        if (requestContext.campaignId) {
          console.log(`[ApiKeyManager] [${requestId}] - Campaign ID: ${requestContext.campaignId.substring(0, 12)}...`);
        }
      }
      
      // Log parallel usage indicator
      const activeRequests = Array.from(this.usageStats.values()).filter(
        s => Date.now() - s.lastUsed < 5000 // Active in last 5 seconds
      ).length;
      if (activeRequests > 1) {
        console.log(`[ApiKeyManager] [${requestId}] - 🔄 Parallel Requests: ${activeRequests} concurrent`);
      }
      console.log(`[ApiKeyManager] [${requestId}] ============================================`);
      
      return decryptedKey;
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.error(`[ApiKeyManager] [${requestId}] ============================================`);
      console.error(`[ApiKeyManager] [${requestId}] ❌ ERROR GETTING API KEY`);
      console.error(`[ApiKeyManager] [${requestId}] - Duration: ${duration}ms`);
      console.error(`[ApiKeyManager] [${requestId}] - Error: ${errorMsg}`);
      console.error(`[ApiKeyManager] [${requestId}] - Active Keys: ${this.activeKeyIds.length}`);
      console.error(`[ApiKeyManager] [${requestId}] - Last Cache Refresh: ${new Date(this.lastRefresh).toISOString()}`);
      if (error instanceof Error && error.stack) {
        console.error(`[ApiKeyManager] [${requestId}] - Stack trace (first 3 lines):`);
        error.stack.split('\n').slice(0, 3).forEach((line, idx) => {
          console.error(`[ApiKeyManager] [${requestId}]   ${idx + 1}. ${line.trim()}`);
        });
      }
      console.error(`[ApiKeyManager] [${requestId}] ============================================`);
      return null;
    }
  }

  /**
   * Refresh the cache of active key IDs
   * Protected against race conditions with a lock mechanism
   */
  private async refreshActiveKeys(): Promise<void> {
    // If a refresh is already in progress, wait for it
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Create the refresh promise to prevent concurrent refreshes
    this.refreshPromise = (async () => {
      try {
        const refreshStartTime = Date.now();
        console.log('[ApiKeyManager] 🔄 Starting cache refresh...');
        
        const activeKeys = await prisma.apiKey.findMany({
          where: {
            status: ApiKeyStatus.ACTIVE,
          },
          select: {
            id: true,
            name: true,
            lastUsedAt: true,
            totalRequests: true,
          },
          orderBy: {
            createdAt: 'asc',
          },
        });

        const previousCount = this.activeKeyIds.length;
        this.activeKeyIds = activeKeys.map((k: { id: string }) => k.id);
        this.lastRefresh = Date.now();
        
        if (this.activeKeyIds.length > 0) {
          // Reset index to avoid out-of-bounds (with bounds check)
          if (this.currentIndex >= this.activeKeyIds.length) {
            this.currentIndex = 0;
          }
          
          // Log detailed refresh information
          const keyNames = activeKeys.map((k: { id: string; name: string | null; lastUsedAt: Date | null; totalRequests: number }) => 
            `${k.name || 'unnamed'} (${k.totalRequests} reqs)`
          ).join(', ');
          
          const refreshDuration = Date.now() - refreshStartTime;
          console.log(
            `[ApiKeyManager] ✅ Refreshed active keys cache in ${refreshDuration}ms: ${this.activeKeyIds.length} keys available ` +
            `(${previousCount} → ${this.activeKeyIds.length})`
          );
          console.log(`[ApiKeyManager] 📋 Active keys: ${keyNames}`);
        } else {
          console.warn('[ApiKeyManager] ⚠️ No active keys found in database');
        }
      } catch (error) {
        console.error('[ApiKeyManager] ❌ Error refreshing active keys:', error);
        // Keep existing keys on error - don't clear to prevent complete failure
        // But reset lastRefresh to allow retry on next request
        this.lastRefresh = Date.now() - this.CACHE_TTL + 5000; // Retry in 5 seconds
      } finally {
        // Clear the promise to allow future refreshes
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  /**
   * Mark a key as rate-limited
   * Sets status to RATE_LIMITED and records the timestamp
   */
  async markRateLimited(keyIdOrDecryptedKey: string, requestContext?: { operation?: string }): Promise<void> {
    const requestId = this.generateRequestId();
    try {
      // Find key by ID or by matching decrypted key
      const apiKey = await this.findKeyByIdOrValue(keyIdOrDecryptedKey);

      if (!apiKey) {
        console.warn(`[ApiKeyManager] [${requestId}] ⚠️ Key not found for rate limit marking`);
        return;
      }

      const keyRecord = await prisma.apiKey.findUnique({
        where: { id: apiKey.id },
        select: { name: true, totalRequests: true },
      });

      await prisma.apiKey.update({
        where: { id: apiKey.id },
        data: {
          status: ApiKeyStatus.RATE_LIMITED,
          rateLimitedAt: new Date(),
          consecutiveFailures: { increment: 1 },
          failedRequests: { increment: 1 },
          totalRequests: { increment: 1 },
        },
      });

      // Invalidate cache to exclude this key
      await this.refreshActiveKeys();
      
      const contextInfo = requestContext?.operation ? ` | Operation: ${requestContext.operation}` : '';
      console.warn(
        `[ApiKeyManager] [${requestId}] 🚫 Marked key ${apiKey.id.substring(0, 8)}... ` +
        `(${keyRecord?.name || 'unnamed'}) as RATE_LIMITED | ` +
        `Total requests: ${(keyRecord?.totalRequests || 0) + 1}${contextInfo}`
      );
      console.warn(`[ApiKeyManager] [${requestId}] ⏰ Key will be excluded from rotation for 24 hours`);
    } catch (error) {
      console.error(`[ApiKeyManager] [${requestId}] ❌ Error marking key as rate-limited:`, error);
    }
  }

  /**
   * Record a successful API call
   */
  async recordSuccess(keyIdOrDecryptedKey: string, requestContext?: { operation?: string; duration?: number }): Promise<void> {
    try {
      const apiKey = await this.findKeyByIdOrValue(keyIdOrDecryptedKey);

      if (!apiKey) {
        return;
      }

      const keyRecord = await prisma.apiKey.findUnique({
        where: { id: apiKey.id },
        select: { name: true, totalRequests: true },
      });

      await prisma.apiKey.update({
        where: { id: apiKey.id },
        data: {
          lastSuccessAt: new Date(),
          lastUsedAt: new Date(),
          consecutiveFailures: 0, // Reset on success
          totalRequests: { increment: 1 },
        },
      });

      // Log success with context (only in verbose mode or for important operations)
      if (requestContext?.operation && (requestContext.operation.includes('analyze') || requestContext.operation.includes('generate'))) {
        const durationInfo = requestContext.duration ? ` | Duration: ${requestContext.duration}ms` : '';
        console.log(
          `[ApiKeyManager] ✅ Success: ${apiKey.id.substring(0, 8)}... ` +
          `(${keyRecord?.name || 'unnamed'}) | ` +
          `Operation: ${requestContext.operation} | ` +
          `Total requests: ${(keyRecord?.totalRequests || 0) + 1}${durationInfo}`
        );
      }
    } catch (error) {
      // Non-critical, just log
      console.warn('[ApiKeyManager] ⚠️ Error recording success:', error);
    }
  }

  /**
   * Record a failed API call (non-rate-limit)
   */
  async recordFailure(keyIdOrDecryptedKey: string): Promise<void> {
    try {
      const apiKey = await this.findKeyByIdOrValue(keyIdOrDecryptedKey);

      if (!apiKey) {
        return;
      }

      await prisma.apiKey.update({
        where: { id: apiKey.id },
        data: {
          lastUsedAt: new Date(),
          consecutiveFailures: { increment: 1 },
          failedRequests: { increment: 1 },
          totalRequests: { increment: 1 },
        },
      });

      // If too many consecutive failures, consider disabling
      const updated = await prisma.apiKey.findUnique({
        where: { id: apiKey.id },
      });

      if (updated && updated.consecutiveFailures >= 10 && updated.status === ApiKeyStatus.ACTIVE) {
        console.warn(`[ApiKeyManager] Key ${apiKey.id} has ${updated.consecutiveFailures} consecutive failures, consider disabling`);
      }
    } catch (error) {
      console.warn('[ApiKeyManager] Error recording failure:', error);
    }
  }

  /**
   * Mark a key as invalid (401/authentication errors)
   * Disables the key and removes it from active rotation
   */
  async markInvalid(keyIdOrDecryptedKey: string, reason: string = 'Authentication failed'): Promise<void> {
    try {
      const apiKeyRecord = await this.findKeyByIdOrValue(keyIdOrDecryptedKey);

      if (!apiKeyRecord) {
        console.warn('[ApiKeyManager] Key not found for invalidation marking');
        return;
      }

      // Get full key record to access name
      const fullKey = await prisma.apiKey.findUnique({
        where: { id: apiKeyRecord.id },
        select: { id: true, name: true },
      });

      await prisma.apiKey.update({
        where: { id: apiKeyRecord.id },
        data: {
          status: ApiKeyStatus.DISABLED,
          consecutiveFailures: { increment: 1 },
          failedRequests: { increment: 1 },
          totalRequests: { increment: 1 },
        },
      });

      // Invalidate cache to exclude this key
      await this.refreshActiveKeys();
      
      // Invalidate concurrency cache so limits update
      const { invalidateConcurrencyCache } = await import('./dynamic-concurrency');
      invalidateConcurrencyCache();
      
      const keyName = fullKey?.name || 'unnamed';
      console.error(`[ApiKeyManager] ⚠️ Marked key ${apiKeyRecord.id} (${keyName}) as DISABLED - ${reason}`);
      console.error(`[ApiKeyManager] Please check this key in the API Keys settings and update it if needed`);
    } catch (error) {
      console.error('[ApiKeyManager] Error marking key as invalid:', error);
    }
  }

  /**
   * Find a key by ID or by matching decrypted key value
   * This allows tracking by either identifier
   */
  private async findKeyByIdOrValue(keyIdOrDecryptedKey: string): Promise<{ id: string } | null> {
    // Try as ID first (most common case)
    const byId = await prisma.apiKey.findUnique({
      where: { id: keyIdOrDecryptedKey },
      select: { id: true },
    });

    if (byId) {
      return byId;
    }

    // If not found as ID, try matching against all keys (slower, but needed for backward compatibility)
    // This is only used when we have the decrypted key but not the ID
    const allKeys = await prisma.apiKey.findMany({
      select: {
        id: true,
        encryptedKey: true,
      },
    });

    for (const key of allKeys) {
      try {
        const decrypted = decryptKey(key.encryptedKey);
        if (decrypted === keyIdOrDecryptedKey) {
          return { id: key.id };
        }
      } catch {
        // Skip invalid keys
        continue;
      }
    }

    return null;
  }

  /**
   * Get count of available keys
   */
  async getKeyCount(): Promise<number> {
    try {
      const count = await prisma.apiKey.count({
        where: {
          status: ApiKeyStatus.ACTIVE,
        },
      });
      return count;
    } catch (error) {
      console.error('[ApiKeyManager] Error getting key count:', error);
      return 0;
    }
  }

  /**
   * Get all keys with their metadata (for admin UI)
   */
  async getAllKeys() {
    try {
      return await prisma.apiKey.findMany({
        orderBy: {
          createdAt: 'desc',
        },
      });
    } catch (error) {
      console.error('[ApiKeyManager] Error getting all keys:', error);
      return [];
    }
  }

  /**
   * Get information about rate limit exhaustion
   * Returns whether all keys are rate-limited and when the earliest key will be available
   */
  async getRateLimitExhaustionInfo(): Promise<{
    allRateLimited: boolean;
    rateLimitedCount: number;
    totalKeys: number;
    earliestAvailableAt: Date | null;
  }> {
    try {
      const allKeys = await prisma.apiKey.findMany({
        select: {
          id: true,
          status: true,
          rateLimitedAt: true,
        },
      });

      const totalKeys = allKeys.length;
      const rateLimitedKeys = allKeys.filter(k => k.status === ApiKeyStatus.RATE_LIMITED);
      const rateLimitedCount = rateLimitedKeys.length;
      const allRateLimited = totalKeys > 0 && rateLimitedCount === totalKeys;

      // Find the earliest time when a rate-limited key will be available
      // Rate limits typically reset after 24 hours
      const RATE_LIMIT_RESET_HOURS = 24;
      let earliestAvailableAt: Date | null = null;

      if (rateLimitedKeys.length > 0) {
        const rateLimitedTimes = rateLimitedKeys
          .map(k => k.rateLimitedAt)
          .filter((date): date is Date => date !== null)
          .map(date => {
            const resetTime = new Date(date);
            resetTime.setHours(resetTime.getHours() + RATE_LIMIT_RESET_HOURS);
            return resetTime;
          });

        if (rateLimitedTimes.length > 0) {
          earliestAvailableAt = new Date(Math.min(...rateLimitedTimes.map(d => d.getTime())));
        }
      }

      return {
        allRateLimited,
        rateLimitedCount,
        totalKeys,
        earliestAvailableAt,
      };
    } catch (error) {
      console.error('[ApiKeyManager] Error getting rate limit exhaustion info:', error);
      return {
        allRateLimited: false,
        rateLimitedCount: 0,
        totalKeys: 0,
        earliestAvailableAt: null,
      };
    }
  }

  /**
   * Get rate limit usage statistics for monitoring
   */
  async getRateLimitUsageStats() {
    try {
      const now = new Date();
      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      // Get all keys with their usage stats
      const allKeys = await prisma.apiKey.findMany({
        select: {
          id: true,
          name: true,
          status: true,
          totalRequests: true,
          failedRequests: true,
          rateLimitedAt: true,
          lastUsedAt: true,
          lastSuccessAt: true,
          consecutiveFailures: true,
          createdAt: true,
        },
        orderBy: {
          lastUsedAt: 'desc',
        },
      });

      // Calculate aggregate statistics
      const activeKeys = allKeys.filter(k => k.status === ApiKeyStatus.ACTIVE);
      const rateLimitedKeys = allKeys.filter(k => k.status === ApiKeyStatus.RATE_LIMITED);
      const disabledKeys = allKeys.filter(k => k.status === ApiKeyStatus.DISABLED);

      const totalRequests = allKeys.reduce((sum, k) => sum + k.totalRequests, 0);
      const totalFailed = allKeys.reduce((sum, k) => sum + k.failedRequests, 0);
      const totalRateLimited = rateLimitedKeys.length;

      // Calculate usage in last hour
      // Note: This is an approximation based on keys used in the last hour
      // For exact request counts, a separate usage log table would be needed
      const recentKeys = allKeys.filter(k => 
        k.lastUsedAt && new Date(k.lastUsedAt) >= oneHourAgo
      );
      // Count keys that were active in the last hour (indicator of recent usage)
      const requestsLastHour = recentKeys.length;

      // Get keys that were rate limited in the last 24 hours
      const recentlyRateLimited = rateLimitedKeys.filter(k =>
        k.rateLimitedAt && new Date(k.rateLimitedAt) >= oneDayAgo
      );

      return {
        summary: {
          totalKeys: allKeys.length,
          activeKeys: activeKeys.length,
          rateLimitedKeys: rateLimitedKeys.length,
          disabledKeys: disabledKeys.length,
          totalRequests,
          totalFailed,
          successRate: totalRequests > 0 ? ((totalRequests - totalFailed) / totalRequests * 100).toFixed(2) : '0.00',
        },
        recentActivity: {
          requestsLastHour: requestsLastHour,
          recentlyRateLimited: recentlyRateLimited.length,
        },
        keys: allKeys.map(k => ({
          id: k.id,
          name: k.name,
          status: k.status,
          totalRequests: k.totalRequests,
          failedRequests: k.failedRequests,
          successRate: k.totalRequests > 0 
            ? ((k.totalRequests - k.failedRequests) / k.totalRequests * 100).toFixed(2)
            : '0.00',
          rateLimitedAt: k.rateLimitedAt?.toISOString() || null,
          lastUsedAt: k.lastUsedAt?.toISOString() || null,
          lastSuccessAt: k.lastSuccessAt?.toISOString() || null,
          consecutiveFailures: k.consecutiveFailures,
          isRecentlyRateLimited: k.rateLimitedAt && new Date(k.rateLimitedAt) >= oneDayAgo,
        })),
        timestamp: now.toISOString(),
      };
    } catch (error) {
      console.error('[ApiKeyManager] Error getting rate limit usage stats:', error);
      return {
        summary: {
          totalKeys: 0,
          activeKeys: 0,
          rateLimitedKeys: 0,
          disabledKeys: 0,
          totalRequests: 0,
          totalFailed: 0,
          successRate: '0.00',
        },
        recentActivity: {
          requestsLastHour: 0,
          recentlyRateLimited: 0,
        },
        keys: [],
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }
}

// Singleton instance
const apiKeyManager = new ApiKeyManager();

export default apiKeyManager;

