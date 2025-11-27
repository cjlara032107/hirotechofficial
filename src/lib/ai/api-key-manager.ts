import { prisma } from '@/lib/db';
import { decryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

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
      // Refresh cache if stale
      const now = Date.now();
      if (now - this.lastRefresh > this.CACHE_TTL || this.activeKeyIds.length === 0) {
        await this.refreshActiveKeys();
      }

      if (this.activeKeyIds.length === 0) {
        console.warn(`[ApiKeyManager] [${requestId}] ⚠️ No active keys available`);
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

      // Update last used timestamp
      await prisma.apiKey.update({
        where: { id: keyId },
        data: { lastUsedAt: new Date() },
      }).catch((err: unknown) => {
        // Non-critical, just log
        console.warn(`[ApiKeyManager] [${requestId}] Failed to update lastUsedAt:`, err);
      });

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
      
      console.log(
        `[ApiKeyManager] [${requestId}] ✅ Using key #${keyIndex + 1}/${this.activeKeyIds.length} ` +
        `(${keyId.substring(0, 8)}... | ${apiKeyRecord.name || 'unnamed'})` +
        ` | Total uses: ${stats.count}${contextInfo}`
      );
      
      // Log parallel usage indicator
      const activeRequests = Array.from(this.usageStats.values()).filter(
        s => Date.now() - s.lastUsed < 5000 // Active in last 5 seconds
      ).length;
      if (activeRequests > 1) {
        console.log(`[ApiKeyManager] [${requestId}] 🔄 Parallel processing: ${activeRequests} concurrent requests detected`);
      }
      
      return decryptedKey;
    } catch (error) {
      console.error(`[ApiKeyManager] [${requestId}] ❌ Error getting next key:`, error);
      return null;
    }
  }

  /**
   * Refresh the cache of active key IDs
   */
  private async refreshActiveKeys(): Promise<void> {
    try {
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
        // Reset index to avoid out-of-bounds
        this.currentIndex = this.currentIndex % this.activeKeyIds.length;
        
        // Log detailed refresh information
        const keyNames = activeKeys.map((k: { id: string; name: string | null; lastUsedAt: Date | null; totalRequests: number }) => 
          `${k.name || 'unnamed'} (${k.totalRequests} reqs)`
        ).join(', ');
        
        console.log(
          `[ApiKeyManager] 🔄 Refreshed active keys cache: ${this.activeKeyIds.length} keys available ` +
          `(${previousCount} → ${this.activeKeyIds.length})`
        );
        console.log(`[ApiKeyManager] 📋 Active keys: ${keyNames}`);
      } else {
        console.warn('[ApiKeyManager] ⚠️ No active keys found in database');
      }
    } catch (error) {
      console.error('[ApiKeyManager] ❌ Error refreshing active keys:', error);
      this.activeKeyIds = [];
    }
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
}

// Singleton instance
const apiKeyManager = new ApiKeyManager();

export default apiKeyManager;

