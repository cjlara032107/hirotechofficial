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

  /**
   * Get the next available API key in round-robin fashion
   * Automatically skips rate-limited and disabled keys
   */
  async getNextKey(): Promise<string | null> {
    try {
      // Refresh cache if stale
      const now = Date.now();
      if (now - this.lastRefresh > this.CACHE_TTL || this.activeKeyIds.length === 0) {
        await this.refreshActiveKeys();
      }

      if (this.activeKeyIds.length === 0) {
        console.warn('[ApiKeyManager] No active keys available');
        return null;
      }

      // Round-robin selection
      const keyId = this.activeKeyIds[this.currentIndex];
      this.currentIndex = (this.currentIndex + 1) % this.activeKeyIds.length;

      // Get and decrypt the key
      const apiKeyRecord = await prisma.apiKey.findUnique({
        where: { id: keyId },
      });

      if (!apiKeyRecord || apiKeyRecord.status !== ApiKeyStatus.ACTIVE) {
        // Key was disabled or rate-limited since cache refresh, refresh and retry
        await this.refreshActiveKeys();
        if (this.activeKeyIds.length === 0) {
          return null;
        }
        // Try again with fresh cache
        return this.getNextKey();
      }

      // Update last used timestamp
      await prisma.apiKey.update({
        where: { id: keyId },
        data: { lastUsedAt: new Date() },
      }).catch((err: unknown) => {
        // Non-critical, just log
        console.warn('[ApiKeyManager] Failed to update lastUsedAt:', err);
      });

      // Decrypt and return the key
      const decryptedKey = decryptKey(apiKeyRecord.encryptedKey);
      
      console.log(`[ApiKeyManager] Using key ${keyId} (${apiKeyRecord.name || 'unnamed'})`);
      
      return decryptedKey;
    } catch (error) {
      console.error('[ApiKeyManager] Error getting next key:', error);
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
        },
        orderBy: {
          createdAt: 'asc',
        },
      });

      this.activeKeyIds = activeKeys.map((k: { id: string }) => k.id);
      this.lastRefresh = Date.now();
      
      if (this.activeKeyIds.length > 0) {
        // Reset index to avoid out-of-bounds
        this.currentIndex = this.currentIndex % this.activeKeyIds.length;
        console.log(`[ApiKeyManager] Refreshed active keys cache: ${this.activeKeyIds.length} keys available`);
      }
    } catch (error) {
      console.error('[ApiKeyManager] Error refreshing active keys:', error);
      this.activeKeyIds = [];
    }
  }

  /**
   * Mark a key as rate-limited
   * Sets status to RATE_LIMITED and records the timestamp
   */
  async markRateLimited(keyIdOrDecryptedKey: string): Promise<void> {
    try {
      // Find key by ID or by matching decrypted key
      const apiKey = await this.findKeyByIdOrValue(keyIdOrDecryptedKey);

      if (!apiKey) {
        console.warn('[ApiKeyManager] Key not found for rate limit marking');
        return;
      }

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
      
      console.log(`[ApiKeyManager] Marked key ${apiKey.id} as rate-limited`);
    } catch (error) {
      console.error('[ApiKeyManager] Error marking key as rate-limited:', error);
    }
  }

  /**
   * Record a successful API call
   */
  async recordSuccess(keyIdOrDecryptedKey: string): Promise<void> {
    try {
      const apiKey = await this.findKeyByIdOrValue(keyIdOrDecryptedKey);

      if (!apiKey) {
        return;
      }

      await prisma.apiKey.update({
        where: { id: apiKey.id },
        data: {
          lastSuccessAt: new Date(),
          lastUsedAt: new Date(),
          consecutiveFailures: 0, // Reset on success
          totalRequests: { increment: 1 },
        },
      });
    } catch (error) {
      // Non-critical, just log
      console.warn('[ApiKeyManager] Error recording success:', error);
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

