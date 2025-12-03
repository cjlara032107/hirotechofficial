/**
 * Job Status Cache
 * 
 * Caches job status to reduce database queries during pipeline analysis.
 * Each job status is cached for a short TTL (5 seconds) to balance
 * freshness with query reduction.
 */

interface CachedStatus {
  status: string;
  timestamp: number;
}

class JobStatusCache {
  private cache: Map<string, CachedStatus> = new Map();
  private readonly TTL_MS = 5000; // 5 seconds TTL
  private readonly MAX_CACHE_SIZE = 1000; // Prevent memory leaks
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    // Start periodic cleanup (every 10 seconds)
    this.startCleanup();
  }

  /**
   * Check if a cached entry is expired
   */
  private isExpired(timestamp: number): boolean {
    return Date.now() - timestamp > this.TTL_MS;
  }

  /**
   * Get cached job status, or null if not cached or expired
   */
  async getStatus(jobId: string): Promise<string | null> {
    const cached = this.cache.get(jobId);
    
    if (!cached) {
      return null;
    }

    if (this.isExpired(cached.timestamp)) {
      // Remove expired entry
      this.cache.delete(jobId);
      return null;
    }

    return cached.status;
  }

  /**
   * Set job status in cache
   */
  setStatus(jobId: string, status: string): void {
    // Prevent memory leaks by limiting cache size
    if (this.cache.size >= this.MAX_CACHE_SIZE) {
      // Remove oldest entries (first 10% of cache)
      const entriesToRemove = Math.floor(this.MAX_CACHE_SIZE * 0.1);
      const sortedEntries = Array.from(this.cache.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp);
      
      for (let i = 0; i < entriesToRemove; i++) {
        this.cache.delete(sortedEntries[i][0]);
      }
    }

    this.cache.set(jobId, {
      status,
      timestamp: Date.now(),
    });
  }

  /**
   * Clear cache for a specific job
   */
  clear(jobId: string): void {
    this.cache.delete(jobId);
  }

  /**
   * Clear all cache entries
   */
  clearAll(): void {
    this.cache.clear();
  }

  /**
   * Clean up expired entries (lazy cleanup)
   */
  private cleanupExpired(): void {
    const now = Date.now();
    const expiredKeys: string[] = [];

    for (const [jobId, cached] of this.cache.entries()) {
      if (this.isExpired(cached.timestamp)) {
        expiredKeys.push(jobId);
      }
    }

    // Remove expired entries
    for (const key of expiredKeys) {
      this.cache.delete(key);
    }

    if (expiredKeys.length > 0) {
      console.log(`[JobStatusCache] Cleaned up ${expiredKeys.length} expired entries`);
    }
  }

  /**
   * Start periodic cleanup
   */
  private startCleanup(): void {
    if (this.cleanupInterval) {
      return; // Already started
    }

    this.cleanupInterval = setInterval(() => {
      this.cleanupExpired();
    }, 10000); // Clean up every 10 seconds
  }

  /**
   * Stop periodic cleanup
   */
  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; maxSize: number; ttl: number } {
    return {
      size: this.cache.size,
      maxSize: this.MAX_CACHE_SIZE,
      ttl: this.TTL_MS,
    };
  }
}

// Export singleton instance
export const jobStatusCache = new JobStatusCache();









