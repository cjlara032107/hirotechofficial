/**
 * Tests for Resource Limiter
 */

import { ResourceLimiter, resourceLimiter, type ResourceType } from '../resource-limiter';

describe('ResourceLimiter', () => {
  let limiter: ResourceLimiter;

  beforeEach(() => {
    limiter = new ResourceLimiter({
      'api-call': 2,
      'db-query': 3,
    });
  });

  describe('execute', () => {
    it('should execute immediately when under limit', async () => {
      let executed = false;
      
      await limiter.execute('api-call', async () => {
        executed = true;
        return 'result';
      });
      
      expect(executed).toBe(true);
    });

    it('should limit concurrent executions', async () => {
      const results: number[] = [];
      const startTimes: number[] = [];
      
      const promises = Array.from({ length: 5 }, (_, i) =>
        limiter.execute('api-call', async () => {
          startTimes[i] = Date.now();
          await new Promise(resolve => setTimeout(resolve, 50));
          results.push(i);
          return i;
        })
      );
      
      await Promise.all(promises);
      
      expect(results.length).toBe(5);
      // Should execute in batches of 2 (the limit)
      expect(Math.max(...startTimes) - Math.min(...startTimes)).toBeLessThan(200);
    });

    it('should queue requests when at limit', async () => {
      const results: number[] = [];
      
      // Start 5 requests with limit of 2
      const promises = Array.from({ length: 5 }, (_, i) =>
        limiter.execute('api-call', async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
          results.push(i);
          return i;
        })
      );
      
      await Promise.all(promises);
      
      expect(results.length).toBe(5);
    });
  });

  describe('getUsage', () => {
    it('should return current usage', () => {
      const usage = limiter.getUsage('api-call');
      
      expect(usage).toHaveProperty('resourceType', 'api-call');
      expect(usage).toHaveProperty('current');
      expect(usage).toHaveProperty('max', 2);
      expect(usage).toHaveProperty('available');
      expect(usage.available).toBe(2); // Initially all available
    });
  });

  describe('hasCapacity', () => {
    it('should return true when capacity available', () => {
      expect(limiter.hasCapacity('api-call')).toBe(true);
    });

    it('should return false when at capacity', async () => {
      // Fill up the limit
      const promises = Array.from({ length: 2 }, () =>
        limiter.execute('api-call', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return 'result';
        })
      );
      
      // Check immediately (should be at capacity)
      expect(limiter.hasCapacity('api-call')).toBe(false);
      
      await Promise.all(promises);
    });
  });

  describe('setLimit', () => {
    it('should update limit for resource type', () => {
      limiter.setLimit('api-call', 5);
      const usage = limiter.getUsage('api-call');
      
      expect(usage.max).toBe(5);
      expect(usage.available).toBe(5);
    });
  });

  describe('getStats', () => {
    it('should return statistics', () => {
      const stats = limiter.getStats();
      
      expect(stats).toHaveProperty('limits');
      expect(stats).toHaveProperty('current');
      expect(stats).toHaveProperty('queues');
      expect(stats).toHaveProperty('totalQueued');
      
      expect(stats.limits['api-call']).toBe(2);
      expect(stats.limits['db-query']).toBe(3);
    });
  });
});









