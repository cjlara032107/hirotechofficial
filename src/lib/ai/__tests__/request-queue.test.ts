/**
 * Tests for Request Queue with Priority Support
 */

import { RequestQueue, RequestPriority } from '../request-queue';

describe('RequestQueue', () => {
  let queue: RequestQueue;

  beforeEach(() => {
    queue = new RequestQueue(2); // Max 2 concurrent requests
    jest.useFakeTimers();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    queue.clear();
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe('Priority ordering', () => {
    it('should process high priority requests before low priority', async () => {
      const executionOrder: number[] = [];

      // Enqueue low priority first
      const lowPriority = queue.enqueue(
        async () => {
          executionOrder.push(1);
          return 'low';
        },
        RequestPriority.LOW
      );

      // Enqueue high priority
      const highPriority = queue.enqueue(
        async () => {
          executionOrder.push(2);
          return 'high';
        },
        RequestPriority.HIGH
      );

      // Process queue
      jest.advanceTimersByTime(100);
      await Promise.all([lowPriority, highPriority]);

      // High priority should execute first
      expect(executionOrder).toEqual([2, 1]);
    });

    it('should maintain FIFO order for same priority', async () => {
      const executionOrder: number[] = [];

      const req1 = queue.enqueue(async () => {
        executionOrder.push(1);
        return '1';
      }, RequestPriority.NORMAL);

      const req2 = queue.enqueue(async () => {
        executionOrder.push(2);
        return '2';
      }, RequestPriority.NORMAL);

      jest.advanceTimersByTime(100);
      await Promise.all([req1, req2]);

      expect(executionOrder).toEqual([1, 2]);
    });
  });

  describe('Concurrency limiting', () => {
    it('should limit concurrent executions', async () => {
      let concurrent = 0;
      let maxConcurrent = 0;

      const requests = Array.from({ length: 5 }, (_, i) =>
        queue.enqueue(async () => {
          concurrent++;
          maxConcurrent = Math.max(maxConcurrent, concurrent);
          await new Promise((resolve) => setTimeout(resolve, 100));
          concurrent--;
          return i;
        }, RequestPriority.NORMAL)
      );

      jest.advanceTimersByTime(500);
      await Promise.all(requests);

      // Should never exceed maxConcurrent (2)
      expect(maxConcurrent).toBeLessThanOrEqual(2);
    });
  });

  describe('Timeout handling', () => {
    it('should timeout requests that exceed timeout', async () => {
      const request = queue.enqueue(
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 200));
          return 'slow';
        },
        RequestPriority.NORMAL,
        100 // 100ms timeout
      );

      jest.advanceTimersByTime(200);

      await expect(request).rejects.toThrow('timed out');
    });

    it('should remove timed-out requests from queue', async () => {
      const request = queue.enqueue(
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 200));
          return 'slow';
        },
        RequestPriority.NORMAL,
        50 // 50ms timeout
      );

      // Wait for timeout
      jest.advanceTimersByTime(100);

      await expect(request).rejects.toThrow('timed out');
      expect(queue.getStats().queueSize).toBe(0);
    });
  });

  describe('Error handling', () => {
    it('should reject promise on error', async () => {
      const request = queue.enqueue(
        async () => {
          throw new Error('Test error');
        },
        RequestPriority.NORMAL
      );

      jest.advanceTimersByTime(100);

      await expect(request).rejects.toThrow('Test error');
    });
  });

  describe('Statistics', () => {
    it('should track queue statistics', async () => {
      queue.enqueue(async () => '1', RequestPriority.HIGH);
      queue.enqueue(async () => '2', RequestPriority.LOW);
      queue.enqueue(async () => '3', RequestPriority.NORMAL);

      const stats = queue.getStats();
      expect(stats.queueSize).toBe(3);
      expect(stats.priorityBreakdown.HIGH).toBe(1);
      expect(stats.priorityBreakdown.LOW).toBe(1);
      expect(stats.priorityBreakdown.NORMAL).toBe(1);
    });
  });
});









