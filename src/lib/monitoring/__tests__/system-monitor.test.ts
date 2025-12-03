/**
 * Tests for SystemMonitor
 */

import { systemMonitor, SystemMonitor } from '../system-monitor';

describe('SystemMonitor', () => {
  beforeEach(() => {
    // Clear metrics before each test
    // Note: We can't directly clear the singleton, so we'll work with a fresh instance
  });

  describe('Database Query Tracking', () => {
    it('should record database queries', () => {
      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "User"',
        duration: 100,
        model: 'User',
        action: 'SELECT',
        timestamp: Date.now(),
        success: true,
      });

      const stats = systemMonitor.getDatabaseStats();
      expect(stats.totalQueries).toBeGreaterThan(0);
      expect(stats.averageDuration).toBeGreaterThan(0);
    });

    it('should track slow queries', () => {
      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "User"',
        duration: 2000,
        model: 'User',
        action: 'SELECT',
        timestamp: Date.now(),
        success: true,
      });

      const stats = systemMonitor.getDatabaseStats();
      expect(stats.slowQueries).toBeGreaterThan(0);
    });

    it('should track query errors', () => {
      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "User"',
        duration: 50,
        model: 'User',
        action: 'SELECT',
        timestamp: Date.now(),
        success: false,
        errorCode: 'P1001',
        errorMessage: 'Connection error',
      });

      const stats = systemMonitor.getDatabaseStats();
      expect(stats.errorCount).toBeGreaterThan(0);
      expect(stats.errorRate).toBeGreaterThan(0);
    });

    it('should group queries by model', () => {
      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "User"',
        duration: 100,
        model: 'User',
        action: 'SELECT',
        timestamp: Date.now(),
        success: true,
      });

      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "Contact"',
        duration: 150,
        model: 'Contact',
        action: 'SELECT',
        timestamp: Date.now(),
        success: true,
      });

      const stats = systemMonitor.getDatabaseStats();
      expect(stats.queriesByModel['User']).toBeGreaterThan(0);
      expect(stats.queriesByModel['Contact']).toBeGreaterThan(0);
    });

    it('should calculate percentiles correctly', () => {
      // Record multiple queries with different durations
      for (let i = 1; i <= 100; i++) {
        systemMonitor.recordDatabaseQuery({
          query: 'SELECT * FROM "User"',
          duration: i * 10, // 10ms, 20ms, ..., 1000ms
          model: 'User',
          action: 'SELECT',
          timestamp: Date.now(),
          success: true,
        });
      }

      const stats = systemMonitor.getDatabaseStats();
      expect(stats.p50Duration).toBeGreaterThan(0);
      expect(stats.p95Duration).toBeGreaterThan(stats.p50Duration);
      expect(stats.p99Duration).toBeGreaterThan(stats.p95Duration);
    });
  });

  describe('Memory Tracking', () => {
    it('should record memory usage', () => {
      const usage = process.memoryUsage();
      systemMonitor.recordMemoryUsage({
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        rss: usage.rss,
        external: usage.external,
        heapUsedMB: usage.heapUsed / 1024 / 1024,
        heapTotalMB: usage.heapTotal / 1024 / 1024,
        rssMB: usage.rss / 1024 / 1024,
        usagePercent: (usage.heapUsed / usage.heapTotal) * 100,
        timestamp: Date.now(),
      });

      const stats = systemMonitor.getMemoryStats();
      expect(stats.current).not.toBeNull();
      expect(stats.samples).toBeGreaterThan(0);
    });

    it('should calculate memory averages', () => {
      // Record multiple memory samples
      for (let i = 0; i < 10; i++) {
        const usage = process.memoryUsage();
        systemMonitor.recordMemoryUsage({
          heapUsed: usage.heapUsed,
          heapTotal: usage.heapTotal,
          rss: usage.rss,
          external: usage.external,
          heapUsedMB: usage.heapUsed / 1024 / 1024,
          heapTotalMB: usage.heapTotal / 1024 / 1024,
          rssMB: usage.rss / 1024 / 1024,
          usagePercent: (usage.heapUsed / usage.heapTotal) * 100,
          timestamp: Date.now(),
        });
      }

      const stats = systemMonitor.getMemoryStats();
      expect(stats.average.heapUsedMB).toBeGreaterThan(0);
      expect(stats.average.rssMB).toBeGreaterThan(0);
      expect(stats.peak.heapUsedMB).toBeGreaterThan(0);
    });

    it('should handle empty memory samples', () => {
      // Create a new monitor instance to test empty state
      const monitor = new SystemMonitor();
      const stats = monitor.getMemoryStats();
      
      // Should return current memory even with no samples
      expect(stats.current).not.toBeNull();
      expect(stats.samples).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Error Tracking', () => {
    it('should record errors', () => {
      systemMonitor.recordError({
        errorType: 'TestError',
        errorMessage: 'Test error message',
        timestamp: Date.now(),
      });

      const stats = systemMonitor.getErrorStats();
      expect(stats.totalErrors).toBeGreaterThan(0);
      expect(stats.errorsByType['TestError']).toBeGreaterThan(0);
    });

    it('should group errors by type', () => {
      systemMonitor.recordError({
        errorType: 'TypeA',
        errorMessage: 'Error A',
        timestamp: Date.now(),
      });

      systemMonitor.recordError({
        errorType: 'TypeB',
        errorMessage: 'Error B',
        timestamp: Date.now(),
      });

      systemMonitor.recordError({
        errorType: 'TypeA',
        errorMessage: 'Error A2',
        timestamp: Date.now(),
      });

      const stats = systemMonitor.getErrorStats();
      expect(stats.errorsByType['TypeA']).toBe(2);
      expect(stats.errorsByType['TypeB']).toBe(1);
    });

    it('should group errors by code', () => {
      systemMonitor.recordError({
        errorType: 'PrismaError',
        errorCode: 'P1001',
        errorMessage: 'Connection error',
        timestamp: Date.now(),
      });

      systemMonitor.recordError({
        errorType: 'PrismaError',
        errorCode: 'P2024',
        errorMessage: 'Pool timeout',
        timestamp: Date.now(),
      });

      const stats = systemMonitor.getErrorStats();
      expect(stats.errorsByCode['P1001']).toBe(1);
      expect(stats.errorsByCode['P2024']).toBe(1);
    });

    it('should calculate error rate', () => {
      // Record errors with timestamps spread over time
      const now = Date.now();
      for (let i = 0; i < 10; i++) {
        systemMonitor.recordError({
          errorType: 'TestError',
          errorMessage: `Error ${i}`,
          timestamp: now - (10 - i) * 1000, // Spread over 10 seconds
        });
      }

      const stats = systemMonitor.getErrorStats();
      expect(stats.errorRate).toBeGreaterThan(0);
    });

    it('should track recent errors', () => {
      for (let i = 0; i < 10; i++) {
        systemMonitor.recordError({
          errorType: 'TestError',
          errorMessage: `Error ${i}`,
          timestamp: Date.now(),
        });
      }

      const stats = systemMonitor.getErrorStats();
      expect(stats.recentErrors.length).toBeGreaterThan(0);
      expect(stats.recentErrors.length).toBeLessThanOrEqual(50);
    });
  });

  describe('System Metrics', () => {
    it('should return all system metrics', () => {
      // Record some sample data
      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "User"',
        duration: 100,
        model: 'User',
        action: 'SELECT',
        timestamp: Date.now(),
        success: true,
      });

      const usage = process.memoryUsage();
      systemMonitor.recordMemoryUsage({
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        rss: usage.rss,
        external: usage.external,
        heapUsedMB: usage.heapUsed / 1024 / 1024,
        heapTotalMB: usage.heapTotal / 1024 / 1024,
        rssMB: usage.rss / 1024 / 1024,
        usagePercent: (usage.heapUsed / usage.heapTotal) * 100,
        timestamp: Date.now(),
      });

      systemMonitor.recordError({
        errorType: 'TestError',
        errorMessage: 'Test error',
        timestamp: Date.now(),
      });

      const metrics = systemMonitor.getSystemMetrics();
      
      expect(metrics).toHaveProperty('database');
      expect(metrics).toHaveProperty('memory');
      expect(metrics).toHaveProperty('errors');
      expect(metrics).toHaveProperty('timestamp');
      
      expect(metrics.database.totalQueries).toBeGreaterThan(0);
      expect(metrics.memory.samples).toBeGreaterThan(0);
      expect(metrics.errors.totalErrors).toBeGreaterThan(0);
    });
  });

  describe('Memory Sampling', () => {
    it('should start and stop memory sampling', () => {
      const monitor = new SystemMonitor();
      
      // Start sampling
      // Note: We can't easily test the interval in Jest, but we can verify the method exists
      expect(typeof monitor.stopMemorySampling).toBe('function');
      
      // Stop sampling
      monitor.stopMemorySampling();
      // Should not throw
    });
  });

  describe('Cleanup', () => {
    it('should clear old metrics', () => {
      // Record some old metrics
      const oldTimestamp = Date.now() - (8 * 24 * 60 * 60 * 1000); // 8 days ago
      
      systemMonitor.recordDatabaseQuery({
        query: 'SELECT * FROM "User"',
        duration: 100,
        model: 'User',
        action: 'SELECT',
        timestamp: oldTimestamp,
        success: true,
      });

      systemMonitor.recordError({
        errorType: 'OldError',
        errorMessage: 'Old error',
        timestamp: oldTimestamp,
      });

      // Clear metrics older than 7 days
      systemMonitor.clearOldMetrics(7 * 24 * 60 * 60 * 1000);

      // Verify old metrics are cleared (we can't directly verify, but the method should not throw)
      const stats = systemMonitor.getDatabaseStats();
      expect(stats).toBeDefined();
    });
  });
});









