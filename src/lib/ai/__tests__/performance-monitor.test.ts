/**
 * Tests for Performance Monitor
 */

import { PerformanceMonitor } from '../performance-monitor';

describe('PerformanceMonitor', () => {
  let monitor: PerformanceMonitor;

  beforeEach(() => {
    monitor = new PerformanceMonitor();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Recording metrics', () => {
    it('should record successful metrics', () => {
      monitor.record({
        operation: 'test-operation',
        duration: 100,
        success: true,
        timestamp: Date.now(),
      });

      const metrics = monitor.getMetrics('test-operation');
      expect(metrics).not.toBeNull();
      expect(metrics?.successCount).toBe(1);
      expect(metrics?.failureCount).toBe(0);
    });

    it('should record failed metrics', () => {
      monitor.record({
        operation: 'test-operation',
        duration: 50,
        success: false,
        errorType: 'TIMEOUT',
        timestamp: Date.now(),
      });

      const metrics = monitor.getMetrics('test-operation');
      expect(metrics).not.toBeNull();
      expect(metrics?.successCount).toBe(0);
      expect(metrics?.failureCount).toBe(1);
    });
  });

  describe('Aggregated metrics', () => {
    it('should calculate average duration', () => {
      monitor.record({
        operation: 'test',
        duration: 100,
        success: true,
        timestamp: Date.now(),
      });
      monitor.record({
        operation: 'test',
        duration: 200,
        success: true,
        timestamp: Date.now(),
      });

      const metrics = monitor.getMetrics('test');
      expect(metrics?.averageDuration).toBe(150);
    });

    it('should calculate percentiles', () => {
      const durations = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      durations.forEach((duration) => {
        monitor.record({
          operation: 'test',
          duration,
          success: true,
          timestamp: Date.now(),
        });
      });

      const metrics = monitor.getMetrics('test');
      expect(metrics?.p50Duration).toBe(50);
      expect(metrics?.p95Duration).toBe(95);
      expect(metrics?.p99Duration).toBe(99);
    });

    it('should calculate error rate', () => {
      monitor.record({
        operation: 'test',
        duration: 100,
        success: true,
        timestamp: Date.now(),
      });
      monitor.record({
        operation: 'test',
        duration: 50,
        success: false,
        timestamp: Date.now(),
      });

      const metrics = monitor.getMetrics('test');
      expect(metrics?.errorRate).toBe(50);
    });
  });

  describe('Summary', () => {
    it('should provide summary of all operations', () => {
      monitor.record({
        operation: 'op1',
        duration: 100,
        success: true,
        timestamp: Date.now(),
      });
      monitor.record({
        operation: 'op2',
        duration: 200,
        success: false,
        timestamp: Date.now(),
      });

      const summary = monitor.getSummary();
      expect(summary.totalCalls).toBe(2);
      expect(summary.successRate).toBe(50);
      expect(summary.operations).toHaveProperty('op1');
      expect(summary.operations).toHaveProperty('op2');
    });
  });

  describe('Operations list', () => {
    it('should return list of all operations', () => {
      monitor.record({
        operation: 'op1',
        duration: 100,
        success: true,
        timestamp: Date.now(),
      });
      monitor.record({
        operation: 'op2',
        duration: 200,
        success: true,
        timestamp: Date.now(),
      });

      const operations = monitor.getOperations();
      expect(operations).toContain('op1');
      expect(operations).toContain('op2');
    });
  });
});









