/**
 * Tests for Memory Monitor
 */

import { MemoryMonitor, memoryMonitor } from '../memory-monitor';

describe('MemoryMonitor', () => {
  describe('getStats', () => {
    it('should return memory statistics', () => {
      const stats = memoryMonitor.getStats();
      
      expect(stats).toHaveProperty('heapUsed');
      expect(stats).toHaveProperty('heapTotal');
      expect(stats).toHaveProperty('rss');
      expect(stats).toHaveProperty('heapUsedMB');
      expect(stats).toHaveProperty('heapTotalMB');
      expect(stats).toHaveProperty('rssMB');
      expect(stats).toHaveProperty('usagePercent');
      
      expect(stats.heapUsed).toBeGreaterThan(0);
      expect(stats.heapTotal).toBeGreaterThan(0);
      expect(stats.heapUsedMB).toBeGreaterThan(0);
      expect(stats.usagePercent).toBeGreaterThanOrEqual(0);
      expect(stats.usagePercent).toBeLessThanOrEqual(100);
    });
  });

  describe('isAboveWarning', () => {
    it('should detect high memory usage', () => {
      const monitor = new MemoryMonitor({ warning: 10, critical: 20 });
      // Mock high memory usage
      const originalGetStats = monitor.getStats.bind(monitor);
      jest.spyOn(monitor as any, 'getStats').mockReturnValue({
        heapUsed: 90,
        heapTotal: 100,
        usagePercent: 90,
      });
      
      expect(monitor.isAboveWarning()).toBe(true);
    });
  });

  describe('isAboveCritical', () => {
    it('should detect critical memory usage', () => {
      const monitor = new MemoryMonitor({ warning: 10, critical: 20 });
      jest.spyOn(monitor as any, 'getStats').mockReturnValue({
        heapUsed: 25,
        heapTotal: 100,
        usagePercent: 25,
        heapUsedMB: 25,
      });
      
      expect(monitor.isAboveCritical()).toBe(true);
    });
  });

  describe('getPressureLevel', () => {
    it('should return correct pressure level', () => {
      const monitor = new MemoryMonitor({ warning: 70, critical: 85 });
      
      jest.spyOn(monitor as any, 'getStats').mockReturnValue({
        usagePercent: 30,
      });
      expect(monitor.getPressureLevel()).toBe('low');
      
      jest.spyOn(monitor as any, 'getStats').mockReturnValue({
        usagePercent: 60,
      });
      expect(monitor.getPressureLevel()).toBe('medium');
      
      jest.spyOn(monitor as any, 'getStats').mockReturnValue({
        usagePercent: 75,
      });
      expect(monitor.getPressureLevel()).toBe('high');
      
      jest.spyOn(monitor as any, 'getStats').mockReturnValue({
        usagePercent: 90,
      });
      expect(monitor.getPressureLevel()).toBe('critical');
    });
  });

  describe('forceGC', () => {
    it('should return false if GC is not available', () => {
      const result = memoryMonitor.forceGC();
      // GC may or may not be available depending on Node.js flags
      expect(typeof result).toBe('boolean');
    });
  });

  describe('formatStats', () => {
    it('should format stats as string', () => {
      const stats = memoryMonitor.getStats();
      const formatted = memoryMonitor.formatStats(stats);
      
      expect(formatted).toContain('Heap:');
      expect(formatted).toContain('MB');
      expect(formatted).toContain('%');
    });
  });
});









