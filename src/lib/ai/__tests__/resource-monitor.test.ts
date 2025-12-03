/**
 * Tests for Resource Monitor
 * Tests system resource monitoring and chunk size calculation
 */

import {
  getSystemResources,
  getCachedSystemResources,
  calculateResourceBasedChunkMultiplier,
  formatBytes,
  type SystemResources,
} from '../resource-monitor';

// Mock os module
jest.mock('os', () => ({
  totalmem: jest.fn(() => 16 * 1024 * 1024 * 1024), // 16GB
  freemem: jest.fn(() => 8 * 1024 * 1024 * 1024), // 8GB free
  cpus: jest.fn(() => Array(8).fill({ model: 'Test CPU', speed: 2400 })),
  loadavg: jest.fn(() => [1.5, 2.0, 2.5]), // 1 minute, 5 minute, 15 minute
}));

// Mock process.memoryUsage
const mockMemoryUsage = {
  rss: 100 * 1024 * 1024, // 100MB
  heapTotal: 50 * 1024 * 1024,
  heapUsed: 30 * 1024 * 1024,
  external: 10 * 1024 * 1024,
  arrayBuffers: 5 * 1024 * 1024,
};

describe('Resource Monitor', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (process.memoryUsage as jest.Mock) = jest.fn(() => mockMemoryUsage);
  });

  describe('getSystemResources', () => {
    it('should return system resource metrics', () => {
      const resources = getSystemResources();

      expect(resources).toHaveProperty('availableMemory');
      expect(resources).toHaveProperty('totalMemory');
      expect(resources).toHaveProperty('memoryUsagePercent');
      expect(resources).toHaveProperty('processMemoryUsage');
      expect(resources).toHaveProperty('cpuCores');
      expect(resources).toHaveProperty('cpuLoadAverage');
      expect(resources).toHaveProperty('resourceAvailabilityScore');

      expect(resources.totalMemory).toBe(16 * 1024 * 1024 * 1024);
      expect(resources.availableMemory).toBe(8 * 1024 * 1024 * 1024);
      expect(resources.memoryUsagePercent).toBe(50); // (16-8)/16 * 100
      expect(resources.cpuCores).toBe(8);
      expect(resources.cpuLoadAverage).toBe(1.5);
      expect(resources.resourceAvailabilityScore).toBeGreaterThanOrEqual(0);
      expect(resources.resourceAvailabilityScore).toBeLessThanOrEqual(1);
    });

    it('should calculate memory usage percentage correctly', () => {
      const resources = getSystemResources();
      const expectedPercent = ((16 - 8) / 16) * 100; // 50%
      expect(resources.memoryUsagePercent).toBe(expectedPercent);
    });

    it('should handle null load average on Windows', () => {
      const os = require('os');
      os.loadavg.mockReturnValueOnce(null);

      const resources = getSystemResources();
      expect(resources.cpuLoadAverage).toBeNull();
      expect(resources.resourceAvailabilityScore).toBeGreaterThanOrEqual(0);
      expect(resources.resourceAvailabilityScore).toBeLessThanOrEqual(1);
    });
  });

  describe('getCachedSystemResources', () => {
    it('should return cached resources within TTL', () => {
      const resources1 = getCachedSystemResources();
      const resources2 = getCachedSystemResources();

      // Should return same object reference (cached)
      expect(resources1).toBe(resources2);
    });

    it('should refresh cache after TTL expires', async () => {
      jest.useFakeTimers();

      const resources1 = getCachedSystemResources();

      // Fast-forward time past cache TTL (5 seconds)
      jest.advanceTimersByTime(6000);

      const resources2 = getCachedSystemResources();

      // Should be different objects (cache refreshed)
      expect(resources1).not.toBe(resources2);

      jest.useRealTimers();
    });
  });

  describe('calculateResourceBasedChunkMultiplier', () => {
    it('should return multiplier between 0.5 and 2.0', () => {
      const multiplier = calculateResourceBasedChunkMultiplier();
      expect(multiplier).toBeGreaterThanOrEqual(0.5);
      expect(multiplier).toBeLessThanOrEqual(2.0);
    });

    it('should return lower multiplier for low resources', () => {
      const lowResources: SystemResources = {
        availableMemory: 1 * 1024 * 1024 * 1024, // 1GB
        totalMemory: 16 * 1024 * 1024 * 1024, // 16GB
        memoryUsagePercent: 93.75, // High usage
        processMemoryUsage: mockMemoryUsage,
        cpuCores: 2,
        cpuLoadAverage: 3.5, // High load
        resourceAvailabilityScore: 0.1, // Low score
      };

      const multiplier = calculateResourceBasedChunkMultiplier(lowResources);
      expect(multiplier).toBeLessThan(1.0); // Should reduce chunk size
      expect(multiplier).toBeGreaterThanOrEqual(0.5);
    });

    it('should return higher multiplier for high resources', () => {
      const highResources: SystemResources = {
        availableMemory: 12 * 1024 * 1024 * 1024, // 12GB
        totalMemory: 16 * 1024 * 1024 * 1024, // 16GB
        memoryUsagePercent: 25, // Low usage
        processMemoryUsage: mockMemoryUsage,
        cpuCores: 16,
        cpuLoadAverage: 0.5, // Low load
        resourceAvailabilityScore: 0.9, // High score
      };

      const multiplier = calculateResourceBasedChunkMultiplier(highResources);
      expect(multiplier).toBeGreaterThan(1.0); // Should increase chunk size
      expect(multiplier).toBeLessThanOrEqual(2.0);
    });

    it('should return medium multiplier for medium resources', () => {
      const mediumResources: SystemResources = {
        availableMemory: 8 * 1024 * 1024 * 1024, // 8GB
        totalMemory: 16 * 1024 * 1024 * 1024, // 16GB
        memoryUsagePercent: 50,
        processMemoryUsage: mockMemoryUsage,
        cpuCores: 8,
        cpuLoadAverage: 1.5,
        resourceAvailabilityScore: 0.5, // Medium score
      };

      const multiplier = calculateResourceBasedChunkMultiplier(mediumResources);
      expect(multiplier).toBeGreaterThanOrEqual(0.8);
      expect(multiplier).toBeLessThanOrEqual(1.5);
    });

    it('should handle edge case with score 0', () => {
      const zeroResources: SystemResources = {
        availableMemory: 0,
        totalMemory: 16 * 1024 * 1024 * 1024,
        memoryUsagePercent: 100,
        processMemoryUsage: mockMemoryUsage,
        cpuCores: 1,
        cpuLoadAverage: 10,
        resourceAvailabilityScore: 0,
      };

      const multiplier = calculateResourceBasedChunkMultiplier(zeroResources);
      expect(multiplier).toBe(0.5); // Minimum multiplier
    });

    it('should handle edge case with score 1', () => {
      const maxResources: SystemResources = {
        availableMemory: 16 * 1024 * 1024 * 1024,
        totalMemory: 16 * 1024 * 1024 * 1024,
        memoryUsagePercent: 0,
        processMemoryUsage: mockMemoryUsage,
        cpuCores: 32,
        cpuLoadAverage: 0,
        resourceAvailabilityScore: 1,
      };

      const multiplier = calculateResourceBasedChunkMultiplier(maxResources);
      expect(multiplier).toBe(2.0); // Maximum multiplier
    });
  });

  describe('formatBytes', () => {
    it('should format bytes correctly', () => {
      expect(formatBytes(0)).toBe('0 Bytes');
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1024 * 1024)).toBe('1 MB');
      expect(formatBytes(1024 * 1024 * 1024)).toBe('1 GB');
      expect(formatBytes(1024 * 1024 * 1024 * 1024)).toBe('1 TB');
    });

    it('should handle decimal values', () => {
      const result = formatBytes(1536); // 1.5 KB
      expect(result).toContain('KB');
      expect(parseFloat(result)).toBeCloseTo(1.5, 1);
    });
  });
});









