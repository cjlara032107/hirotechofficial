/**
 * Resource Monitoring Utility
 * Monitors system resources (memory, CPU) to inform dynamic chunk sizing
 */

import * as os from 'os';

export interface SystemResources {
  /** Available memory in bytes */
  availableMemory: number;
  /** Total system memory in bytes */
  totalMemory: number;
  /** Memory usage percentage (0-100) */
  memoryUsagePercent: number;
  /** Process memory usage in bytes */
  processMemoryUsage: NodeJS.MemoryUsage;
  /** Number of CPU cores */
  cpuCores: number;
  /** CPU load average (1 minute) - if available */
  cpuLoadAverage: number | null;
  /** Resource availability score (0-1, where 1 = most resources available) */
  resourceAvailabilityScore: number;
}

/**
 * Get current system resource metrics
 */
export function getSystemResources(): SystemResources {
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const availableMemory = freeMemory;
  const memoryUsagePercent = ((totalMemory - freeMemory) / totalMemory) * 100;
  
  const processMemoryUsage = process.memoryUsage();
  const cpuCores = os.cpus().length;
  
  // CPU load average (1 minute) - available on Unix-like systems
  // On Windows, this may return [0, 0, 0] or throw, so we handle it gracefully
  let cpuLoadAverage: number | null = null;
  try {
    const loadAvg = os.loadavg();
    cpuLoadAverage = loadAvg && loadAvg.length > 0 && loadAvg[0] > 0 ? loadAvg[0] : null;
  } catch {
    // Windows doesn't support loadavg, or it failed
    cpuLoadAverage = null;
  }
  
  // Calculate resource availability score (0-1)
  // Higher score = more resources available
  // Factors:
  // - Available memory (higher = better, normalized to 0-1)
  // - Memory usage (lower = better, inverted)
  // - CPU cores (more = better, normalized)
  // - CPU load (lower = better, if available)
  
  // Memory factor: available memory as percentage of total (0-1)
  // We want at least 20% free memory to be considered "good"
  const memoryFactor = Math.min(availableMemory / totalMemory, 1);
  
  // Memory usage factor: inverted (lower usage = higher score)
  const memoryUsageFactor = Math.max(0, 1 - (memoryUsagePercent / 100));
  
  // CPU cores factor: normalize to 0-1 (assuming max 32 cores for normalization)
  const cpuCoresFactor = Math.min(cpuCores / 32, 1);
  
  // CPU load factor: if available, lower load = higher score
  // Normalize load average (assuming max load of 2x cores is "fully loaded")
  let cpuLoadFactor = 1; // Default to best if not available
  if (cpuLoadAverage !== null) {
    const maxLoad = cpuCores * 2;
    cpuLoadFactor = Math.max(0, 1 - (cpuLoadAverage / maxLoad));
  }
  
  // Weighted combination of factors
  // Memory is most important (40%), then CPU cores (30%), then CPU load (20%), then memory usage (10%)
  const resourceAvailabilityScore = 
    (memoryFactor * 0.4) +
    (cpuCoresFactor * 0.3) +
    (cpuLoadFactor * 0.2) +
    (memoryUsageFactor * 0.1);
  
  return {
    availableMemory,
    totalMemory,
    memoryUsagePercent,
    processMemoryUsage,
    cpuCores,
    cpuLoadAverage,
    resourceAvailabilityScore: Math.max(0, Math.min(1, resourceAvailabilityScore)), // Clamp to 0-1
  };
}

/**
 * Get a cached version of system resources (refreshes every 5 seconds)
 * This avoids expensive system calls on every check
 */
let cachedResources: SystemResources | null = null;
let cacheTimestamp = 0;
const RESOURCE_CACHE_TTL = 5000; // 5 seconds

export function getCachedSystemResources(): SystemResources {
  const now = Date.now();
  
  if (cachedResources && (now - cacheTimestamp) < RESOURCE_CACHE_TTL) {
    return cachedResources;
  }
  
  cachedResources = getSystemResources();
  cacheTimestamp = now;
  
  return cachedResources;
}

/**
 * Calculate optimal chunk size multiplier based on available resources
 * Returns a multiplier (0.5 to 2.0) that adjusts chunk size based on resources
 * 
 * @param resources System resources (optional, will fetch if not provided)
 * @returns Multiplier to apply to base chunk size
 */
export function calculateResourceBasedChunkMultiplier(
  resources?: SystemResources
): number {
  const systemResources = resources || getCachedSystemResources();
  
  // Resource availability score is 0-1
  // We want to map this to a multiplier range of 0.5 to 2.0
  // - Low resources (0.0-0.3): 0.5-0.8x (reduce chunk size)
  // - Medium resources (0.3-0.7): 0.8-1.5x (normal to slightly increased)
  // - High resources (0.7-1.0): 1.5-2.0x (increase chunk size)
  
  const score = systemResources.resourceAvailabilityScore;
  
  if (score < 0.3) {
    // Low resources: reduce chunk size to 0.5-0.8x
    return 0.5 + (score / 0.3) * 0.3; // Maps 0.0 -> 0.5, 0.3 -> 0.8
  } else if (score < 0.7) {
    // Medium resources: normal to slightly increased (0.8-1.5x)
    const normalized = (score - 0.3) / 0.4; // 0-1 range for medium resources
    return 0.8 + normalized * 0.7; // Maps 0.3 -> 0.8, 0.7 -> 1.5
  } else {
    // High resources: increase chunk size (1.5-2.0x)
    const normalized = (score - 0.7) / 0.3; // 0-1 range for high resources
    return 1.5 + normalized * 0.5; // Maps 0.7 -> 1.5, 1.0 -> 2.0
  }
}

/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

