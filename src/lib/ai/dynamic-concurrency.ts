/**
 * Dynamic Concurrency Management
 * Scales concurrency limits based on:
 * 1. Number of available API keys
 * 2. Available system resources (memory, CPU)
 * 3. Database connection pool capacity (prevents pool exhaustion)
 * More keys + more resources = faster processing through higher parallelism
 * But DB operations are limited by pool size to prevent exhaustion
 */

import apiKeyManager from './api-key-manager';
import {
  getCachedSystemResources,
  calculateResourceBasedChunkMultiplier,
  type SystemResources,
} from './resource-monitor';
import { getRecommendedConcurrency } from '@/lib/db/pool-aware-limiter';
import { getGlobalRecommendedConcurrency } from '@/lib/db/global-pool-manager';

/**
 * Calculate optimal concurrency limits based on:
 * - Available API keys
 * - System resources (memory, CPU)
 * 
 * More keys + more resources = higher concurrency = faster processing
 */
export async function getDynamicConcurrencyLimits() {
  const keyCount = await apiKeyManager.getKeyCount();
  const systemResources = getCachedSystemResources();
  
  // Base limits (for 1-5 keys)
  const baseAnalysisConcurrency = 50;
  const baseConversationFetchConcurrency = 30;
  const baseBatchConcurrency = 3;
  const baseMessageGenerationConcurrency = 20;
  const baseAutomationConcurrency = 50; // AI automations
  
  // Scaling factors (how much to add per key)
  // Analysis can scale more aggressively since we have multiple keys to rotate
  const analysisScalePerKey = 10; // +10 concurrent AI calls per key
  const conversationFetchScalePerKey = 2; // +2 per key (Facebook API limits)
  const batchScalePerKey = 0.5; // +0.5 per key (database operations)
  const messageGenerationScalePerKey = 5; // +5 per key (AI message generation)
  const automationScalePerKey = 10; // +10 per key (AI automations)
  
  // Maximum limits (safety caps)
  const maxAnalysisConcurrency = 500; // Max 500 concurrent AI calls
  const maxConversationFetchConcurrency = 100; // Max 100 concurrent Facebook API calls
  const maxBatchConcurrency = 20; // Max 20 concurrent batch operations
  const maxMessageGenerationConcurrency = 200; // Max 200 concurrent message generations
  const maxAutomationConcurrency = 200; // Max 200 concurrent automations
  
  // Calculate desired limits based on API keys (for API calls - no DB connection limit)
  const desiredAnalysisConcurrency = Math.min(
    baseAnalysisConcurrency + (keyCount * analysisScalePerKey),
    maxAnalysisConcurrency
  );
  
  const desiredConversationFetchConcurrency = Math.min(
    baseConversationFetchConcurrency + (keyCount * conversationFetchScalePerKey),
    maxConversationFetchConcurrency
  );
  
  const desiredBatchConcurrency = Math.min(
    Math.ceil(baseBatchConcurrency + (keyCount * batchScalePerKey)),
    maxBatchConcurrency
  );
  
  const desiredMessageGenerationConcurrency = Math.min(
    baseMessageGenerationConcurrency + (keyCount * messageGenerationScalePerKey),
    maxMessageGenerationConcurrency
  );
  
  const desiredAutomationConcurrency = Math.min(
    baseAutomationConcurrency + (keyCount * automationScalePerKey),
    maxAutomationConcurrency
  );
  
  // Apply GLOBAL pool-aware limits for DB-heavy operations
  // This ensures all operations together don't exceed pool capacity
  // Analysis: reads contact, conversations, writes analysis (3 connections)
  const analysisConcurrency = getGlobalRecommendedConcurrency('analysis', desiredAnalysisConcurrency);
  
  // Conversation fetch: mostly API calls, minimal DB (1 connection)
  const conversationFetchConcurrency = getGlobalRecommendedConcurrency('simple', desiredConversationFetchConcurrency);
  
  // Batch operations: multiple queries (5 connections)
  const batchConcurrency = getGlobalRecommendedConcurrency('batch', desiredBatchConcurrency);
  
  // Message generation: reads contact, writes message (2 connections)
  // But AI generation itself doesn't use DB, so we can be more lenient
  const messageGenerationConcurrency = getGlobalRecommendedConcurrency('message-generation', desiredMessageGenerationConcurrency);
  
  // Automation: reads contact/rule, writes execution, sends message (4 connections)
  const automationConcurrency = getGlobalRecommendedConcurrency('automation', desiredAutomationConcurrency);
  
  // Calculate optimal batch size (larger batches with more keys)
  const baseBatchSize = 20;
  const batchSizeScalePerKey = 2;
  const maxBatchSize = 100;
  const batchSize = Math.min(
    baseBatchSize + (keyCount * batchSizeScalePerKey),
    maxBatchSize
  );
  
  // Calculate optimal chunk size (contacts per chunk)
  // This is specifically for batching contacts for processing
  const baseChunkSize = 100;
  const chunkSizeScalePerKey = 10;
  const maxChunkSize = 500;
  
  // Calculate base chunk size based on API keys
  const keyBasedChunkSize = Math.min(
    baseChunkSize + (keyCount * chunkSizeScalePerKey),
    maxChunkSize
  );
  
  // Apply resource-based multiplier to adjust chunk size based on available resources
  // This dynamically scales chunk size based on memory, CPU, and system load
  const resourceMultiplier = calculateResourceBasedChunkMultiplier(systemResources);
  const chunkSize = Math.max(
    50, // Minimum chunk size (safety floor)
    Math.min(
      Math.round(keyBasedChunkSize * resourceMultiplier),
      maxChunkSize // Maximum chunk size (safety cap)
    )
  );
  
  return {
    keyCount,
    analysisConcurrency,
    conversationFetchConcurrency,
    batchConcurrency,
    messageGenerationConcurrency,
    automationConcurrency,
    batchSize,
    chunkSize,
    systemResources, // Include system resources for debugging/monitoring
  };
}

/**
 * Get cached concurrency limits (refreshes every 60 seconds)
 * This avoids querying the database on every call
 */
let cachedLimits: Awaited<ReturnType<typeof getDynamicConcurrencyLimits>> | null = null;
let cacheTimestamp = 0;
const CACHE_TTL = 60000; // 60 seconds

export async function getCachedConcurrencyLimits() {
  const now = Date.now();
  
  if (cachedLimits && (now - cacheTimestamp) < CACHE_TTL) {
    return cachedLimits;
  }
  
  cachedLimits = await getDynamicConcurrencyLimits();
  cacheTimestamp = now;
  
  // Log the limits for debugging
  const resources = cachedLimits.systemResources;
  const resourceInfo = resources
    ? ` | Resources: ${resources.memoryUsagePercent.toFixed(1)}% mem used, ${resources.cpuCores} cores, score: ${resources.resourceAvailabilityScore.toFixed(2)}`
    : '';
  
  // Get pool limit for context
  const { getConnectionPoolLimit } = await import('@/lib/db/pool-aware-limiter');
  const poolLimit = getConnectionPoolLimit();
  
  console.log(
    `[Dynamic Concurrency] ${cachedLimits.keyCount} API keys, Pool: ${poolLimit} → ` +
    `Analysis: ${cachedLimits.analysisConcurrency} (pool-aware), ` +
    `Fetch: ${cachedLimits.conversationFetchConcurrency}, ` +
    `Batch: ${cachedLimits.batchConcurrency} (pool-aware), ` +
    `Messages: ${cachedLimits.messageGenerationConcurrency} (pool-aware), ` +
    `Automations: ${cachedLimits.automationConcurrency} (pool-aware), ` +
    `BatchSize: ${cachedLimits.batchSize}, ` +
    `ChunkSize: ${cachedLimits.chunkSize} (contacts per chunk)${resourceInfo}`
  );
  
  return cachedLimits;
}

/**
 * Invalidate the cache (call when keys are added/removed)
 */
export function invalidateConcurrencyCache() {
  cachedLimits = null;
  cacheTimestamp = 0;
}





