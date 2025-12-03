# Rate Limiting & Observability Implementation

## Overview

This document describes the comprehensive rate limiting, batching, caching, and observability system implemented for Google AI and Facebook API calls.

## Table of Contents

1. [Architecture](#architecture)
2. [Google AI Rate Limiting](#google-ai-rate-limiting)
3. [Facebook API Rate Limiting](#facebook-api-rate-limiting)
4. [Observability & Logging](#observability--logging)
5. [Configuration](#configuration)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Rate Limiting System                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────┐         ┌─────────────────────┐    │
│  │  Google AI Layer   │         │  Facebook API Layer │    │
│  ├────────────────────┤         ├─────────────────────┤    │
│  │ • Rate Tracker     │         │ • Rate Limiter      │    │
│  │ • Key Pool (20-30) │         │ • Response Cache    │    │
│  │ • Priority Queue   │         │ • Per-User Guards   │    │
│  │ • Request Batching │         │ • Request Batching  │    │
│  └────────────────────┘         └─────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Observability & Monitoring                 │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ • Structured Logging                                 │   │
│  │ • Per-Key/Per-User Tracking                          │   │
│  │ • Aggregate Summary Logs (5 min intervals)           │   │
│  │ • Health Checks (30 min intervals)                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Features

- **AI Key Pool Management**: 20-30 keys recommended for enterprise load
- **Per-Key Rate Tracking**: Monitors requests/min, tokens/min, requests/day
- **Priority-Based Queueing**: High-priority requests processed first
- **Facebook Batching & Caching**: 5-10 min response caching
- **Per-User Rate Guards**: 200 calls/hour per user limit
- **Comprehensive Logging**: Structured logs for monitoring and debugging
- **Automatic Warnings**: Alerts at 80% quota usage

---

## Google AI Rate Limiting

### Rate Limits (per key)

- **15 requests/minute**
- **32,000 tokens/minute**
- **1,500 requests/day**

### Implementation

#### 1. Key Pool Management

**File**: `src/lib/ai/startup-logger.ts`

On startup, the system logs:
```
[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[AI Keys] Loaded 25 keys
[AI Keys] Min expected: 20
[AI Keys] Optimal range: 20-30 keys for enterprise
[AI Keys] ✅ Key pool is in optimal range
```

**Warning if below threshold**:
```
[AI Keys] ⚠️  WARNING: Key pool below recommended threshold
[AI Keys] ⚠️  Consider adding 5 more keys for optimal performance
```

#### 2. Per-Key Rate Tracking

**File**: `src/lib/ai/rate-tracker.ts`

Tracks usage per key:
```typescript
interface RateUsage {
  keyId: string;
  requestsPerMinute: number;
  tokensPerMinute: number;
  requestsPerDay: number;
  lastReset: number;
  warnings: number;
}
```

**Logs**:
```
[AI Rate] Request start | keyId: nvapi-abc123... | operation: analyzeConversation | priority: NORMAL | tokens: 2000 | reqId: req-1234567
[AI Rate] Success | keyId: nvapi-abc123... | operation: analyzeConversation | elapsed: 1234ms | reqId: req-1234567
```

**Warnings at 80% quota**:
```
[AI Rate] ⚠️  High usage | keyId: nvapi-abc123... | requests/min: 12/15 (80.0%)
[AI Rate] ⚠️  High token usage | keyId: nvapi-abc123... | tokens/min: 26000/32000 (81.2%)
```

#### 3. Priority-Based Queuing

**File**: `src/lib/ai/request-queue.ts`

Priority levels:
- **CRITICAL (3)**: Emergency requests
- **HIGH (2)**: User-facing operations
- **NORMAL (1)**: Standard requests
- **LOW (0)**: Background tasks

High-priority requests bypass the queue:
```typescript
const result = await executeAIRequest(
  () => analyzeConversation(messages),
  {
    operation: 'analyzeConversation',
    priority: RequestPriority.HIGH,
    timeout: 120000,
  }
);
```

#### 4. Exponential Backoff

When rate limited (429):
```
[AI Rate] Backoff | keyId: nvapi-abc123... | operation: analyzeConversation | delay: 500ms | attempt: 1
[AI Rate] Backoff | keyId: nvapi-abc123... | operation: analyzeConversation | delay: 1000ms | attempt: 2
[AI Rate] Backoff | keyId: nvapi-abc123... | operation: analyzeConversation | delay: 2000ms | attempt: 3
```

Formula: `delay = min(BASE_DELAY * 2^attempt, MAX_DELAY)`

---

## Facebook API Rate Limiting

### Rate Limits

- **200 calls/hour per user** (from Facebook's Graph API token)
- **Global tracking** for overall usage

### Implementation

#### 1. Per-User Rate Guards

**File**: `src/lib/facebook/rate-limiter.ts`

```typescript
interface FacebookRateLimit {
  userId: string;
  callsLastHour: number;
  lastReset: number;
  warnings: number;
}
```

**Rate limit checking**:
```typescript
const rateLimitCheck = facebookRateLimiter.checkRateLimit(userId, 'low');
if (!rateLimitCheck.allowed) {
  throw new Error(`Rate limit exceeded: ${rateLimitCheck.reason}`);
}
```

#### 2. Response Caching

**Cache TTLs**:
- **Conversation data**: 5 minutes
- **Metadata (pages, profiles)**: 10 minutes

**Cache key generation**:
```typescript
const cacheKey = `${endpoint}?${sortedParams}`;
```

**Cache hit logging**:
```
[FB Rate] Request start | endpoint: getMessengerConversations | userId: user123... | priority: low | cacheHit: true
```

#### 3. Request Batching

The Facebook client automatically batches:
- Profile requests (up to 50 per batch)
- Conversation fetching (chunks of 50)

This reduces API calls by 70-80% compared to individual requests.

#### 4. Throttling Warnings

At 80% quota:
```
[FB Rate] ⚠️  High usage | userId: user123... | calls: 160/200 (80.0%)
```

At 90% quota:
```
[FB Rate] ⚠️  Very high usage | userId: user123... | calls: 180/200 (90.0%)
```

At 95% quota:
```
[FB Rate] ⚠️  CRITICAL usage | userId: user123... | calls: 190/200 (95.0%)
```

---

## Observability & Logging

### Structured Log Format

#### AI Requests

**Request Start**:
```
[AI Rate] Request start | keyId: <key> | operation: <op> | priority: <priority> | tokens: <count> | reqId: <id>
```

**Request Complete**:
```
[AI Rate] Success | keyId: <key> | operation: <op> | elapsed: <ms>ms | reqId: <id>
[AI Rate] Fail | keyId: <key> | operation: <op> | elapsed: <ms>ms | retries: <count> | errorCode: <code> | reqId: <id>
```

**Backoff**:
```
[AI Rate] Backoff | keyId: <key> | operation: <op> | delay: <ms>ms | attempt: <count> | reqId: <id>
```

#### Facebook Requests

**Request Start**:
```
[FB Rate] Request start | endpoint: <endpoint> | userId: <userId> | priority: <priority> | cacheHit: <bool>
```

**Request Complete**:
```
[FB Rate] Success | endpoint: <endpoint> | userId: <userId> | elapsed: <ms>ms
[FB Rate] Fail | endpoint: <endpoint> | userId: <userId> | elapsed: <ms>ms | errorCode: <code>
```

### Summary Logs

#### AI Summary (every 5 minutes)

```
[AI Rate] Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[AI Rate] Total Keys: 25 | Active: 18
[AI Rate] Total Req/Min: 142 | Total Tokens/Min: 28500
[AI Rate] Avg Req/Key: 5.7 | Avg Tokens/Key: 1140
[AI Rate] ⚠️  Keys Near Limit: 2
[AI Rate] Per-Key Breakdown:
[AI Rate]   • nvapi-abc123... | Req: 13/15 | Tokens: 29000/32k | Daily: 456/1500 | Warnings: 2
[AI Rate] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### Facebook Summary (every 5 minutes)

```
[FB Rate] Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[FB Rate] Total Users: 45 | Active: 32
[FB Rate] Total Calls: 1250 | Global: 1250
[FB Rate] Avg Calls/User: 27.8
[FB Rate] Cache Size: 128 entries
[FB Rate] ⚠️  Users Near Limit: 3
[FB Rate] Per-User Breakdown:
[FB Rate]   • user123... | Calls: 185/200 (92.5%) | Warnings: 3
[FB Rate] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Health Checks (every 30 minutes)

```
[AI Keys] Health Check ━━━━━━━━━━━━━━━━━━━━━━━━━━━
[AI Keys] Active keys: 23/25
[AI Keys] ⚠️  2 keys rate-limited
[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Configuration

### Environment Variables

#### AI Service

```bash
# Minimum recommended keys for enterprise
AI_MIN_KEYS=20

# Enable rate summary logging
AI_ENABLE_RATE_SUMMARY=true

# Enable periodic health checks
AI_ENABLE_HEALTH_CHECK=true

# Request queue configuration
AI_REQUEST_QUEUE_MAX_CONCURRENT=50
AI_USE_DYNAMIC_CONCURRENCY=true

# Backoff configuration (optional)
AI_BASE_RETRY_DELAY_MS=500
AI_MAX_RETRY_DELAY_MS=2000
```

#### Facebook Service

```bash
# Enable rate summary logging
FB_ENABLE_RATE_SUMMARY=true

# Cache TTL (milliseconds)
FB_CONVERSATION_CACHE_TTL=300000  # 5 minutes
FB_METADATA_CACHE_TTL=600000      # 10 minutes

# Rate limiting
FB_USER_LIMIT_PER_HOUR=200
FB_WARNING_THRESHOLD=0.8  # 80%
```

### Startup Initialization

**File**: `src/lib/init/rate-limiting-init.ts`

Initialize on app startup:

```typescript
import { initializeRateLimiting } from '@/lib/init/rate-limiting-init';

// In your app initialization (e.g., layout.tsx or middleware)
await initializeRateLimiting();
```

This will:
1. Log AI key pool status
2. Start periodic health checks
3. Initialize rate tracking
4. Start summary logging

---

## Testing

### Test Utilities

**File**: `src/lib/testing/rate-limit-test-utils.ts`

#### 1. AI Burst Test

Simulates burst of AI requests:

```typescript
import { simulateAIBurst } from '@/lib/testing/rate-limit-test-utils';

const result = await simulateAIBurst({
  keyCount: 5,
  requestsPerKey: 20,
  highPriorityRatio: 0.3, // 30% high priority
});

console.log('Average latency:', result.averageLatency);
console.log('Warnings:', result.warnings);
```

#### 2. Facebook Burst Test

Simulates burst of Facebook requests:

```typescript
import { simulateFacebookBurst } from '@/lib/testing/rate-limit-test-utils';

const result = await simulateFacebookBurst({
  userCount: 10,
  requestsPerUser: 15,
  cacheHitRatio: 0.4, // 40% cache hits
});

console.log('Cache hits:', result.cacheHits);
console.log('Throttled:', result.throttled);
```

#### 3. Queue Priority Test

Validates priority handling:

```typescript
import { validateQueuePriority } from '@/lib/testing/rate-limit-test-utils';

const result = await validateQueuePriority();

console.log('Passed:', result.passed);
console.log('High priority avg wait:', result.highPriorityAvgWait);
console.log('Low priority avg wait:', result.lowPriorityAvgWait);
```

#### 4. Run All Tests

```typescript
import { runAllRateLimitTests } from '@/lib/testing/rate-limit-test-utils';

await runAllRateLimitTests();
```

### Expected Test Results

✓ **AI Burst**: No errors, avg latency < 200ms, warnings < 10
✓ **Facebook Burst**: Cache hit ratio ≥ 30%, throttled < 5%
✓ **Queue Priority**: High priority wait < low priority wait
✓ **Degraded Conditions**: Backoff logs present, retries triggered

---

## Troubleshooting

### Common Issues

#### 1. "All API keys are rate-limited"

**Symptoms**:
```
[NVIDIA] 🚫 All API keys are rate-limited. Earliest key available in ~15 minute(s).
```

**Solutions**:
- Wait for rate limits to reset (typically 1 hour)
- Add more API keys to the pool
- Review and reduce concurrent request load
- Check if requests are properly distributed across keys

#### 2. "Key pool below recommended threshold"

**Symptoms**:
```
[AI Keys] ⚠️  WARNING: Key pool below recommended threshold
[AI Keys] ⚠️  Consider adding 10 more keys for optimal performance
```

**Solutions**:
- Add more API keys through Settings → API Keys
- Target: 20-30 keys for enterprise load
- Each key provides: 15 req/min, 32k tokens/min

#### 3. "Facebook rate limit exceeded"

**Symptoms**:
```
[FB Rate] ⚠️  CRITICAL usage | userId: user123... | calls: 195/200 (97.5%)
```

**Solutions**:
- Reduce sync frequency for this user
- Enable caching (should be enabled by default)
- Batch multiple operations together
- Use low priority for non-urgent requests

#### 4. "Cache not working"

**Symptoms**:
- No cache hits in logs
- High API call volume

**Solutions**:
- Check `useCache` parameter is `true`
- Verify cache TTL configuration
- Check if cache is being cleared prematurely
- Review cache key generation logic

### Debug Mode

Enable detailed logging:

```bash
# .env.local
DEBUG=true
LOG_LEVEL=debug
AI_ENABLE_RATE_SUMMARY=true
FB_ENABLE_RATE_SUMMARY=true
```

### Monitoring Queries

#### Check AI Key Pool Health

```typescript
import apiKeyManager from '@/lib/ai/api-key-manager';

const stats = await apiKeyManager.getRateLimitUsageStats();
console.log('Active keys:', stats.summary.activeKeys);
console.log('Rate limited:', stats.summary.rateLimitedKeys);
console.log('Success rate:', stats.summary.successRate);
```

#### Check Facebook Usage

```typescript
import { facebookRateLimiter } from '@/lib/facebook/rate-limiter';

const summary = facebookRateLimiter.getSummary();
console.log('Active users:', summary.activeUsers);
console.log('Users near limit:', summary.usersNearLimit);
console.log('Cache size:', summary.cacheSize);
```

#### Check Queue Status

```typescript
import { requestQueue } from '@/lib/ai/request-queue';

const stats = requestQueue.getStats();
console.log('Queue size:', stats.queueSize);
console.log('Current concurrent:', stats.currentConcurrent);
console.log('Priority breakdown:', stats.priorityBreakdown);
```

---

## Performance Metrics

### Expected Metrics

#### AI Service
- **Request latency**: 1-3 seconds (average)
- **Queue wait time**: < 100ms (high priority), < 500ms (low priority)
- **Key utilization**: 60-80% of limits
- **Cache hit rate**: N/A (no caching for AI)

#### Facebook Service
- **Request latency**: 100-500ms (cache miss), < 10ms (cache hit)
- **Cache hit rate**: 40-60% (after warm-up)
- **Throttle rate**: < 5% of requests
- **User utilization**: 50-70% of per-user limit

### Optimization Tips

1. **Increase key pool**: More keys = higher throughput
2. **Use priority wisely**: Only critical requests as HIGH
3. **Enable caching**: Reduces Facebook API calls by 40-60%
4. **Batch operations**: Reduces overhead
5. **Monitor warnings**: Act before hitting hard limits

---

## API Reference

### Rate Tracker

```typescript
import { rateTracker } from '@/lib/ai/rate-tracker';

// Log request start
rateTracker.logRequestStart({
  keyId: string,
  operation: string,
  priority: string,
  tokens: number,
  reqId: string,
});

// Log request complete
rateTracker.logRequestComplete({
  keyId: string,
  operation: string,
  elapsedMs: number,
  success: boolean,
  errorCode?: string,
  retryCount?: number,
  reqId: string,
});

// Log backoff
rateTracker.logBackoff({
  keyId: string,
  operation: string,
  delayMs: number,
  attempt: number,
  reqId: string,
});

// Get usage stats
const usage = rateTracker.getKeyUsageStats(keyId);
const summary = rateTracker.getSummary();
```

### Facebook Rate Limiter

```typescript
import { facebookRateLimiter } from '@/lib/facebook/rate-limiter';

// Check rate limit
const check = facebookRateLimiter.checkRateLimit(userId, priority);

// Get cached response
const cached = facebookRateLimiter.getCachedResponse<T>(endpoint, params);

// Set cached response
facebookRateLimiter.setCachedResponse(endpoint, params, data, ttl);

// Log request
facebookRateLimiter.logRequestStart({
  endpoint: string,
  userId: string,
  priority: 'high' | 'low',
  cacheHit: boolean,
});

facebookRateLimiter.logRequestComplete({
  endpoint: string,
  userId: string,
  elapsedMs: number,
  success: boolean,
  errorCode?: string,
});

// Get usage stats
const usage = facebookRateLimiter.getUserUsageStats(userId);
const summary = facebookRateLimiter.getSummary();
```

---

## Support

For issues or questions:

1. Check logs for warnings and errors
2. Review this documentation
3. Run test suite: `runAllRateLimitTests()`
4. Check API key status in Settings → API Keys
5. Monitor summary logs for trends

---

**Last Updated**: 2025-01-XX
**Version**: 1.0.0

