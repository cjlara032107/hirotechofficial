# Rate Limiting Quick Start Guide

## TL;DR

This system provides comprehensive rate limiting, caching, and observability for Google AI and Facebook API calls.

## Key Features

✅ **AI Key Pool**: 20-30 keys recommended (currently tracks per-key usage)
✅ **Per-Key Rate Tracking**: Monitors requests/min, tokens/min, requests/day  
✅ **Priority Queueing**: High-priority requests processed first  
✅ **Facebook Caching**: 5-10 min response caching  
✅ **Per-User Rate Guards**: 200 calls/hour per user  
✅ **Structured Logging**: All requests logged with context  
✅ **Auto Warnings**: Alerts at 80% quota usage  
✅ **Summary Logs**: Every 5 minutes  

## Quick Setup

### 1. Environment Variables

```bash
# Required
NVIDIA_API_KEY=your_key_here  # Or add multiple keys via UI

# Optional (recommended for production)
AI_ENABLE_RATE_SUMMARY=true
FB_ENABLE_RATE_SUMMARY=true
AI_ENABLE_HEALTH_CHECK=true
```

### 2. Initialize on Startup

Add to your app initialization (e.g., `middleware.ts` or `layout.tsx`):

```typescript
import { initializeRateLimiting } from '@/lib/init/rate-limiting-init';

// On app startup
await initializeRateLimiting();
```

That's it! The system will automatically:
- Log AI key pool status
- Track rate usage per key/user
- Apply caching and batching
- Log warnings and summaries

## What You'll See

### On Startup

```
[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[AI Keys] Loaded 25 keys
[AI Keys] Min expected: 20
[AI Keys] ✅ Key pool is in optimal range
[AI Keys] Status breakdown:
[AI Keys]   • Active: 25
[AI Keys]   • Rate Limited: 0
[AI Keys]   • Disabled: 0
[AI Keys] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### During Operation

```
[AI Rate] Request start | keyId: nvapi-abc... | operation: analyzeConversation | priority: NORMAL | tokens: 2000
[AI Rate] Success | keyId: nvapi-abc... | elapsed: 1234ms

[FB Rate] Request start | endpoint: getConversations | userId: user123... | cacheHit: true
```

### Warnings (at 80% quota)

```
[AI Rate] ⚠️  High usage | keyId: nvapi-abc... | requests/min: 12/15 (80.0%)
[FB Rate] ⚠️  High usage | userId: user123... | calls: 160/200 (80.0%)
```

### Summary (every 5 minutes)

```
[AI Rate] Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[AI Rate] Total Keys: 25 | Active: 23
[AI Rate] Total Req/Min: 142 | Total Tokens/Min: 28500
[AI Rate] Avg Req/Key: 5.7 | Avg Tokens/Key: 1140
[AI Rate] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Testing

Run the test suite:

```typescript
import { runAllRateLimitTests } from '@/lib/testing/rate-limit-test-utils';

await runAllRateLimitTests();
```

Expected output:

```
[Rate Test] AI Burst: ✓ PASSED
[Rate Test] Facebook Burst: ✓ PASSED
[Rate Test] Queue Priority: ✓ PASSED
[Rate Test] Degraded Conditions: ✓ VALIDATED
```

## Troubleshooting

### Issue: "All API keys are rate-limited"

**Solution**: Wait 1 hour or add more keys (target: 20-30)

### Issue: "Key pool below threshold"

**Solution**: Add more API keys via Settings → API Keys

### Issue: "Facebook rate limit exceeded"

**Solution**: Enable caching (default) or reduce sync frequency

### Issue: No logs appearing

**Solution**: Enable logging:
```bash
AI_ENABLE_RATE_SUMMARY=true
FB_ENABLE_RATE_SUMMARY=true
```

## Monitoring

### Check AI Health

```typescript
import apiKeyManager from '@/lib/ai/api-key-manager';

const stats = await apiKeyManager.getRateLimitUsageStats();
console.log(stats.summary);
```

### Check Facebook Health

```typescript
import { facebookRateLimiter } from '@/lib/facebook/rate-limiter';

const summary = facebookRateLimiter.getSummary();
console.log(summary);
```

### Check Queue Status

```typescript
import { requestQueue } from '@/lib/ai/request-queue';

const stats = requestQueue.getStats();
console.log(stats);
```

## Key Metrics

### Targets

- **AI Key Pool**: 20-30 keys
- **AI Key Utilization**: 60-80% of limits
- **Facebook Cache Hit Rate**: 40-60%
- **Throttle Rate**: < 5%
- **Queue Wait Time**: < 100ms (high priority)

### What to Watch

🚨 **Red Flags**:
- Rate limited keys > 20%
- Throttled requests > 10%
- Cache hit rate < 30%
- Queue size > 100

⚠️ **Yellow Flags**:
- Key pool < 20
- Key utilization > 85%
- Users near limit > 15%
- Queue wait > 500ms

✅ **Green Flags**:
- All keys active
- Cache hit rate > 40%
- Throttle rate < 5%
- Low warning count

## Advanced Usage

### Custom Priority

```typescript
import { executeAIRequest, RequestPriority } from '@/lib/ai/ai-request-wrapper';

const result = await executeAIRequest(
  () => myAIFunction(),
  {
    operation: 'myOperation',
    priority: RequestPriority.HIGH,  // CRITICAL, HIGH, NORMAL, LOW
    timeout: 60000,
  }
);
```

### Manual Cache Control

```typescript
import { facebookRateLimiter } from '@/lib/facebook/rate-limiter';

// Get cached
const cached = facebookRateLimiter.getCachedResponse<MyType>(
  'myEndpoint',
  { param1: 'value' }
);

// Set cached
facebookRateLimiter.setCachedResponse(
  'myEndpoint',
  { param1: 'value' },
  myData,
  600000  // 10 min TTL
);
```

## Files Reference

| File | Purpose |
|------|---------|
| `src/lib/ai/rate-tracker.ts` | Per-key rate tracking for AI |
| `src/lib/facebook/rate-limiter.ts` | Per-user rate limiting for Facebook |
| `src/lib/ai/startup-logger.ts` | Startup logging and health checks |
| `src/lib/init/rate-limiting-init.ts` | Initialization module |
| `src/lib/testing/rate-limit-test-utils.ts` | Testing utilities |
| `docs/RATE_LIMITING.md` | Full documentation |

## Next Steps

1. ✅ Initialize on startup
2. ✅ Monitor logs for warnings
3. ✅ Add more keys if needed (target: 20-30)
4. ✅ Run test suite periodically
5. ✅ Review summary logs

---

**Need more details?** See [RATE_LIMITING.md](./RATE_LIMITING.md)

