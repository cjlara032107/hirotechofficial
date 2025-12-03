# Solution 4: Request Queuing System - Implementation Complete

## Overview

Implemented a request queuing system for AI analysis to prevent connection pool exhaustion by controlling the rate of concurrent database operations.

## Architecture

```
┌─────────────────┐
│  Analysis       │
│  Requests       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Analysis Queue │
│  (Priority)     │
└────────┬────────┘
         │
         │ Controlled Batch Processing
         │ (Max 10 concurrent)
         ▼
┌─────────────────┐
│  AI Analysis    │
│  (Database)    │
└─────────────────┘
```

## Benefits

1. **Prevents Connection Pool Exhaustion**: Limits concurrent database operations
2. **Priority Support**: High-priority requests processed first
3. **Automatic Retry**: Failed requests retry up to 3 times
4. **Statistics & Monitoring**: Real-time queue metrics
5. **Graceful Shutdown**: Handles process termination cleanly
6. **Configurable**: Adjustable concurrency and queue size

## Implementation Status

✅ **Completed:**
- Queue data structure with priority support
- Queue processor with concurrency control
- Statistics and monitoring
- Queue manager singleton
- Integration into analyze-contact flow
- Configuration options
- Health checks
- Monitoring endpoint
- Graceful shutdown

## Files Created

1. **`src/lib/ai/analysis-queue.ts`**
   - Core queue implementation
   - Priority-based processing
   - Statistics tracking
   - Retry logic

2. **`src/lib/ai/analyze-contact-queued.ts`**
   - Wrapper for queued analysis
   - Automatic fallback to direct analysis
   - Configuration check

3. **`src/lib/ai/queue-health.ts`**
   - Health check utilities
   - Status indicators

4. **`src/app/api/ai/queue-stats/route.ts`**
   - REST API endpoint for queue statistics
   - Real-time metrics

## Configuration

### Enable Queue

Add to your `.env.local`:

```env
# Enable analysis queue
USE_ANALYSIS_QUEUE=true

# Optional: Customize queue settings
AI_ANALYSIS_QUEUE_CONCURRENCY=10      # Max concurrent analyses (default: 10)
AI_ANALYSIS_QUEUE_MAX_SIZE=1000      # Max queue size (default: 1000)
AI_ANALYSIS_QUEUE_INTERVAL=100       # Process interval in ms (default: 100)
```

### Disable Queue

Remove or set to `false`:

```env
USE_ANALYSIS_QUEUE=false
```

When disabled, the system uses direct analysis (current behavior).

## Usage

### Basic Usage

The queue is automatically used when enabled. No code changes needed in most cases.

### Priority Levels

```typescript
import { analyzeContactQueued } from '@/lib/ai/analyze-contact-queued';

// High priority (processed first)
await analyzeContactQueued(messages, stages, date, jobId, 'high');

// Normal priority (default)
await analyzeContactQueued(messages, stages, date, jobId, 'normal');

// Low priority (processed last)
await analyzeContactQueued(messages, stages, date, jobId, 'low');
```

## Monitoring

### Check Queue Statistics

**API Endpoint:**
```
GET /api/ai/queue-stats
```

**Response:**
```json
{
  "enabled": true,
  "stats": {
    "totalQueued": 150,
    "totalProcessed": 120,
    "totalFailed": 2,
    "currentQueueSize": 30,
    "currentProcessing": 5,
    "averageWaitTime": 2500,
    "averageProcessTime": 3500,
    "queueUtilization": 3,
    "health": "healthy"
  },
  "config": {
    "maxConcurrent": 10,
    "maxQueueSize": 1000,
    "processInterval": 100
  }
}
```

### Health Check

```typescript
import { checkQueueHealth } from '@/lib/ai/queue-health';

const health = checkQueueHealth();
console.log(health.status); // 'healthy' | 'warning' | 'critical'
```

## Queue Behavior

### Processing Flow

1. **Request Enqueued**: Added to queue with priority
2. **Queue Processor**: Picks up requests based on priority
3. **Concurrency Control**: Limits to MAX_CONCURRENT simultaneous analyses
4. **Processing**: Executes analysis with retry logic
5. **Completion**: Resolves promise with result

### Priority Order

1. **High**: Processed first
2. **Normal**: Processed after high priority
3. **Low**: Processed last (used for retries)

### Retry Logic

- Failed requests retry up to 3 times
- Retries are queued with 'low' priority
- Exponential backoff between retries

### Timeout Handling

- Requests timeout after 5 minutes in queue
- Timed-out requests are rejected with error
- Prevents queue from growing indefinitely

## Performance Impact

### Expected Improvements

- **Connection Pool Usage**: Reduced by 50-70% (controlled concurrency)
- **Database Load**: More predictable and manageable
- **Error Rate**: Lower due to controlled processing
- **Throughput**: Slightly reduced but more stable

### Trade-offs

- **Latency**: Slight increase due to queuing (typically < 1 second)
- **Memory**: Queue uses memory for pending requests
- **Complexity**: Additional system to monitor

## Monitoring & Alerts

### Health Indicators

- **Healthy**: Queue utilization < 80%, wait time < 1 minute
- **Warning**: Queue utilization 80-95%, or wait time > 1 minute
- **Critical**: Queue utilization ≥ 95%, or wait time > 5 minutes

### Recommended Monitoring

1. **Queue Size**: Monitor `currentQueueSize` - should stay < 800
2. **Wait Time**: Monitor `averageWaitTime` - should stay < 30 seconds
3. **Failure Rate**: Monitor `totalFailed / totalQueued` - should stay < 5%
4. **Processing Time**: Monitor `averageProcessTime` - baseline for performance

## Troubleshooting

### Queue Full

**Symptom**: `Queue is full` error

**Solutions**:
1. Increase `AI_ANALYSIS_QUEUE_MAX_SIZE`
2. Increase `AI_ANALYSIS_QUEUE_CONCURRENCY`
3. Check for stuck requests
4. Review processing time (may be too slow)

### High Wait Times

**Symptom**: `averageWaitTime` > 60 seconds

**Solutions**:
1. Increase `AI_ANALYSIS_QUEUE_CONCURRENCY`
2. Check database connection pool health
3. Review AI API response times
4. Consider using edge functions (Solution 2)

### High Failure Rate

**Symptom**: `totalFailed / totalQueued` > 10%

**Solutions**:
1. Check AI API key availability
2. Review error logs for patterns
3. Check database connection health
4. Verify network connectivity

## Integration Points

### Modified Files

1. **`src/lib/facebook/pipeline-analyzer/process-contact.ts`**
   - Uses `analyzeContactQueued` instead of direct `analyzeContact`
   - Automatic fallback if queue unavailable

### Backward Compatibility

- ✅ Queue is opt-in (disabled by default)
- ✅ Automatic fallback to direct analysis if queue fails
- ✅ No breaking changes to existing code
- ✅ Can be enabled/disabled via environment variable

## Next Steps

1. **Enable Queue**: Set `USE_ANALYSIS_QUEUE=true` in `.env.local`
2. **Monitor**: Check `/api/ai/queue-stats` regularly
3. **Tune**: Adjust concurrency based on performance
4. **Alert**: Set up alerts for critical queue status

## Testing

### Test Queue Functionality

```typescript
import { analyzeContactQueued } from '@/lib/ai/analyze-contact-queued';
import { getQueueStats } from '@/lib/ai/analyze-contact-queued';

// Enable queue in .env.local
// USE_ANALYSIS_QUEUE=true

// Make analysis request
const result = await analyzeContactQueued(messages, stages, date, 'test-job');

// Check queue stats
const stats = getQueueStats();
console.log('Queue size:', stats.currentQueueSize);
```

### Load Testing

1. Enable queue
2. Send 100+ analysis requests simultaneously
3. Monitor queue stats endpoint
4. Verify all requests complete successfully
5. Check connection pool usage

---

**Solution 4 is complete and ready to use!** 🚀









