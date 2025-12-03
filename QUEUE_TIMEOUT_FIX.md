# Queue Timeout Fix - Preventing Request Cancellation

## Issue Found

The queue was potentially canceling requests due to timeout conflicts:

1. **60-second timeout in `process-contact.ts`** was too short when queue is enabled
2. **Queue timeout logic** could reject requests that were already processing
3. **Race condition** between queue timeout and processing timeout

## Fixes Applied

### 1. Increased Timeout When Queue Enabled ✅

**Before:**
- Fixed 60-second timeout regardless of queue status
- Queue operations could take 2+ minutes (queue wait + processing)

**After:**
- **90 seconds** when queue is disabled (direct analysis)
- **180 seconds (3 minutes)** when queue is enabled
- Accounts for queue wait time + processing time

### 2. Fixed Queue Timeout Logic ✅

**Before:**
- Timeout could fire even if request was already processing
- No way to cancel timeout when processing starts

**After:**
- Timeout ID stored in request object
- Timeout cleared when request starts processing
- Only rejects if request is still waiting in queue

### 3. Better Timeout Messages ✅

- Clear error messages indicating queue status
- "Analysis timeout after 3 minutes (queue may be busy)" when queue enabled
- Helps identify if timeout is due to queue backlog

## Code Changes

### `process-contact.ts`
```typescript
// Dynamic timeout based on queue status
const queueEnabled = isQueueEnabled();
const analysisTimeout = queueEnabled ? 180000 : 90000; // 3 min with queue, 90s without
```

### `analysis-queue.ts`
```typescript
// Store timeout ID in request
request.timeoutId = setTimeout(() => { ... }, this.MAX_WAIT_TIME);

// Clear timeout when processing starts
if (request.timeoutId) {
  clearTimeout(request.timeoutId);
  request.timeoutId = undefined;
}
```

## Expected Behavior

✅ **No Premature Cancellation**: Requests won't be canceled if they're processing  
✅ **Appropriate Timeouts**: Longer timeout when queue is enabled  
✅ **Clear Error Messages**: Users know if timeout is due to queue backlog  
✅ **Proper Cleanup**: Timeouts are cleared when no longer needed  

## Testing

1. Enable queue: `USE_ANALYSIS_QUEUE=true`
2. Process 15 contacts
3. Verify all complete without premature timeouts
4. Check logs for timeout messages

## If Still Having Issues

1. **Check queue status**: `/api/ai/queue-stats`
2. **Monitor queue size**: Should stay reasonable (< 100)
3. **Check processing count**: Should be ≤ MAX_CONCURRENT (10)
4. **Disable queue if needed**: `USE_ANALYSIS_QUEUE=false`

---

**Fix Applied**: Queue timeouts now properly account for queue wait time and don't cancel in-flight requests.









