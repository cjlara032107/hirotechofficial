# Queue Fix: Stuck Analysis Issue

## Problem

Analysis was getting stuck at "2 out of 15" with 6 failed contacts. The queue processor had a critical bug preventing concurrent processing.

## Root Cause

1. **`isProcessing` Flag Bug**: A global `isProcessing` flag was blocking concurrent request processing
2. **Processor Stopping Prematurely**: Processor stopped when queue was empty, but didn't restart when new requests arrived during processing
3. **No Timeout on Queue Operations**: Queue operations could wait indefinitely

## Fixes Applied

### 1. Removed Blocking `isProcessing` Flag ✅

**Before:**
```typescript
if (this.isProcessing || this.isShuttingDown) {
  return; // Blocked all processing
}
```

**After:**
- Removed global `isProcessing` flag
- Now processes multiple requests concurrently up to `MAX_CONCURRENT` limit
- Each request tracked individually in `processing` Set

### 2. Improved Concurrent Processing ✅

**Before:**
- Processed one request at a time
- Blocked by `isProcessing` flag

**After:**
- Processes multiple requests concurrently (up to `MAX_CONCURRENT`)
- Uses `while` loop to process all available requests
- Each request runs independently

### 3. Better Processor Restart Logic ✅

**Before:**
- Processor stopped when queue empty
- Didn't restart if requests added during processing

**After:**
- Processor restarts automatically if queue has items and below concurrency limit
- Only stops when queue is empty AND nothing is processing

### 4. Added Queue Operation Timeout ✅

**Before:**
- Queue operations could wait indefinitely

**After:**
- Added 2-minute timeout on queue operations
- Automatically falls back to direct analysis if timeout

### 5. Enhanced Error Handling ✅

- Better error logging with job ID
- Errors properly propagate for retry logic
- Failed requests properly tracked

## How to Use

### If Queue is Causing Issues

**Option 1: Disable Queue (Immediate Fix)**
```env
# In .env.local - remove or set to false
USE_ANALYSIS_QUEUE=false
```

**Option 2: Check Queue Status**
```bash
# Check queue stats
curl http://localhost:3000/api/ai/queue-stats
```

**Option 3: Monitor Queue**
- Check logs for `[AnalysisQueue]` messages
- Monitor queue size and processing count
- Check for error messages

## Expected Behavior After Fix

✅ **Concurrent Processing**: Multiple requests process simultaneously (up to 10 by default)  
✅ **No Blocking**: Requests don't block each other  
✅ **Automatic Restart**: Processor restarts when needed  
✅ **Timeout Protection**: Operations timeout after 2 minutes  
✅ **Graceful Fallback**: Falls back to direct analysis if queue fails  

## Testing

1. **Enable queue**: `USE_ANALYSIS_QUEUE=true`
2. **Run analysis**: Process 15 contacts
3. **Monitor**: Check that all 15 complete (not stuck at 2)
4. **Verify**: Check queue stats endpoint

## If Still Stuck

1. **Disable queue immediately**: `USE_ANALYSIS_QUEUE=false`
2. **Check logs**: Look for error messages
3. **Check database**: Verify connection pool isn't exhausted
4. **Check API keys**: Verify AI API keys are valid
5. **Monitor**: Use `/api/ai/queue-stats` to see queue status

---

**Fix Applied**: Queue now processes requests concurrently without blocking. If issues persist, disable queue with `USE_ANALYSIS_QUEUE=false`.









