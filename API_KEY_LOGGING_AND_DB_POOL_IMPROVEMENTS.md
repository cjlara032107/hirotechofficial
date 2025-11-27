# API Key Logging & Database Pool Improvements

## Summary

Enhanced logging for API key usage tracking and optimized database connection pool configuration to support parallel processing with 20 NVIDIA API keys.

## Changes Made

### 1. Enhanced API Key Manager Logging (`src/lib/ai/api-key-manager.ts`)

#### Added Features:
- **Request ID Tracking**: Each API key request now gets a unique request ID for tracking concurrent operations
- **Operation Context**: Logs now include operation type, contact ID, and campaign ID when available
- **Usage Statistics**: Tracks per-key usage counts and last used timestamps
- **Parallel Processing Detection**: Automatically detects and logs when multiple requests are happening concurrently
- **Enhanced Refresh Logging**: Shows key names, request counts, and change in active key count

#### New Log Format:
```
[ApiKeyManager] [req-1234567890-1] ✅ Using key #3/20 (abc12345... | NVIDIA Key #3) | Total uses: 45 | Operation: analyzeConversation | Contact: cmigddvv...
[ApiKeyManager] [req-1234567890-1] 🔄 Parallel processing: 5 concurrent requests detected
```

#### Key Methods Enhanced:
- `getNextKey()`: Now accepts `requestContext` parameter with operation, contactId, campaignId
- `refreshActiveKeys()`: Enhanced logging with key names and statistics
- `markRateLimited()`: Includes operation context in logs
- `recordSuccess()`: Logs operation type and duration for important operations

### 2. Database Connection Pool Optimization (`src/lib/db.ts`)

#### Changes:
- **Connection Limit**: Increased from 20 → **25** (allows more concurrent connections)
- **Pool Timeout**: Increased from 60s → **90s** (more time to get connection under high load)
- **Connect Timeout**: Increased from 20s → **30s** (more time for initial connection)
- **Statement Cache**: Disabled (`statement_cache_size=0`) to reduce memory usage

#### Enhanced Error Handling:
- Better detection of pool exhaustion errors (P2024)
- More informative error messages with actionable suggestions
- Improved retry logic for connection pool timeouts

#### New Log Format:
```
[Prisma] 🔧 Enhanced connection pool settings for parallel processing:
[Prisma]   - connection_limit: 25
[Prisma]   - pool_timeout: 90s
[Prisma]   - connect_timeout: 30s
[Prisma] ✅ Connected to database (pool configured)
```

### 3. Updated API Key Usage Points

#### Files Updated:
- `src/lib/ai/google-ai-service.ts`
  - `analyzeConversation()`: Now passes context and records success with duration
  - `analyzeConversationWithStageRecommendation()`: Enhanced with context tracking
  - `getApiKey()`: Accepts and passes request context

- `src/lib/ai/assistant-service.ts`
  - `processAssistantMessage()`: Tracks operation and records success with duration
  - `getApiKey()`: Accepts and passes request context

- `src/lib/ai/contact-info-extraction.ts`
  - `extractContactInfo()`: Now accepts context parameter for tracking

## Benefits

### 1. Better Visibility
- **Track which keys are being used**: See exactly which API key is used for each operation
- **Monitor parallel processing**: Detect when multiple requests are happening simultaneously
- **Identify bottlenecks**: See which operations take longest and which keys are most used

### 2. Improved Debugging
- **Request IDs**: Track individual requests through the system
- **Operation context**: Know what operation each key is being used for
- **Error correlation**: Match errors to specific keys and operations

### 3. Database Pool Reliability
- **More connections**: 25 connections support more parallel operations
- **Longer timeouts**: 90s pool timeout prevents premature failures under load
- **Better error messages**: Clear guidance when pool is exhausted

## Example Log Output

### Before:
```
[ApiKeyManager] Using key abc123 (NVIDIA Key #1)
[NVIDIA] Sending request - Model: openai/gpt-oss-20b
```

### After:
```
[ApiKeyManager] [req-1764197203451-1] ✅ Using key #3/20 (abc12345... | NVIDIA Key #3) | Total uses: 45 | Operation: analyzeConversation | Contact: cmigddvv...
[ApiKeyManager] [req-1764197203451-1] 🔄 Parallel processing: 5 concurrent requests detected
[NVIDIA] Sending request - Model: openai/gpt-oss-20b, Messages: 12
[ApiKeyManager] ✅ Success: abc12345... (NVIDIA Key #3) | Operation: analyzeConversation | Total requests: 46 | Duration: 1234ms
```

## Monitoring Recommendations

1. **Watch for parallel processing logs**: Look for "🔄 Parallel processing" messages to confirm concurrent operations
2. **Monitor key rotation**: Check that all 20 keys are being used (should see keys #1-20 in rotation)
3. **Track pool exhaustion**: Watch for P2024 errors - if frequent, may need further pool optimization
4. **Review usage statistics**: Check which keys are most used and ensure even distribution

## Next Steps

1. **Deploy to production** and monitor logs
2. **Verify parallel processing** is working with all 20 keys
3. **Monitor database pool** usage and adjust if needed
4. **Review key usage patterns** to ensure even distribution

## Testing

To verify the improvements:

1. **Trigger parallel operations**: Sync multiple contacts or generate AI messages
2. **Check logs**: Look for request IDs and parallel processing indicators
3. **Verify key rotation**: Should see different key numbers in sequence
4. **Monitor database**: Check for pool exhaustion errors (should be reduced)

