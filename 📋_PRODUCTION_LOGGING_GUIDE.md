# 📋 Production Logging Guide

## Overview

This guide explains the comprehensive logging system implemented across HIRO V1.2's backend, designed specifically for production debugging and monitoring.

---

## 🎯 Key Features

### 1. **Unique Request IDs**
Every operation is tagged with a unique request ID for tracing:
```
[Enhanced Analysis analysis-1733230800000-abc123] Starting analysis
[ApiKeyManager conn-1733230800000] Attempting connection
[Prisma conn-1733230800500] Connection attempt 1/3
```

### 2. **Structured Logging Format**
All critical operations use a consistent box format:
```
============================================
✅ OPERATION COMPLETE
- Duration: 1500ms
- Status: success
- Details: ...
============================================
```

### 3. **Contextual Information**
Every log includes relevant context:
- **Duration**: How long the operation took
- **Status**: Success/failure indicators
- **Metrics**: Memory usage, counts, rates
- **Error Details**: Type, message, stack trace

### 4. **Production-Safe**
- No sensitive data in logs (API keys masked)
- Stack traces limited to relevant lines
- Memory usage tracked
- Request correlation via IDs

---

## 📊 Log Categories

### AI Analysis Logs

#### Success Case
```
[Enhanced Analysis analysis-1733230800000-abc123] ============================================
[Enhanced Analysis analysis-1733230800000-abc123] ✅ AI ANALYSIS SUCCESS on attempt 1
[Enhanced Analysis analysis-1733230800000-abc123] - Duration: 1234ms
[Enhanced Analysis analysis-1733230800000-abc123] - Lead Score: 85/100
[Enhanced Analysis analysis-1733230800000-abc123] - Recommended Stage: Hot Lead
[Enhanced Analysis analysis-1733230800000-abc123] - Lead Status: QUALIFIED
[Enhanced Analysis analysis-1733230800000-abc123] - Confidence: 92%
[Enhanced Analysis analysis-1733230800000-abc123] - Used Fallback: false
[Enhanced Analysis analysis-1733230800000-abc123] ============================================
```

#### Failure Case
```
[Enhanced Analysis analysis-1733230800000-abc123] ============================================
[Enhanced Analysis analysis-1733230800000-abc123] ❌ ATTEMPT 1/3 FAILED
[Enhanced Analysis analysis-1733230800000-abc123] - Duration: 5678ms
[Enhanced Analysis analysis-1733230800000-abc123] - Error: API timeout after 30000ms
[Enhanced Analysis analysis-1733230800000-abc123] - Error Type: Error
[Enhanced Analysis analysis-1733230800000-abc123] - Messages Analyzed: 150
[Enhanced Analysis analysis-1733230800000-abc123] - Stack trace (first 5 lines):
[Enhanced Analysis analysis-1733230800000-abc123]   1. at analyzeWithFallback (enhanced-analysis.ts:75)
[Enhanced Analysis analysis-1733230800000-abc123]   2. at analyzeConversation (google-ai-service.ts:120)
[Enhanced Analysis analysis-1733230800000-abc123]   3. at async Promise.race (...)
[Enhanced Analysis analysis-1733230800000-abc123] ============================================
```

#### Fallback Case
```
[Enhanced Analysis analysis-1733230800000-abc123] ============================================
[Enhanced Analysis analysis-1733230800000-abc123] ❌ ALL 3 AI ATTEMPTS FAILED - USING FALLBACK
[Enhanced Analysis analysis-1733230800000-abc123] - Total Duration: 18456ms
[Enhanced Analysis analysis-1733230800000-abc123] - Messages: 150
[Enhanced Analysis analysis-1733230800000-abc123] - Stages: 5
[Enhanced Analysis analysis-1733230800000-abc123] - Last Error: API rate limit exceeded
[Enhanced Analysis analysis-1733230800000-abc123] - Error Type: Error
[Enhanced Analysis analysis-1733230800000-abc123] - Stack trace (first 10 lines):
[Enhanced Analysis analysis-1733230800000-abc123]   1. at analyzeWithFallback (...)
[Enhanced Analysis analysis-1733230800000-abc123]   ... (full stack trace)
[Enhanced Analysis analysis-1733230800000-abc123] - Full Error Log:
[Enhanced Analysis analysis-1733230800000-abc123]   Attempt 1: Timeout (5600ms)
[Enhanced Analysis analysis-1733230800000-abc123]   Attempt 2: Rate limit (6200ms)
[Enhanced Analysis analysis-1733230800000-abc123]   Attempt 3: Rate limit (6656ms)
[Enhanced Analysis analysis-1733230800000-abc123] ============================================
```

### API Key Manager Logs

#### Successful Key Retrieval
```
[ApiKeyManager] [req-1733230800000-1] ============================================
[ApiKeyManager] [req-1733230800000-1] ✅ API KEY RETRIEVED
[ApiKeyManager] [req-1733230800000-1] - Key Index: 3/5
[ApiKeyManager] [req-1733230800000-1] - Key ID: a1b2c3d4...
[ApiKeyManager] [req-1733230800000-1] - Key Name: Production Key 3
[ApiKeyManager] [req-1733230800000-1] - Total Uses: 127
[ApiKeyManager] [req-1733230800000-1] - Retrieval Time: 12ms
[ApiKeyManager] [req-1733230800000-1] - Operation: contact-analysis
[ApiKeyManager] [req-1733230800000-1] - Contact ID: cont_abc123...
[ApiKeyManager] [req-1733230800000-1] - 🔄 Parallel Requests: 8 concurrent
[ApiKeyManager] [req-1733230800000-1] ============================================
```

#### Key Retrieval Failure
```
[ApiKeyManager] [req-1733230800000-2] ============================================
[ApiKeyManager] [req-1733230800000-2] ❌ ERROR GETTING API KEY
[ApiKeyManager] [req-1733230800000-2] - Duration: 45ms
[ApiKeyManager] [req-1733230800000-2] - Error: No active keys available
[ApiKeyManager] [req-1733230800000-2] - Active Keys: 0
[ApiKeyManager] [req-1733230800000-2] - Last Cache Refresh: 2025-12-03T10:30:00.000Z
[ApiKeyManager] [req-1733230800000-2] - Stack trace (first 3 lines):
[ApiKeyManager] [req-1733230800000-2]   1. at getNextKey (api-key-manager.ts:95)
[ApiKeyManager] [req-1733230800000-2]   2. at analyzeWithFallback (...)
[ApiKeyManager] [req-1733230800000-2]   3. at POST (route.ts:67)
[ApiKeyManager] [req-1733230800000-2] ============================================
```

### Database Connection Logs

#### Successful Connection
```
[Prisma] [conn-1733230800000] Attempting database connection (maxRetries: 3)
[Prisma] [conn-1733230800000] Attempt 1/3 - Connecting...
[Prisma] [conn-1733230800000] ✅ Connected successfully in 245ms
```

#### Connection Retry
```
[Prisma] [conn-1733230800000] ============================================
[Prisma] [conn-1733230800000] ❌ CONNECTION ATTEMPT 1/3 FAILED
[Prisma] [conn-1733230800000] - Duration: 3456ms
[Prisma] [conn-1733230800000] - Error Code: P2024
[Prisma] [conn-1733230800000] - Error Message: Connection pool timeout
[Prisma] [conn-1733230800000] - Is Connection Error: true
[Prisma] [conn-1733230800000] - Connection State: idle
[Prisma] [conn-1733230800000] - Will retry in 1000ms...
[Prisma] [conn-1733230800000] ============================================
```

#### Connection Recovered
```
[Prisma] [conn-1733230800000] ============================================
[Prisma] [conn-1733230800000] ✅ CONNECTED AFTER 2 ATTEMPT(S)
[Prisma] [conn-1733230800000] - Duration: 567ms
[Prisma] [conn-1733230800000] - Connection State: connected
[Prisma] [conn-1733230800000] ============================================
```

### Batch Analysis Logs

#### Starting Batch
```
[API analyze-1733230800000-xyz] ============================================
[API analyze-1733230800000-xyz] STARTING BATCH ANALYSIS
[API analyze-1733230800000-xyz] - Organization: org_12345
[API analyze-1733230800000-xyz] - Limit: 100
[API analyze-1733230800000-xyz] - Skip if has context: true
[API analyze-1733230800000-xyz] - User ID: user_67890
[API analyze-1733230800000-xyz] ============================================
```

#### Batch Complete
```
[API analyze-1733230800000-xyz] ============================================
[API analyze-1733230800000-xyz] ✅ BATCH ANALYSIS COMPLETE
[API analyze-1733230800000-xyz] - Duration: 45678ms
[API analyze-1733230800000-xyz] - Contacts Processed: 100
[API analyze-1733230800000-xyz] - Success: 95
[API analyze-1733230800000-xyz] - Failed: 5
[API analyze-1733230800000-xyz] - Success Rate: 95%
[API analyze-1733230800000-xyz] - Avg Time/Contact: 456ms
[API analyze-1733230800000-xyz] - Peak Memory: 512.34MB
[API analyze-1733230800000-xyz] - Errors Encountered: 5
[API analyze-1733230800000-xyz]   1. Contact cont_001: Timeout after 30s
[API analyze-1733230800000-xyz]   2. Contact cont_042: API rate limit
[API analyze-1733230800000-xyz]   3. Contact cont_078: Invalid message format
[API analyze-1733230800000-xyz]   ... and 2 more errors
[API analyze-1733230800000-xyz] ============================================
```

#### Batch Failed
```
[API analyze-1733230800000-xyz] ============================================
[API analyze-1733230800000-xyz] ❌ BATCH ANALYSIS FAILED
[API analyze-1733230800000-xyz] - Duration: 12345ms
[API analyze-1733230800000-xyz] - Contacts Processed: 15
[API analyze-1733230800000-xyz] - Error: Database connection lost
[API analyze-1733230800000-xyz] - Error Type: PrismaClientKnownRequestError
[API analyze-1733230800000-xyz] - Is Timeout: false
[API analyze-1733230800000-xyz] - Is Rate Limit: false
[API analyze-1733230800000-xyz] - Is Auth Error: false
[API analyze-1733230800000-xyz] - Is Memory Error: false
[API analyze-1733230800000-xyz] - Current Memory: 678.90MB
[API analyze-1733230800000-xyz] ============================================
```

---

## 🔍 How to Debug Production Issues

### 1. Find the Request ID

When a user reports an issue, get the timestamp and look for logs around that time:

```bash
# Search by approximate time
grep "2025-12-03T10:30" /var/log/app.log

# Or search by operation type
grep "Enhanced Analysis" /var/log/app.log
```

### 2. Track the Entire Flow

Use the request ID to follow the operation through all systems:

```bash
# Find all logs for a specific request
grep "analysis-1733230800000-abc123" /var/log/app.log

# This will show you:
# - Analysis start with parameters
# - API key retrieval
# - AI service calls
# - Retry attempts
# - Final result or errors
```

### 3. Analyze Error Patterns

Look for common failure patterns:

```bash
# Find all timeout errors
grep "❌.*Timeout" /var/log/app.log

# Find all rate limit errors
grep "rate limit" /var/log/app.log

# Find all memory issues
grep "memory" /var/log/app.log
```

### 4. Check Memory Usage

Monitor memory trends:

```bash
# Extract memory usage over time
grep "Peak Memory" /var/log/app.log | awk '{print $NF}'

# Find high memory operations
grep "Peak Memory.*[5-9][0-9][0-9]\." /var/log/app.log
```

---

## 📈 Monitoring Queries

### For Datadog / New Relic / CloudWatch

#### Success Rate
```
Filter: "BATCH ANALYSIS COMPLETE"
Metric: count(success) / count(total) * 100
Group by: hour
```

#### Average Duration
```
Filter: "Duration:"
Extract: duration_ms
Metric: avg(duration_ms)
Group by: operation_type
```

#### Error Frequency
```
Filter: "❌"
Metric: count()
Group by: error_type
```

#### Memory Usage Trend
```
Filter: "Peak Memory"
Extract: memory_mb
Metric: max(memory_mb), p95(memory_mb)
Group by: 5min intervals
```

---

## 🚨 Alert Triggers

### Critical Alerts

1. **All API Keys Exhausted**
   ```
   Pattern: "🚫 All API keys are rate-limited"
   Action: Add more API keys or increase rate limits
   ```

2. **Database Connection Failure**
   ```
   Pattern: "❌ All 3 connection attempts failed"
   Action: Check database health, connection pool settings
   ```

3. **High Memory Usage**
   ```
   Pattern: "Peak Memory.*[7-9][0-9][0-9]\\."
   Threshold: >700MB
   Action: Reduce batch size, investigate memory leaks
   ```

### Warning Alerts

1. **High Fallback Usage**
   ```
   Pattern: "USING FALLBACK"
   Threshold: >20% of requests
   Action: Investigate AI service reliability
   ```

2. **Slow Analysis**
   ```
   Pattern: "Duration: [0-9]{5,}"
   Threshold: >10000ms
   Action: Check API response times, optimize message processing
   ```

3. **Connection Retries**
   ```
   Pattern: "CONNECTION ATTEMPT [2-3]/3"
   Threshold: >10% of connections
   Action: Check database load, pool configuration
   ```

---

## 💡 Best Practices

### 1. **Correlation**
Always search by request ID to see the full context:
```bash
grep "req-1733230800000-1" logs/ -r
```

### 2. **Time Windows**
Use timestamps to isolate issues:
```bash
grep "2025-12-03T10:3[0-9]" logs/
```

### 3. **Error Categorization**
Group errors by type:
- Timeout errors → API performance issue
- Rate limit errors → Need more API keys
- Memory errors → Batch size too large
- Auth errors → API key expired/invalid

### 4. **Trend Analysis**
Look for patterns over time:
```bash
# Count errors per hour
grep "❌" logs/ | awk '{print $1 " " $2}' | cut -d: -f1 | sort | uniq -c
```

---

## 🔧 Quick Troubleshooting

### Issue: Analysis Taking Too Long

**Look for:**
```
[Enhanced Analysis xxx] - Duration: [large number]
```

**Check:**
1. Message count (should be <500)
2. Retry attempts (should be 1-2 max)
3. Memory usage
4. API response times

### Issue: High Failure Rate

**Look for:**
```
[API xxx] - Failed: [high number]
[API xxx] - Success Rate: [low %]
```

**Check:**
1. Error types in error log
2. API key status
3. Database connectivity
4. Memory availability

### Issue: Intermittent Errors

**Look for:**
```
[ApiKeyManager] - 🔄 Parallel Requests: [high number]
```

**Check:**
1. Concurrent request load
2. Connection pool size
3. API rate limits
4. Resource contention

---

## 📞 Support

If logs don't provide enough information:

1. **Enable Development Mode** (temporary):
   ```env
   NODE_ENV=development
   ```
   This adds stack traces to API responses.

2. **Increase Log Detail**: All logs are already comprehensive, but check:
   - Memory snapshots
   - Full error logs
   - Request correlation

3. **Check Health Endpoint**:
   ```
   GET /api/health
   ```
   Provides real-time system status.

---

## ✅ Log Quality Checklist

- [x] Unique request IDs for tracing
- [x] Structured format with boxes
- [x] Duration tracking
- [x] Memory usage monitoring
- [x] Error categorization
- [x] Stack traces (limited lines)
- [x] Context information
- [x] Success/failure indicators
- [x] Retry attempt tracking
- [x] Correlation across systems

---

**Last Updated**: December 3, 2025
**Version**: 1.2.0
**Coverage**: AI Analysis, API Keys, Database, Batch Operations

