# 🎯 Production Logging - Quick Reference Card

## Search Commands

### By Request ID
```bash
# AI Analysis
grep "analysis-[0-9]*" /var/log/app.log

# API Key Manager  
grep "req-[0-9]*" /var/log/app.log

# Database Connection
grep "conn-[0-9]*" /var/log/app.log

# Batch Operations
grep "analyze-[0-9]*" /var/log/app.log
```

### By Status
```bash
# All successes
grep "✅" /var/log/app.log

# All failures
grep "❌" /var/log/app.log

# All warnings
grep "⚠️" /var/log/app.log
```

### By Operation Type
```bash
# AI Analysis
grep "Enhanced Analysis" /var/log/app.log

# API Key Operations
grep "ApiKeyManager" /var/log/app.log

# Database Operations
grep "Prisma" /var/log/app.log

# Batch Analysis
grep "BATCH ANALYSIS" /var/log/app.log
```

### By Error Type
```bash
# Timeouts
grep "Timeout" /var/log/app.log

# Rate Limits
grep "rate limit" /var/log/app.log

# Memory Issues
grep "memory\|heap" /var/log/app.log -i

# Database Errors
grep "Connection.*failed\|P[0-9]" /var/log/app.log
```

---

## Log Patterns

### AI Analysis Start
```
[Enhanced Analysis analysis-XXX] ============================================
[Enhanced Analysis analysis-XXX] Starting analysis
[Enhanced Analysis analysis-XXX] - Messages: 150
[Enhanced Analysis analysis-XXX] - Pipeline stages: 5
```

### AI Analysis Success
```
[Enhanced Analysis analysis-XXX] ✅ AI ANALYSIS SUCCESS
[Enhanced Analysis analysis-XXX] - Duration: 1234ms
[Enhanced Analysis analysis-XXX] - Lead Score: 85/100
```

### AI Analysis Failed with Fallback
```
[Enhanced Analysis analysis-XXX] ❌ ALL 3 AI ATTEMPTS FAILED - USING FALLBACK
[Enhanced Analysis analysis-XXX] - Total Duration: 18456ms
[Enhanced Analysis analysis-XXX] - Full Error Log:
[Enhanced Analysis analysis-XXX]   Attempt 1: Timeout (5600ms)
```

### API Key Retrieved
```
[ApiKeyManager] [req-XXX] ✅ API KEY RETRIEVED
[ApiKeyManager] [req-XXX] - Key Index: 3/5
[ApiKeyManager] [req-XXX] - Total Uses: 127
[ApiKeyManager] [req-XXX] - 🔄 Parallel Requests: 8 concurrent
```

### Database Connection
```
[Prisma] [conn-XXX] ✅ Connected successfully in 245ms
```

### Batch Analysis Complete
```
[API analyze-XXX] ✅ BATCH ANALYSIS COMPLETE
[API analyze-XXX] - Duration: 45678ms
[API analyze-XXX] - Success Rate: 95%
[API analyze-XXX] - Peak Memory: 512.34MB
```

---

## Common Issues

### Issue: High Timeout Rate
**Search:**
```bash
grep "Timeout" /var/log/app.log | wc -l
```
**Fix:** Increase timeout limit or optimize AI service

### Issue: All Keys Rate Limited
**Search:**
```bash
grep "🚫 All API keys are rate-limited" /var/log/app.log
```
**Fix:** Add more API keys or wait for reset

### Issue: Database Connection Failures
**Search:**
```bash
grep "❌ CONNECTION ATTEMPT.*FAILED" /var/log/app.log
```
**Fix:** Check database health and pool settings

### Issue: High Memory Usage
**Search:**
```bash
grep "Peak Memory" /var/log/app.log | sort -t: -k5 -n | tail -10
```
**Fix:** Reduce batch size or investigate leaks

---

## Metrics Extraction

### Success Rate
```bash
grep "Success Rate:" /var/log/app.log | awk '{print $NF}'
```

### Average Duration
```bash
grep "Avg Time/Contact:" /var/log/app.log | awk '{print $NF}'
```

### Memory Peaks
```bash
grep "Peak Memory:" /var/log/app.log | awk '{print $NF}' | sort -n | tail -10
```

### Concurrent Requests
```bash
grep "Parallel Requests:" /var/log/app.log | awk '{print $NF}' | sort -n | tail -10
```

---

## Request Correlation

### Follow a Single Request
```bash
# Get request ID from initial log
REQUEST_ID=$(grep "Starting analysis" /var/log/app.log | tail -1 | grep -oP 'analysis-[^]]+')

# See all logs for that request
grep "$REQUEST_ID" /var/log/app.log
```

### Trace User Operation
```bash
# Find by user ID
USER_ID="user_67890"
grep "$USER_ID" /var/log/app.log

# Get all related request IDs
grep "$USER_ID" /var/log/app.log | grep -oP '(analysis|analyze)-[0-9]+-[a-z0-9]+'
```

---

## Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Success Rate | <90% | <75% |
| Avg Duration | >5000ms | >10000ms |
| Memory Usage | >600MB | >700MB |
| Timeout Rate | >10% | >25% |
| Rate Limit Hits | >5/hour | >20/hour |
| Connection Failures | >5% | >15% |

---

## Emergency Response

### 1. Check System Health
```bash
# Overall error count
grep "❌" /var/log/app.log | tail -100

# Recent critical errors
grep "CRITICAL\|FATAL\|FAILED" /var/log/app.log | tail -20
```

### 2. Check Current State
```bash
# Active operations (last 5 minutes)
grep "Starting\|STARTING" /var/log/app.log | tail -50

# Recent completions
grep "COMPLETE\|SUCCESS" /var/log/app.log | tail -50
```

### 3. Check Resources
```bash
# Memory trend
grep "Peak Memory" /var/log/app.log | tail -20

# Concurrent load
grep "Parallel Requests" /var/log/app.log | tail -20
```

---

## Useful One-Liners

```bash
# Error rate by hour
grep "❌" /var/log/app.log | awk '{print $2}' | cut -d: -f1 | sort | uniq -c

# Top error messages
grep "Error:" /var/log/app.log | awk -F'Error: ' '{print $2}' | sort | uniq -c | sort -rn | head -10

# Slowest operations
grep "Duration:" /var/log/app.log | awk '{print $NF}' | sort -n | tail -10

# Memory consumption trend
grep "Peak Memory" /var/log/app.log | awk '{print $2, $NF}' | tail -50

# API key usage distribution
grep "Key Index:" /var/log/app.log | awk '{print $NF}' | sort | uniq -c

# Success vs failure count
echo "Success: $(grep -c '✅' /var/log/app.log)"
echo "Failure: $(grep -c '❌' /var/log/app.log)"
```

---

## Production Monitoring

### Datadog Query Examples
```
# Error rate
source:app status:error | count by service

# P95 duration
source:app @duration:>* | percentile(duration, 95)

# Memory spikes
source:app @memory:>600 | max(memory) by host

# Rate limit events
source:app "rate limit" | count
```

### CloudWatch Insights
```javascript
fields @timestamp, @message
| filter @message like /❌/
| sort @timestamp desc
| limit 100
```

---

**Last Updated**: December 3, 2025
**Print and Keep Handy** 📌

