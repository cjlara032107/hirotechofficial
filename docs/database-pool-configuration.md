# Database Connection Pool Configuration

## Overview

This document describes the database connection pool configuration and monitoring implemented in HIRO V1.2 to prevent pool exhaustion errors (P2024) and optimize performance under load.

## Configuration Changes

### Connection Limits (Increased)

**Single Database Mode** (`src/lib/db.ts`):
- **Vercel/Serverless**: Increased from 10 to **20 connections**
- **Traditional Server**: Increased from 15 to **30 connections**

**Multi-Database Mode** (`src/lib/db/multi-db-router.ts`):
- **Vercel/Serverless**: **20 connections per database**
- **Traditional Server**: **30 connections per database**

### Timeout Settings

- **Pool Timeout**: 
  - Vercel: 60 seconds
  - Traditional: 90 seconds
- **Connect Timeout**: 
  - Vercel: 60 seconds
  - Traditional: 30 seconds

### Why These Values?

1. **Vercel/Serverless Considerations**:
   - Lambda functions can scale to multiple instances quickly
   - Each instance needs adequate connections
   - Cold starts require longer timeouts
   - 20 connections per instance is a balance between availability and resource usage

2. **Traditional Server**:
   - Single long-running process
   - Higher connection limit (30) for handling concurrent requests
   - Longer pool timeout (90s) for better queue handling

3. **Supabase Pooler**:
   - Using pgBouncer transaction mode pooler URLs
   - Pooler handles connection multiplexing efficiently
   - These limits are per-client, not global

## Enhanced Logging

All database operations now use `[DB Pool]` prefix for easy filtering and monitoring.

### Initialization Logs

```
[DB Pool] 🔧 Single-DB mode initialized
  - Environment: Vercel/serverless
  - Host: db.xxxxx.supabase.co
  - connection_limit: 20
  - pool_timeout: 60s
  - connect_timeout: 60s
```

### Connection Success

```
[DB Pool] [conn-1234567890] ✅ Connected successfully in 234ms
```

### Connection Failures

```
[DB Pool] [conn-1234567890] ============================================
[DB Pool] [conn-1234567890] ❌ CONNECTION ATTEMPT 1/3 FAILED
  - Duration: 5234ms
  - Host: db.xxxxx.supabase.co
  - Error Code: P2024
  - Error Type: Pool Exhaustion
  - Error Message: Connection pool timeout
  - Connection State: connecting
  - Connection Limit: 20
[DB Pool] [conn-1234567890]   - Will retry in 1000ms...
[DB Pool] [conn-1234567890] ============================================
```

### Multi-Database Context

When using multi-DB mode, all logs include the database index:

```
[DB Pool] ✅ Initialized database 1/3
  - DB index: 0
  - Host: db-primary.xxxxx.supabase.co
  - Connection limit: 20
```

```
[DB Pool] ⚠️ Health check failed
  - DB index: 1
  - Host: db-secondary.xxxxx.supabase.co
  - Error code: P2024
  - Error: Connection pool timeout
  - Status: degraded (still usable)
  - Will retry on next health check
```

## Pool Usage Monitoring

### Automatic Tracking

The system now tracks pool usage metrics:

```typescript
interface PoolUsageMetrics {
  failureCount: number;        // Failures in the alert window
  lastFailureTime: number;     // Timestamp of last failure
  consecutiveTimeouts: number; // Consecutive timeout errors
  p2024Count: number;          // Pool exhaustion errors
  lastAlertTime: number;       // Last alert sent
}
```

### Alert Thresholds

- **Failure Threshold**: 5 failures within 5 minutes triggers an alert
- **Alert Window**: 5 minutes (300 seconds)
- **Alert Cooldown**: 10 minutes (prevents alert spam)
- **High Usage Warning**: 80% estimated pool usage

### Alert Logs

```
[DB Pool] ⚠️ High pool usage detected:
  - Estimated usage: ~85%
  - Failures in window: 6
  - P2024 errors: 4
  - Consecutive timeouts: 3
  - Connection limit: 20
```

```
[DB Pool] 🚨 ALERT: Pool exhaustion threshold exceeded
  - Failures in last 300s: 7
  - P2024 errors: 5
  - Connection limit: 20
  - Recommended: Check connection pooling config and Supabase pooler URLs
```

## Best Practices

### 1. Use Supabase Pooler URLs

**Always use pgBouncer pooler URLs** (Transaction mode):

```env
# ✅ CORRECT - Pooler URL
DATABASE_URL="postgresql://postgres:[PASSWORD]@[PROJECT_REF].pooler.supabase.com:6543/postgres?pgbouncer=true"

# ❌ AVOID - Direct URL (only for migrations)
DATABASE_URL="postgresql://postgres:[PASSWORD]@[PROJECT_REF].supabase.co:5432/postgres"
```

### 2. Monitor Logs

Filter logs by `[DB Pool]` prefix to monitor:
- Connection failures
- Pool exhaustion errors (P2024)
- High usage warnings
- Health check status (multi-DB mode)

### 3. Adjust Limits Based on Load

If you still see P2024 errors after these changes:

1. **Check Supabase Connection Limit**:
   - Free tier: 60 connections total
   - Pro tier: 200 connections total
   - Team/Enterprise: Higher limits

2. **Reduce Limits if Hitting Supabase Cap**:
   ```typescript
   // If you have 10 Vercel instances and 60 connection limit:
   // 60 / 10 = 6 connections per instance
   const connectionLimit = isVercel ? 5 : 10;
   ```

3. **Upgrade Supabase Plan**:
   - More connections available
   - Better performance
   - Dedicated resources

### 4. Multi-Database Configuration

When using multiple databases, connection limits are **per database**:

```env
ENABLE_MULTI_DB=true
DATABASE_URL_0="postgresql://...pooler.supabase.com..."
DATABASE_URL_1="postgresql://...pooler.supabase.com..."
```

With 2 databases and 20 connections each:
- Total: 40 connections per Vercel instance
- Ensure Supabase plan supports this

### 5. Cold Start Considerations

On Vercel/serverless:
- First request after cold start may be slower
- Connection pooling initializes lazily
- Health checks run after 5-second delay
- Timeouts are set higher to accommodate cold starts

## Troubleshooting

### Still Seeing P2024 Errors?

1. **Check Total Connection Usage**:
   ```sql
   -- Run in Supabase SQL Editor
   SELECT count(*) FROM pg_stat_activity;
   ```

2. **Review Vercel Function Concurrency**:
   - Each Vercel function instance uses the configured limit
   - High traffic = many instances = many connections
   - Consider connection limit = total_limit / max_expected_instances

3. **Check for Connection Leaks**:
   - Ensure `await prisma.$disconnect()` in cleanup
   - Review long-running queries
   - Check for stuck transactions

4. **Enable Debug Logging**:
   ```typescript
   // Temporarily in src/lib/db.ts
   log: ['query', 'info', 'warn', 'error']
   ```

### High Pool Usage Warnings

If you see frequent 80% usage warnings:
- Increase connection limits further
- Optimize query performance
- Review concurrent request patterns
- Consider read replicas (multi-DB mode)

### Multi-DB Health Check Failures

If databases are marked as "degraded":
- Check network connectivity
- Verify DATABASE_URL_* format
- Ensure pooler URLs are used
- Review Supabase status page

## Performance Metrics

Track these metrics over time:
- Average connection time
- P2024 error rate
- Pool exhaustion alerts
- Health check success rate (multi-DB)
- Query duration (logged automatically)

## Environment Variables Reference

```env
# Required
DATABASE_URL="postgresql://...pooler.supabase.com..."

# Optional - Multi-DB
ENABLE_MULTI_DB=true
DATABASE_URL_0="postgresql://..."
DATABASE_URL_1="postgresql://..."
DB_ROUTING_STRATEGY="hash"  # or "round-robin" or "load-aware"

# Optional - Vercel detection (auto-set by Vercel)
VERCEL=1
NEXT_PUBLIC_VERCEL_ENV=production

# Optional - Development
NODE_ENV=development
```

## Summary of Changes

### src/lib/db.ts
- ✅ Increased connection limits (20 Vercel / 30 local)
- ✅ Added `[DB Pool]` logging with host context
- ✅ Implemented pool usage tracking
- ✅ Added automatic alerting for pool exhaustion
- ✅ Enhanced error logging with connection context

### src/lib/db/multi-db-router.ts
- ✅ Already had 20/30 connection limits
- ✅ Added `[DB Pool]` logging with dbIndex and host
- ✅ Enhanced health check logging
- ✅ Improved connection test logging
- ✅ Added detailed error context

## Next Steps

1. Deploy changes to Vercel
2. Monitor logs for `[DB Pool]` entries
3. Watch for P2024 errors and pool usage warnings
4. Adjust limits if needed based on actual usage
5. Set up log aggregation/alerting for production monitoring

## Support

If you continue to experience pool exhaustion:
1. Review logs for patterns (peak times, specific endpoints)
2. Check Supabase connection pool limits
3. Consider upgrading Supabase plan
4. Optimize query patterns and reduce connection hold time
5. Implement request queuing/throttling at application level

