# Performance Considerations

This document outlines the performance optimizations, bottlenecks, and best practices for the HIRO messaging platform.

## Table of Contents

1. [Database Performance](#database-performance)
2. [API Performance](#api-performance)
3. [Caching Strategies](#caching-strategies)
4. [Frontend Performance](#frontend-performance)
5. [Background Jobs & Workers](#background-jobs--workers)
6. [Rate Limiting](#rate-limiting)
7. [Connection Pooling](#connection-pooling)
8. [Query Optimization](#query-optimization)
9. [Memory Management](#memory-management)
10. [Monitoring & Metrics](#monitoring--metrics)

---

## Database Performance

### Connection Pooling

**Configuration:**
- **Serverless (Vercel)**: `connection_limit=10` per instance
- **Traditional Server**: `connection_limit=15` per instance
- **Pool Timeout**: 90 seconds
- **Connect Timeout**: 30 seconds
- **Statement Cache**: Disabled (reduces memory usage)

**Rationale:**
- Serverless functions are short-lived and benefit from lower connection limits
- Each operation typically needs 2-3 connections
- Pooler handles connection distribution across instances
- Prevents connection exhaustion under high concurrency

**Location:** `src/lib/db.ts`

### Database Indexes

**Critical Indexes:**
```sql
-- Contact lookups
CREATE INDEX idx_contact_org ON "Contact"(organizationId);
CREATE INDEX idx_contact_messenger ON "Contact"(messengerPSID, facebookPageId);
CREATE INDEX idx_contact_instagram ON "Contact"(instagramSID);
CREATE INDEX idx_contact_pipeline ON "Contact"(pipelineId, stageId);

-- Pipeline queries
CREATE INDEX idx_pipeline_org ON "Pipeline"(organizationId);
CREATE INDEX idx_stage_pipeline ON "PipelineStage"(pipelineId);

-- Campaign filtering
CREATE INDEX idx_campaign_status ON "Campaign"(status, platform);
CREATE INDEX idx_campaign_org ON "Campaign"(organizationId);

-- Conversation sorting
CREATE INDEX idx_conversation_status ON "Conversation"(status, platform);
CREATE INDEX idx_conversation_last_message ON "Conversation"(lastMessageAt);

-- Team queries
CREATE INDEX idx_team_member_user ON "TeamMember"(userId, teamId);
CREATE INDEX idx_team_org ON "Team"(organizationId);
```

**Performance Impact:**
- Reduces query time from O(n) to O(log n) for filtered queries
- Enables efficient pagination and sorting
- Critical for large datasets (10,000+ contacts)

### Query Optimization

**Best Practices:**
1. **Use `select` to limit fields**: Only fetch required fields
2. **Pagination**: Always use `skip` and `take` for large datasets
3. **Avoid N+1 queries**: Use `include` strategically, prefer `select` for counts
4. **Batch operations**: Use `createMany`, `updateMany` for bulk operations

**Example:**
```typescript
// ❌ Bad: Fetches all fields and all relations
const contacts = await prisma.contact.findMany({
  where: { organizationId },
  include: { tags: true, pipeline: true, stage: true }
});

// ✅ Good: Selects only needed fields with pagination
const contacts = await prisma.contact.findMany({
  where: { organizationId },
  select: {
    id: true,
    firstName: true,
    lastName: true,
    _count: { select: { tags: true } }
  },
  skip: (page - 1) * limit,
  take: limit
});
```

---

## API Performance

### Request Validation

**Body Size Limits:**
- **SMALL**: 10 KB (simple requests)
- **MEDIUM**: 100 KB (standard requests)
- **LARGE**: 1 MB (file uploads, bulk operations)
- **XLARGE**: 10 MB (large file uploads)

**Location:** `src/lib/api/validate-body-size.ts`

**Impact:**
- Prevents memory exhaustion from oversized requests
- Reduces processing time for invalid requests
- Protects against DoS attacks

### Response Time Targets

| Endpoint Type | Target | Warning Threshold |
|--------------|--------|-------------------|
| Simple CRUD | < 200ms | > 500ms |
| List/Query | < 500ms | > 1000ms |
| Bulk Operations | < 2000ms | > 5000ms |
| AI Processing | < 5000ms | > 10000ms |
| Background Jobs | N/A | N/A |

### Slow Query Detection

**Configuration:**
- Development: Logs queries > 2000ms
- Production: Monitored via system monitor

**Location:** `src/lib/db.ts` (query event handler)

---

## Caching Strategies

### Message Cache

**Purpose:** Cache conversation messages to reduce database load

**Configuration:**
- **Chunk Size**: 50 messages per chunk
- **Max Messages**: 200 messages per conversation (initial load)
- **TTL**: 5 minutes (300 seconds)
- **Max Cache Size**: 1000 entries (auto-cleanup)

**Cache Key:** SHA256 hash of `conversationIds:chunkIndex:cursor`

**Location:** `src/lib/cache/message-cache.ts`

**Use Cases:**
- Conversation message lists
- Message pagination
- Real-time message updates

**Invalidation:**
- Automatic expiration after TTL
- Manual invalidation on message updates
- Cache cleared on conversation updates

### Pipeline Cache

**Purpose:** Cache pipeline and stage data using React `cache()`

**Configuration:**
- Request-scoped memoization (React Server Components)
- No TTL (cleared on next request)

**Location:** `src/lib/cache/pipeline-cache.ts`

**Use Cases:**
- Pipeline lists
- Stage data
- Contact counts per stage

**Limitations:**
- Request-scoped only (not shared across requests)
- For production, consider Redis for cross-request caching

### Conversation Cache

**Purpose:** Cache AI conversation analysis results

**Configuration:**
- TTL: 1 hour
- Key: Conversation ID + analysis type

**Location:** `src/lib/ai/conversation-cache.ts`

---

## Frontend Performance

### Code Splitting

**Strategy:**
- Automatic code splitting via Next.js App Router
- Dynamic imports for heavy components
- Route-based splitting

**Example:**
```typescript
// Dynamic import for heavy components
const HeavyComponent = dynamic(() => import('./HeavyComponent'), {
  loading: () => <Skeleton />,
  ssr: false // If not needed for SEO
});
```

### Virtualization

**Components:**
- `@tanstack/react-virtual` for long lists
- Virtualized pipeline stage cards
- Virtualized contact tables

**Location:** `src/components/pipelines/pipeline-stage-card-virtualized.tsx`

**Impact:**
- Renders only visible items
- Reduces initial render time for 1000+ items
- Improves scroll performance

### Image Optimization

**Configuration:**
- Next.js Image component with automatic optimization
- WebP format preferred
- Lazy loading enabled
- Size constraints enforced

### React Query Caching

**Configuration:**
- Default stale time: 30 seconds
- Cache time: 5 minutes
- Automatic background refetching

**Location:** `src/components/providers/query-provider.tsx`

---

## Background Jobs & Workers

### Campaign Worker

**Purpose:** Process campaign messages asynchronously

**Technology:** BullMQ with Redis

**Performance:**
- Concurrent job processing
- Rate limiting per campaign
- Retry logic for failed messages
- Job prioritization

**Rate Limiting:**
- Configurable per campaign (default: 3600 messages/hour)
- Prevents Facebook API rate limit violations
- Respects message tag restrictions

**Location:** `src/lib/campaigns/send.ts`

### Sync Jobs

**Purpose:** Background Facebook contact synchronization

**Performance:**
- Batch processing (50-100 contacts per batch)
- Incremental sync (only new/updated contacts)
- Parallel processing for multiple pages
- Job cancellation support

**Location:** `src/lib/facebook/instant-sync.ts`

**Optimization:**
- Deduplication of sync requests
- Lock mechanism to prevent concurrent syncs
- Status tracking for progress monitoring

### AI Analysis Jobs

**Purpose:** Background AI processing for contact analysis

**Performance:**
- Dynamic concurrency based on resource availability
- Batch processing for efficiency
- Resource monitoring to prevent overload
- API key rotation for rate limit management

**Location:** `src/lib/ai/dynamic-concurrency.ts`

---

## Rate Limiting

### API Rate Limits

**Presets:**
- **Strict**: 10 requests/minute (sensitive operations)
- **Standard**: 100 requests/minute (default)
- **Generous**: 1000 requests/minute (read-heavy endpoints)
- **Auth**: 5 requests/minute (authentication endpoints)
- **File Upload**: 10 requests/minute

**Implementation:**
- In-memory store (development)
- Redis recommended for production (distributed)
- IP-based + pathname key generation
- Automatic cleanup of expired entries

**Location:** `src/lib/api/rate-limit.ts`

### Facebook API Rate Limits

**Constraints:**
- Messenger API: 200 requests/second per page
- Graph API: 200 requests/hour per user (default)
- Webhook delivery: Unlimited (but should be processed quickly)

**Mitigation:**
- Campaign rate limiting (configurable per campaign)
- Request queuing via BullMQ
- Exponential backoff on rate limit errors
- API key rotation for AI services

---

## Connection Pooling

### Database Connection Pool

**Configuration:**
- Managed via Prisma Client
- Connection reuse across requests
- Automatic connection lifecycle management
- Retry logic for transient failures

**Connection States:**
- `idle`: No active connection
- `connecting`: Establishing connection
- `connected`: Ready for queries

**Retry Logic:**
- Max retries: 3
- Exponential backoff: 1s, 2s, 4s
- Handles P1001 (connection) and P2024 (pool exhaustion) errors

**Location:** `src/lib/db.ts`

### Redis Connection

**Purpose:** BullMQ job queue and caching

**Configuration:**
- Connection pooling via ioredis
- Automatic reconnection on failure
- Connection timeout: 10 seconds

---

## Query Optimization

### Pagination

**Standard Pattern:**
```typescript
const page = parseInt(searchParams.get('page') || '1');
const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
const skip = (page - 1) * limit;

const results = await prisma.model.findMany({
  skip,
  take: limit,
  orderBy: { createdAt: 'desc' }
});
```

**Cursor-based Pagination:**
- Used for real-time feeds
- More efficient for large datasets
- Prevents duplicate results on concurrent updates

### Batch Operations

**Best Practices:**
- Use `createMany` for bulk inserts (up to 1000 records)
- Use transactions for multi-step operations
- Batch updates with `updateMany` where possible

**Example:**
```typescript
// ✅ Good: Batch insert
await prisma.contact.createMany({
  data: contacts,
  skipDuplicates: true
});

// ❌ Bad: Individual inserts
for (const contact of contacts) {
  await prisma.contact.create({ data: contact });
}
```

### Selective Field Fetching

**Use `select` instead of `include` when possible:**
```typescript
// ✅ Good: Only fetch needed fields
const contacts = await prisma.contact.findMany({
  select: {
    id: true,
    firstName: true,
    _count: { select: { tags: true } }
  }
});

// ❌ Bad: Fetches all fields and relations
const contacts = await prisma.contact.findMany({
  include: { tags: true, pipeline: true }
});
```

---

## Memory Management

### Garbage Collection Optimization

**Purpose:** Optimize memory usage for long-running processes

**Configuration:**
- Automatic GC tuning based on heap size
- Memory threshold monitoring
- Forced GC on high memory usage

**Location:** `src/lib/utils/gc-optimizer.ts`

### Cache Size Limits

**Message Cache:**
- Max entries: 1000
- Auto-cleanup on size limit
- TTL-based expiration

**Conversation Cache:**
- Size-based eviction
- LRU (Least Recently Used) strategy

### Resource Monitoring

**Purpose:** Monitor AI processing resources

**Metrics:**
- API key usage
- Request rate
- Error rates
- Response times

**Location:** `src/lib/ai/resource-monitor.ts`

---

## Monitoring & Metrics

### System Monitor

**Purpose:** Track system performance metrics

**Metrics Collected:**
- Database query performance
- API response times
- Error rates
- Resource usage

**Location:** `src/lib/monitoring/system-monitor.ts`

### Database Query Tracking

**Events Tracked:**
- Query duration
- Model and action type
- Slow query warnings (> 2000ms in development)
- Connection pool status

**Location:** `src/lib/db.ts` (query event handler)

### Performance Targets

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| API Response Time | < 500ms | > 1000ms | > 5000ms |
| Database Query | < 200ms | > 500ms | > 2000ms |
| Page Load (First Contentful Paint) | < 1.5s | > 3s | > 5s |
| Time to Interactive | < 3s | > 5s | > 10s |

---

## Best Practices Summary

1. **Always use pagination** for list endpoints
2. **Cache frequently accessed data** (messages, pipelines)
3. **Use `select` instead of `include`** when possible
4. **Batch operations** for bulk updates
5. **Monitor slow queries** and optimize indexes
6. **Implement rate limiting** on all public endpoints
7. **Use connection pooling** appropriately for your deployment
8. **Virtualize long lists** in the frontend
9. **Optimize images** with Next.js Image component
10. **Monitor resource usage** for background jobs

---

## Performance Checklist

- [ ] Database indexes created for all filtered queries
- [ ] Pagination implemented on all list endpoints
- [ ] Rate limiting configured for all public APIs
- [ ] Caching implemented for frequently accessed data
- [ ] Connection pooling configured appropriately
- [ ] Slow query monitoring enabled
- [ ] Frontend virtualization for long lists
- [ ] Image optimization enabled
- [ ] Background jobs use appropriate concurrency
- [ ] Memory usage monitored and optimized

---

## Troubleshooting Performance Issues

### High Database Connection Usage

**Symptoms:**
- P2024 errors (connection pool exhausted)
- Slow query responses
- Timeout errors

**Solutions:**
1. Check for connection leaks (queries not closing)
2. Reduce `connection_limit` if using pooler
3. Optimize slow queries
4. Implement request queuing

### Slow API Responses

**Symptoms:**
- Response times > 1000ms
- Timeout errors
- High server CPU usage

**Solutions:**
1. Check database query performance
2. Add missing indexes
3. Implement caching
4. Optimize N+1 queries
5. Use pagination

### Memory Issues

**Symptoms:**
- Out of memory errors
- Slow garbage collection
- High memory usage

**Solutions:**
1. Review cache size limits
2. Implement cache eviction
3. Optimize large object handling
4. Use streaming for large responses

---

*Last Updated: 2025-01-27*









