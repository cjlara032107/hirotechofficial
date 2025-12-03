# Error Handling Strategies

This document outlines the comprehensive error handling strategies implemented across the HIRO codebase.

## Overview

The codebase implements a multi-layered error handling approach that ensures:
- **Graceful degradation**: Operations continue when possible even if some parts fail
- **User-friendly messages**: Technical errors are converted to understandable messages
- **Automatic retry**: Transient errors are automatically retried with exponential backoff
- **Error tracking**: All errors are logged with context for debugging
- **Type safety**: Custom error classes provide type-safe error handling

---

## Error Handling Layers

### 1. Database Errors (Prisma)

**Location**: `src/lib/prisma-error-handler.ts`

#### Strategy

Database errors are handled through a centralized error handler that:

1. **Categorizes errors** into retryable vs. non-retryable
2. **Converts technical errors** to user-friendly messages
3. **Implements automatic retry** for transient errors
4. **Manages connections** automatically (reconnects on failure)

#### Retryable Errors

The following Prisma errors are automatically retried:
- `P2024`: Connection pool timeout
- `P1001`: Can't reach database
- `P2034`: Database deadlock
- Connection pool exhaustion
- Network timeouts (`ETIMEDOUT`, `ECONNREFUSED`)
- Engine not connected errors

#### Error Message Mapping

| Prisma Code | User Message |
|------------|--------------|
| `P2024` | "The database is temporarily busy. Please try again in a moment." |
| `P1001` | "Unable to connect to the database. Please try again." |
| `P2002` | "A record with this information already exists." |
| `P2025` | "The record you are looking for does not exist." |
| `P2003` | "Invalid reference to a related record." |
| `P2034` | "A database conflict occurred. The operation will be retried automatically." |

#### Usage Example

```typescript
import { safePrismaOperation, handlePrismaError } from '@/lib/prisma-error-handler';

// In API routes
try {
  const user = await safePrismaOperation(
    () => prisma.user.findUnique({ where: { id } }),
    { operationName: 'findUser', maxRetries: 3 }
  );
} catch (error) {
  const { message, status, shouldRetry } = handlePrismaError(error);
  return NextResponse.json({ error: message }, { status });
}
```

---

### 2. Facebook API Errors

**Location**: `src/lib/facebook/client.ts`

#### Strategy

Facebook API errors use a custom error class (`FacebookApiError`) that provides:

1. **Type-safe error checking** via helper methods
2. **Automatic error parsing** from Facebook API responses
3. **Contextual error information** (code, type, message, context)
4. **Specific handling** for common error types

#### Error Types

| Error Code | Type | Description | Handling |
|------------|------|-------------|----------|
| `190` | Token Expired | Access token has expired | Stop operation, require re-authentication |
| `613`, `4`, `17` | Rate Limited | API rate limit exceeded | Retry with backoff, continue with other operations |
| `200`, `10` | Permission Error | Insufficient permissions | Log error, skip operation |
| `100` | Invalid Parameter | Invalid request parameter | Log error, return validation message |

#### Usage Example

```typescript
import { FacebookClient, FacebookApiError } from '@/lib/facebook/client';

try {
  const conversations = await client.getConversations(pageId, 'messenger');
} catch (error) {
  if (error instanceof FacebookApiError) {
    if (error.isTokenExpired) {
      // Handle token expiration
      return { tokenExpired: true };
    }
    if (error.isRateLimited) {
      // Handle rate limiting
      await sleep(2000);
      // Retry or continue with other operations
    }
  }
  throw error;
}
```

---

### 3. AI Service Errors

**Location**: `src/lib/ai/google-ai-service.ts`, `src/lib/ai/ai-request-wrapper.ts`

#### Strategy

AI service errors are handled through:

1. **Circuit breaker pattern**: Prevents cascading failures
2. **API key rotation**: Automatically switches to available keys
3. **Exponential backoff**: Retries with increasing delays
4. **Timeout handling**: Prevents hanging requests
5. **Graceful degradation**: Returns null instead of throwing for non-critical operations

#### Error Categories

| Error Type | Detection | Handling |
|------------|-----------|----------|
| Rate Limit (429) | HTTP status 429 or "quota" in message | Rotate to next API key, retry with backoff |
| Invalid API Key | "API key not valid" in message | Skip to next key, continue rotation |
| Network Error | `ECONNRESET`, `ETIMEDOUT` | Retry with exponential backoff |
| Timeout | Request exceeds timeout | Return null, log error |
| Circuit Breaker Open | Circuit breaker state | Return null immediately, log error |

#### Usage Example

```typescript
import { analyzeConversation } from '@/lib/ai/google-ai-service';

// Automatically handles retries, key rotation, and circuit breakers
const summary = await analyzeConversation(messages, 2, { contactId });
if (!summary) {
  // Analysis failed, but operation can continue
  console.log('AI analysis unavailable, using fallback');
}
```

---

### 4. API Route Error Handling

**Location**: `src/lib/monitoring/api-error-wrapper.ts`, `src/lib/utils/request-logger.ts`

#### Strategy

API routes use wrapper functions that:

1. **Track errors** with context (user, endpoint, timestamp)
2. **Log requests/responses** for debugging
3. **Return appropriate HTTP status codes**
4. **Provide user-friendly error messages**

#### HTTP Status Code Mapping

| Error Type | Status Code | Description |
|------------|-------------|-------------|
| Retryable errors | `503` | Service Unavailable (temporary) |
| Validation errors | `400` | Bad Request |
| Authentication errors | `401` | Unauthorized |
| Authorization errors | `403` | Forbidden |
| Not found errors | `404` | Not Found |
| Permanent errors | `500` | Internal Server Error |

#### Usage Example

```typescript
import { withErrorTracking } from '@/lib/monitoring/api-error-wrapper';
import { handlePrismaError } from '@/lib/prisma-error-handler';

export const GET = withErrorTracking(async (request: NextRequest) => {
  try {
    const data = await fetchData();
    return NextResponse.json(data);
  } catch (error) {
    const { message, status } = handlePrismaError(error);
    return NextResponse.json({ error: message }, { status });
  }
}, { endpoint: '/api/contacts' });
```

---

## Error Logging

### Centralized Error Logger

**Location**: `src/lib/logging/error-logger.ts`

All errors are logged with:
- **Full stack trace** (in development)
- **Error context** (operation, user, metadata)
- **Timestamp** and error type
- **Non-blocking**: Error logging failures don't break the app

### System Monitor

**Location**: `src/lib/monitoring/system-monitor.ts`

Tracks error rates and patterns:
- Error counts by type
- Error rates over time
- Performance impact of errors

---

## Best Practices

### 1. Always Use Type-Safe Error Handling

```typescript
// ✅ Good: Type-safe error checking
if (error instanceof FacebookApiError && error.isTokenExpired) {
  // Handle token expiration
}

// ❌ Bad: String-based error checking
if (error.message?.includes('token expired')) {
  // Fragile, can break if error message changes
}
```

### 2. Provide User-Friendly Messages

```typescript
// ✅ Good: User-friendly message
catch (error) {
  const { message } = handlePrismaError(error);
  return NextResponse.json({ error: message }, { status: 500 });
}

// ❌ Bad: Exposing technical errors
catch (error) {
  return NextResponse.json({ error: error.message }, { status: 500 });
}
```

### 3. Implement Graceful Degradation

```typescript
// ✅ Good: Operation continues even if analysis fails
const summary = await analyzeConversation(messages);
if (!summary) {
  // Use fallback or continue without summary
  return { summary: 'Analysis unavailable' };
}

// ❌ Bad: Throwing stops entire operation
const summary = await analyzeConversation(messages);
// If this throws, entire operation fails
```

### 4. Log Errors with Context

```typescript
// ✅ Good: Log with context
catch (error) {
  logger.error('Failed to sync contact', error, {
    contactId,
    pageId,
    operation: 'syncContact'
  });
  // Continue with next contact
}

// ❌ Bad: Silent failures
catch (error) {
  // No logging, hard to debug
}
```

### 5. Use Retry for Transient Errors

```typescript
// ✅ Good: Automatic retry for transient errors
const result = await safePrismaOperation(
  () => prisma.contact.create({ data }),
  { maxRetries: 3, operationName: 'createContact' }
);

// ❌ Bad: No retry, fails immediately
try {
  await prisma.contact.create({ data });
} catch (error) {
  // Fails on first transient error
  throw error;
}
```

---

## Error Recovery Strategies

### 1. Automatic Retry with Exponential Backoff

Used for: Database operations, API calls, network requests

```typescript
// Exponential backoff: 500ms, 1000ms, 2000ms
const delay = BASE_DELAY * Math.pow(2, attemptNumber);
await sleep(Math.min(delay, MAX_DELAY));
```

### 2. API Key Rotation

Used for: AI service calls

```typescript
// Automatically rotates to next available key on rate limit
const apiKey = await apiKeyManager.getNextKey({ operation: 'analyze' });
```

### 3. Circuit Breaker Pattern

Used for: External API calls

```typescript
// Prevents cascading failures by "opening" circuit after failures
if (circuitBreaker.isOpen()) {
  return null; // Fail fast
}
```

### 4. Chunk-Level Transaction Rollback

Used for: Bulk operations

```typescript
// Failed chunks don't affect successful chunks
await updateContactsInChunks(updateFn, {
  contactIds,
  chunkSize: 50,
  maxRetries: 3
});
```

---

## Error Monitoring

### Metrics Tracked

- Error rates by type and endpoint
- Retry success rates
- Average error recovery time
- Circuit breaker state changes

### Alerts

- High error rates (>5% of requests)
- Circuit breaker openings
- Database connection pool exhaustion
- API key rate limit exhaustion

---

## Summary

The error handling strategy ensures:

1. **Resilience**: Operations continue when possible
2. **User Experience**: Clear, actionable error messages
3. **Debugging**: Comprehensive error logging with context
4. **Performance**: Automatic retry and recovery
5. **Type Safety**: Custom error classes for type-safe handling

For specific implementation details, refer to the source files mentioned in each section.









