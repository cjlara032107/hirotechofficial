# AI Automations - Multi-DB Implementation Guide

## Overview

The AI Automation system enables automated, personalized follow-up messages powered by AI. This document describes the complete multi-database implementation with comprehensive logging and org-aware routing.

## Architecture

### Components

1. **APIs** (`src/app/api/ai-automations/`)
   - `route.ts` - List/Create automation rules
   - `[id]/route.ts` - Get/Update/Delete specific rules
   - `[id]/executions/route.ts` - Execution history
   - `execute/route.ts` - Manual trigger

2. **Cron Worker** (`src/app/api/cron/ai-automations/route.ts`)
   - Scheduled execution (every minute)
   - Processes enabled rules within active hours
   - Respects time intervals and daily limits

3. **Database Models** (Prisma)
   - `AIAutomationRule` - Configuration and settings
   - `AIAutomationExecution` - Run history and results
   - `AIAutomationStop` - Stopped contacts (replied or excluded)

4. **Multi-DB Router** (`src/lib/db/multi-db-router.ts`)
   - Hash-based routing by `organizationId`
   - Health monitoring and failover
   - Connection pooling

## Multi-DB Routing Implementation

### Key Principles

1. **Org-Scoped Routing**: Every automation request is routed to the organization's designated database
2. **Comprehensive Logging**: All operations log routing information including DB index and host
3. **Data Integrity**: Strict validation ensures automations and related data exist only in the correct org's DB
4. **Error Context**: Meaningful error messages indicate DB connectivity issues

### Routing Flow

```typescript
// 1. Get user's organization
const user = await prisma.user.findUnique({
  where: { id: session.user.id },
  select: { organizationId: true },
});

// 2. Route to org's database
const db = getPrismaForOrg(user.organizationId);

// 3. Log routing (if multi-DB enabled)
if (process.env.ENABLE_MULTI_DB === 'true') {
  const router = getDatabaseRouter();
  const client = router.getClient(user.organizationId);
  const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
  
  logger.info('[Automation API] Routed DB', {
    organizationId: user.organizationId,
    dbIndex: dbConfig.index,
    dbHost: new URL(dbConfig.url).hostname,
    dbHealth: dbConfig.health,
  });
}

// 4. Execute operations on routed DB
const rules = await db.aIAutomationRule.findMany({ ... });
```

## Logging Standards

### Log Format

All automation operations follow a consistent logging format:

```
[Automation {Context}] {Action} - {Details}
```

**Contexts:**
- `[Automation API]` - API endpoints
- `[Automation Execute]` - Manual triggers
- `[Automation Cron]` - Scheduled executions

### Required Log Fields

**Routing Logs:**
```typescript
{
  organizationId: string,
  userId: string,
  ruleId?: string,
  multiDbEnabled: boolean,
  routingStrategy: 'hash' | 'round-robin' | 'load-aware',
  dbIndex?: number,
  dbHost?: string,
  dbHealth?: 'healthy' | 'degraded' | 'down',
}
```

**Execution Logs:**
```typescript
{
  ruleId: string,
  ruleName: string,
  organizationId: string,
  triggerType: 'manual' | 'scheduled',
  sent: number,
  failed: number,
  skipped?: number,
}
```

**Error Logs:**
```typescript
{
  error: string,
  organizationId?: string,
  ruleId?: string,
  contactId?: string,
  multiDbEnabled: boolean,
  details?: string, // In development only
}
```

## Data Integrity

### Org-Scoped Access

All operations enforce organization-level access control:

1. **Rule Access**: `rule.userId === session.user.id`
2. **Facebook Page Access**: `page.organizationId === user.organizationId`
3. **Contact Access**: `contact.organizationId === user.organizationId`

### Cross-Org Prevention

Operations that would cross organization boundaries return `403 Forbidden`:

```typescript
// Example: Attempting to use another org's Facebook page
const page = await db.facebookPage.findFirst({
  where: {
    id: facebookPageId,
    organizationId: user.organizationId, // ✓ Enforced
  },
});

if (!page) {
  return NextResponse.json(
    { error: 'Invalid Facebook page or page does not belong to your organization' },
    { status: 403 }
  );
}
```

## Status Tracking

### Execution Status

**AIAutomationExecution.status:**
- `sent` - Successfully sent to contact
- `failed` - Failed to send (includes error message)
- `pending` - Queued but not yet processed (future feature)

### Stop Reasons

**AIAutomationStop.stoppedReason:**
- `"User replied to automated message"` - Contact replied (webhook detection)
- `"User replied to automated message (detected by cron fallback)"` - Reply detected by cron
- `"User replied to automated message (detected in conversation check)"` - Reply detected during execution
- Custom reasons (tag removal, manual stop, etc.)

## AI Generation Pipeline

### Flow

1. **Input Validation**
   - Verify contact has conversation and messages
   - Check conversation history (last 20 messages)
   - Filter out system messages

2. **AI Generation**
   ```typescript
   const aiResult = await generateFollowUpMessage(
     contact.firstName || 'there',
     conversationHistory,
     rule.customPrompt,
     rule.languageStyle
   );
   ```

3. **Output Storage**
   - `generatedMessage` - The AI-generated text
   - `aiReasoning` - AI's reasoning/context
   - `aiPromptUsed` - The prompt used

4. **Logging**
   ```typescript
   logger.info('[Automation AI] Generate', {
     automationId: rule.id,
     contactId: contact.id,
     organizationId: user.organizationId,
     model: 'google-gemini',
     messageLength: aiResult.message.length,
   });
   ```

## Actions System

### Message Sending

**Flow:**
1. Generate AI message
2. Send via Facebook Messenger API
3. Store execution record
4. Store message in database
5. Update automation statistics

**Supported Features:**
- Text messages
- Message tags (ACCOUNT_UPDATE, etc.)
- Media attachments (if configured)

**Error Handling:**
```typescript
if (!result.success) {
  await db.aIAutomationExecution.create({
    data: {
      status: 'failed',
      errorMessage: result.error || 'Unknown error',
      // ... other fields
    },
  });
  
  logger.error('[Automation Execute] Failed to send', new Error(result.error), {
    contactId: contact.id,
    ruleId: rule.id,
    organizationId: user.organizationId,
  });
}
```

## Validation

### Manual Validation Steps

1. **Create Automation**
   ```bash
   # Create rule via UI or API
   POST /api/ai-automations
   
   # Verify logs show correct routing
   # Expected: [Automation API] Create: Routed DB - dbIndex, dbHost
   ```

2. **Manual Execution**
   ```bash
   POST /api/ai-automations/execute
   { "ruleId": "rule_..." }
   
   # Verify:
   # - Logs show DB routing
   # - AI generation occurs
   # - Messages are sent
   # - Execution records created
   ```

3. **Scheduled Execution**
   ```bash
   # Wait for cron (runs every minute) or trigger manually
   GET /api/cron/ai-automations
   
   # Verify:
   # - Rules are processed
   # - Contacts filtered correctly
   # - Time intervals respected
   # - Statistics updated
   ```

4. **Multi-DB Verification**
   ```bash
   # Run validation script
   npm run validate:automation-multi-db
   
   # Verify:
   # - All DBs have correct schema
   # - Data exists in routed DBs
   # - Routing works consistently
   ```

### Automated Validation

Run the validation script:

```bash
npx tsx scripts/validate-automation-multi-db.ts
```

**Checks:**
1. Schema existence in all DBs
2. Data integrity (org scoping)
3. Routing functionality
4. Cross-DB connectivity

## Error Handling

### User-Facing Errors

All errors include helpful context:

```typescript
{
  error: 'Database connection error. Please check DB1/DB2 connectivity and try again.',
  details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
}
```

### DB Connection Errors

**Detection:**
- Message includes "database", "connection", or "timeout"
- Caught at API layer

**Response:**
```json
{
  "error": "Database connection error. Please check DB1/DB2 connectivity and try again."
}
```

### Not Found Errors

When data doesn't exist in routed DB:

```json
{
  "error": "Automation rule not found",
  "details": "Rule not found in routed database. Check DB1/DB2 connectivity."
}
```

## Configuration

### Environment Variables

```bash
# Multi-DB configuration
ENABLE_MULTI_DB=true
DB_ROUTING_STRATEGY=hash  # hash | round-robin | load-aware

# Database URLs
DATABASE_URL_0=postgresql://...  # Primary/DB0
DATABASE_URL_1=postgresql://...  # DB1 (optional)
DATABASE_URL_2=postgresql://...  # DB2 (optional)

# Fallback (used when multi-DB is disabled)
DATABASE_URL=postgresql://...
```

### Cron Configuration

```json
// vercel.json
{
  "crons": [{
    "path": "/api/cron/ai-automations",
    "schedule": "* * * * *"  // Every minute
  }]
}
```

## Performance Considerations

### Concurrency

**Dynamic Limits Based on API Keys:**
```typescript
const { getCachedConcurrencyLimits } = await import('@/lib/ai/dynamic-concurrency');
const limits = await getCachedConcurrencyLimits();

// Uses: limits.automationConcurrency
// Based on: limits.keyCount (number of API keys)
```

### Batch Processing

**Cron Job:**
- Processes 20 contacts per rule per run
- Prevents overwhelming the system
- Ensures responsive execution

**Pagination:**
- Oldest contacts processed first (`lastInteraction` ASC)
- Prevents contact starvation
- Fair distribution

### Query Optimization

**Indexes Used:**
- `AIAutomationRule`: `enabled, lastExecutedAt`
- `AIAutomationRule`: `userId, enabled`
- `AIAutomationExecution`: `ruleId, createdAt`
- `AIAutomationExecution`: `contactId, createdAt`
- `AIAutomationExecution`: `status`

## Monitoring

### Key Metrics

**Rule-Level:**
- `executionCount` - Total execution attempts
- `successCount` - Successful sends
- `failureCount` - Failed sends
- `lastExecutedAt` - Last execution time

**Execution-Level:**
- `status` - sent | failed
- `errorMessage` - Failure reason (if failed)
- `executedAt` - Execution timestamp

### Logs to Monitor

```bash
# Successful routing
[Automation API] Routed DB - dbIndex: 1, dbHost: db1.supabase.co

# Execution complete
[Automation Execute] Complete - sent: 5, failed: 0, skipped: 2

# Cron processing
[AI Automations Cron] Processing rule "Follow-up Rule" (rule_123)
[AI Automations Cron] Rule "Follow-up Rule" routed to DB1 (db1.supabase.co) - Health: healthy
```

### Health Checks

**Database Health:**
```typescript
const router = getDatabaseRouter();
const status = router.getStatus();
// {
//   totalDatabases: 2,
//   healthyDatabases: 2,
//   degradedDatabases: 0,
//   downDatabases: 0,
// }
```

**Rule Health:**
- Check execution success rate: `successCount / (successCount + failureCount)`
- Monitor for high failure rates (> 10%)
- Investigate error messages

## Troubleshooting

### Common Issues

**1. "Rule not found in routed database"**
- **Cause**: Rule exists in default DB but not in org's routed DB
- **Solution**: Verify `ENABLE_MULTI_DB` setting and run data migration

**2. "Database connection error"**
- **Cause**: DB1 or DB2 connectivity issues
- **Solution**: Check DATABASE_URL_X environment variables and database health

**3. "No messages sent"**
- **Cause**: No eligible contacts match time interval/tags
- **Solution**: Review rule configuration and contact data

**4. High failure rate**
- **Cause**: AI generation failures, Facebook API errors
- **Solution**: Check logs for error patterns, verify Facebook page tokens

### Debug Mode

Enable detailed logging:

```bash
NODE_ENV=development
```

This includes `details` field in error responses with full error messages.

## Best Practices

1. **Always use `getPrismaForOrg()`** for automation operations
2. **Log routing information** at the start of each operation
3. **Include organizationId** in all log messages
4. **Validate org ownership** before accessing related resources (pages, contacts)
5. **Handle DB errors gracefully** with user-friendly messages
6. **Test multi-DB routing** before deploying to production
7. **Monitor execution success rates** and investigate failures
8. **Use the validation script** regularly to ensure data integrity

## Future Enhancements

1. **Webhook-based triggers** for real-time events
2. **Advanced scheduling** (specific dates/times)
3. **A/B testing** for prompts
4. **Performance analytics** dashboard
5. **Bulk import/export** of rules
6. **Template library** for common use cases
7. **Multi-channel support** (Instagram, WhatsApp)

