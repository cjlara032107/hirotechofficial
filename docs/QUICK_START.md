# AI Automations - Quick Start Guide

## 🚀 5-Minute Setup

### 1. Verify Environment

```bash
# Check .env file has:
ENABLE_MULTI_DB=true
DB_ROUTING_STRATEGY=hash
DATABASE_URL_0=postgresql://...
DATABASE_URL_1=postgresql://...  # Optional, for multi-DB
```

### 2. Validate Schema

```bash
# Run validation script
npx tsx scripts/validate-automation-multi-db.ts

# Expected output:
# ✅ All validation checks PASSED
```

### 3. Test Basic Flow

#### Create an Automation Rule

**Via UI:**
1. Navigate to `/ai-automations`
2. Click "Create Rule"
3. Fill in:
   - Name: "Test Rule"
   - Prompt: "Send a friendly follow-up message"
   - Time interval: 24 hours
   - Tags: Any relevant tags
4. Click "Create"

**Via API:**
```bash
curl -X POST http://localhost:3000/api/ai-automations \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "name": "Test Rule",
    "customPrompt": "Send a friendly follow-up message",
    "languageStyle": "professional",
    "timeIntervalHours": 24,
    "includeTags": ["interested"],
    "enabled": true
  }'
```

#### Check Logs

Look for:
```
[Automation API] Create start
  organizationId: org_...
  multiDbEnabled: true

[Automation API] Routed DB
  dbIndex: 1
  dbHost: db1.supabase.co
  dbHealth: healthy

[Automation API] Create success
  ruleId: rule_...
```

✅ **Success!** Rule created with proper routing.

#### Execute Manually

**Via UI:**
1. Click the Play button (▶️) on your rule
2. Wait for toast notification
3. Check execution history

**Via API:**
```bash
curl -X POST http://localhost:3000/api/ai-automations/execute \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{"ruleId": "rule_..."}'
```

#### Verify Results

Check logs:
```
[Automation Execute] Start
  triggerType: manual
  
[Automation Execute] Complete
  sent: X
  failed: Y
```

Check database:
```sql
SELECT id, status, "generatedMessage", "contactId"
FROM "AIAutomationExecution"
ORDER BY "executedAt" DESC
LIMIT 5;
```

✅ **Success!** Messages sent with AI generation.

### 4. Test Cron Worker

```bash
# Trigger manually (requires CRON_SECRET)
curl http://localhost:3000/api/cron/ai-automations \
  -H "Authorization: Bearer ${CRON_SECRET}"

# Or wait for Vercel Cron (runs every minute)
```

Check logs:
```
[AI Automations Cron] Processing rule "Test Rule"
[AI Automations Cron] Rule routed to DB1
[AI Automations Cron] Rule complete: X sent, Y failed
```

✅ **Success!** Cron processing with routing.

## 📋 Quick Validation Checklist

- [ ] ✅ Environment variables set (`ENABLE_MULTI_DB=true`, etc.)
- [ ] ✅ Validation script passes
- [ ] ✅ Rule creation shows routing logs
- [ ] ✅ Manual execution works
- [ ] ✅ AI generates messages
- [ ] ✅ Messages appear in Messenger
- [ ] ✅ Execution history displays
- [ ] ✅ Cron worker processes rules
- [ ] ✅ Statistics update correctly

## 🔍 Verify Routing

### Check Routing Logs

All operations should log:
```
[Automation {API|Execute|Cron}] {Action}
  organizationId: org_...
  dbIndex: 0 or 1
  dbHost: db0.supabase.co or db1.supabase.co
```

### Verify Data in Correct DB

```typescript
// For org_abc routing to DB1:

// Query DB1 (should find data):
SELECT * FROM "AIAutomationRule" WHERE "userId" IN (
  SELECT id FROM "User" WHERE "organizationId" = 'org_abc'
);

// Query DB0 (should NOT find this org's data):
SELECT * FROM "AIAutomationRule" WHERE "userId" IN (
  SELECT id FROM "User" WHERE "organizationId" = 'org_abc'
);
```

## 🐛 Troubleshooting

### Issue: "Rule not found"

**Check:**
1. Are you using the correct session/user?
2. Does the rule exist in the routed DB?
3. Check logs for `dbIndex` and `dbHost`

**Fix:**
```bash
# Verify routing
npx tsx scripts/validate-automation-multi-db.ts

# Check which DB the org routes to
# Look for: org_abc → DB1
```

### Issue: No messages sent

**Check:**
1. Are there eligible contacts?
   - Match `includeTags`
   - Don't match `excludeTags`
   - `lastInteraction` older than time interval
   - Not in `AIAutomationStop` table

2. Is it within active hours?
3. Has daily limit been reached?

**Fix:**
Review rule configuration and contact data.

### Issue: "Database connection error"

**Check:**
1. `DATABASE_URL_0` and `DATABASE_URL_1` are correct
2. Databases are accessible (not paused/blocked)
3. Connection string format is valid

**Fix:**
```bash
# Test connection
npx tsx scripts/validate-automation-multi-db.ts

# Check Supabase dashboard for database status
```

## 📚 Next Steps

1. **Read Full Guide**: [AI_AUTOMATIONS_MULTI_DB.md](./AI_AUTOMATIONS_MULTI_DB.md)
2. **Run All Tests**: [AUTOMATION_TESTING_CHECKLIST.md](./AUTOMATION_TESTING_CHECKLIST.md)
3. **Review Implementation**: [AUTOMATION_IMPLEMENTATION_SUMMARY.md](./AUTOMATION_IMPLEMENTATION_SUMMARY.md)

## 🎉 You're All Set!

Your AI Automation system is now running with:
- ✅ Multi-database routing
- ✅ Comprehensive logging
- ✅ Org-aware security
- ✅ AI-powered personalization
- ✅ Automated execution

**Happy automating!** 🤖✨

