# AI Automations - Testing & Validation Checklist

## Pre-Testing Setup

### Environment Configuration

- [ ] `ENABLE_MULTI_DB=true` is set
- [ ] `DATABASE_URL_0` is configured
- [ ] `DATABASE_URL_1` is configured (if using multi-DB)
- [ ] `DB_ROUTING_STRATEGY=hash` is set
- [ ] Facebook page access tokens are valid
- [ ] AI API keys (Google Gemini) are configured

### Database Preparation

- [ ] Run database migrations on all DBs:
  ```bash
  # For each DATABASE_URL_X
  npx prisma migrate deploy
  ```

- [ ] Verify schema exists in all DBs:
  ```bash
  npx tsx scripts/validate-automation-multi-db.ts
  ```

- [ ] Create test organization(s) with users
- [ ] Connect Facebook pages to test organizations
- [ ] Create test contacts with:
  - Valid `messengerPSID`
  - Linked to Facebook page
  - Conversation history
  - Various tags for filtering

## Test 1: Multi-DB Routing Validation

### Objective
Verify that automation rules are stored and retrieved from the correct organization's database.

### Steps

1. **Create automation rule** (User from Org A):
   ```bash
   POST /api/ai-automations
   {
     "name": "Test Rule - Org A",
     "customPrompt": "Send a friendly follow-up message",
     "languageStyle": "professional",
     "timeIntervalHours": 24,
     "includeTags": ["interested"],
     "enabled": true
   }
   ```

2. **Check logs** for routing information:
   ```
   ✓ [Automation API] Create start - organizationId: org_a
   ✓ [Automation API] Create: Routed DB - dbIndex: 0, dbHost: db0.supabase.co
   ✓ [Automation API] Create success - ruleId: rule_...
   ```

3. **Verify in database**:
   ```sql
   -- On routed DB (DB0 for org_a)
   SELECT id, name, "userId" FROM "AIAutomationRule" WHERE id = 'rule_...';
   -- Should return the rule
   
   -- On other DBs (DB1, etc.)
   SELECT id, name FROM "AIAutomationRule" WHERE id = 'rule_...';
   -- Should return nothing
   ```

4. **List rules** (same user):
   ```bash
   GET /api/ai-automations
   ```
   
5. **Verify response includes the created rule**

**Expected Results:**
- ✅ Rule created in routed DB (DB0 for org_a)
- ✅ Rule NOT present in other DBs
- ✅ Logs show correct dbIndex and dbHost
- ✅ List API returns the rule

## Test 2: Org Integrity Checks

### Objective
Ensure cross-organization access is prevented.

### Steps

1. **Create rule** with User A (Org A)
2. **Attempt to access** with User B (Org B):
   ```bash
   # Login as User B
   GET /api/ai-automations/{ruleId from User A}
   ```

3. **Verify 404 response**:
   ```json
   {
     "error": "Automation rule not found or access denied"
   }
   ```

4. **Check logs**:
   ```
   ✓ [Automation API] Get: Rule not found or access denied
   ✓ organizationId: org_b (different from rule's org)
   ```

**Expected Results:**
- ✅ 404 error returned
- ✅ User B cannot access User A's rule
- ✅ Logs indicate access denial

## Test 3: Manual Execution (Immediate Run)

### Objective
Test manual trigger with AI generation and message sending.

### Steps

1. **Create test rule** with valid prompt
2. **Ensure test contacts exist**:
   - Have conversations
   - Match rule criteria (tags, time interval)
   - Not recently contacted

3. **Trigger manual execution**:
   ```bash
   POST /api/ai-automations/execute
   { "ruleId": "rule_..." }
   ```

4. **Monitor logs**:
   ```
   [Automation Execute] Start - ruleId, organizationId, triggerType: manual
   [Automation Execute] Routed DB - dbIndex, dbHost
   [Automation Execute] Manual execution of automation rule
   [Automation Execute] Sent message to {contact}
   [Automation Execute] Complete - sent: X, failed: Y
   ```

5. **Verify in database**:
   ```sql
   SELECT id, status, "generatedMessage", "contactId"
   FROM "AIAutomationExecution"
   WHERE "ruleId" = 'rule_...'
   ORDER BY "executedAt" DESC;
   ```

6. **Check Facebook**:
   - Open Messenger conversation with test contact
   - Verify message was sent

**Expected Results:**
- ✅ AI generates personalized message
- ✅ Message sent to eligible contacts
- ✅ Execution records created with `status='sent'`
- ✅ Message visible in Facebook Messenger
- ✅ Logs show routing and execution details

## Test 4: Scheduled Execution (Cron)

### Objective
Verify cron job processes rules correctly.

### Steps

1. **Create rule** with:
   - `enabled: true`
   - Short time interval (e.g., 1 hour)
   - Active hours covering current time
   - Tags matching test contacts

2. **Wait for cron** (runs every minute) or trigger manually:
   ```bash
   GET /api/cron/ai-automations
   # Add auth header: Authorization: Bearer {CRON_SECRET}
   ```

3. **Monitor logs**:
   ```
   [AI Automations Cron] Starting execution...
   [AI Automations Cron] Processing rule "{ruleName}" (rule_...)
   [AI Automations Cron] Organization: org_a
   [AI Automations Cron] Rule routed to DB0 (db0.supabase.co) - Health: healthy
   [AI Automations Cron] Found X potentially eligible contacts
   [AI Automations Cron] Processing contact: {firstName} (contact_id)
   [AI Automations Cron] Sent message to {firstName}
   [AI Automations Cron] Rule "{ruleName}" complete: X sent, Y failed
   ```

4. **Verify rule statistics updated**:
   ```sql
   SELECT 
     id, name, "executionCount", "successCount", "failureCount", "lastExecutedAt"
   FROM "AIAutomationRule"
   WHERE id = 'rule_...';
   ```

**Expected Results:**
- ✅ Cron picks up enabled rule
- ✅ Routes to correct DB per organization
- ✅ Processes eligible contacts
- ✅ Sends messages
- ✅ Updates rule statistics
- ✅ Respects time intervals (doesn't re-process too soon)

## Test 5: Time Interval Enforcement

### Objective
Ensure contacts aren't messaged more frequently than configured.

### Steps

1. **Create rule** with `timeIntervalHours: 24`
2. **Execute manually** → Contact A gets message
3. **Execute again immediately** → Verify Contact A is skipped:
   ```json
   {
     "sent": 0,
     "failed": 0,
     "skipped": 1,
     "message": "1 contacts were skipped because they were processed in the last X minutes."
   }
   ```

4. **Wait 24 hours** (or adjust rule interval)
5. **Execute again** → Contact A should receive message

**Expected Results:**
- ✅ Contact skipped when within time interval
- ✅ Contact eligible after interval expires
- ✅ Logs show per-contact time interval checks

## Test 6: Stop on Reply

### Objective
Verify automation stops for contacts who reply.

### Steps

1. **Create rule** with `stopOnReply: true`
2. **Execute** → Contact A receives message
3. **Send reply** from Contact A via Messenger
4. **Wait for webhook** to process reply (or trigger cron)
5. **Check AIAutomationStop table**:
   ```sql
   SELECT * FROM "AIAutomationStop"
   WHERE "ruleId" = 'rule_...' AND "contactId" = 'contact_a';
   ```

6. **Execute again** → Contact A should be skipped

**Expected Results:**
- ✅ Stop record created when contact replies
- ✅ Contact excluded from future executions
- ✅ Other contacts still receive messages
- ✅ Logs show stop record creation

## Test 7: Tag Filtering

### Objective
Verify include/exclude tags work correctly.

### Steps

1. **Create rule** with:
   - `includeTags: ["interested"]`
   - `excludeTags: ["do-not-contact"]`

2. **Create test contacts**:
   - Contact A: tags = `["interested"]` → Should receive
   - Contact B: tags = `["interested", "do-not-contact"]` → Should NOT receive
   - Contact C: tags = `["other"]` → Should NOT receive

3. **Execute rule**

4. **Verify**:
   - Only Contact A received message
   - Logs show filtered contacts

**Expected Results:**
- ✅ Only contacts matching includeTags receive messages
- ✅ Contacts with excludeTags are filtered out
- ✅ Correct number of eligible contacts logged

## Test 8: Active Hours

### Objective
Verify cron respects active hours.

### Steps

1. **Create rule** with:
   - `activeHoursStart: 9`
   - `activeHoursEnd: 21`
   - `run24_7: false`

2. **Trigger cron outside active hours** (e.g., 2 AM)
3. **Verify logs**:
   ```
   [AI Automations Cron] Rule "{name}" outside active hours (9-21)
   ```

4. **Trigger cron during active hours** (e.g., 2 PM)
5. **Verify rule executes**

**Expected Results:**
- ✅ Rule skipped outside active hours
- ✅ Rule executes during active hours
- ✅ Logs indicate hour check

## Test 9: AI Generation

### Objective
Verify AI generates appropriate messages.

### Steps

1. **Create rule** with detailed prompt:
   ```
   "Send a friendly follow-up asking about their interest in our product. 
   Reference their previous conversation and be personal."
   ```

2. **Execute for contact** with conversation history
3. **Check execution record**:
   ```sql
   SELECT "generatedMessage", "aiReasoning", "previousMessages"
   FROM "AIAutomationExecution"
   WHERE id = 'exec_...';
   ```

4. **Verify**:
   - Message is personalized
   - References conversation context
   - Follows prompt instructions
   - Appropriate tone (from `languageStyle`)

**Expected Results:**
- ✅ AI generates unique message per contact
- ✅ Message context-aware (references previous messages)
- ✅ Tone matches `languageStyle`
- ✅ `aiReasoning` field populated

## Test 10: Execution History

### Objective
Verify execution history API and UI display.

### Steps

1. **Execute rule multiple times** with various outcomes (sent/failed)
2. **Fetch execution history**:
   ```bash
   GET /api/ai-automations/{ruleId}/executions?page=1&limit=25
   ```

3. **Verify response includes**:
   - All executions for the rule
   - Correct status (sent/failed)
   - Contact details
   - Generated messages
   - Error messages (if failed)
   - Pagination info

4. **Check UI**:
   - Click "View Execution History" on rule card
   - Verify executions display with:
     - ✅ Status badges (green=sent, red=failed)
     - ✅ Contact names
     - ✅ Timestamps
     - ✅ Generated messages
     - ✅ AI reasoning
     - ✅ Error details (if failed)

**Expected Results:**
- ✅ API returns correct execution history
- ✅ Pagination works
- ✅ UI displays history clearly
- ✅ Can view AI-generated content

## Test 11: Error Handling

### Objective
Verify graceful error handling and meaningful error messages.

### Test Cases

### 11.1: Database Connectivity Error

**Setup:** Temporarily disable DB1 (if using multi-DB)

**Steps:**
1. Create rule (should fallback to available DB or show clear error)
2. Verify error message:
   ```json
   {
     "error": "Database connection error. Please check DB1/DB2 connectivity and try again."
   }
   ```

### 11.2: Invalid Facebook Page

**Steps:**
1. Attempt to create rule with `facebookPageId` from another org
2. Verify 403 response:
   ```json
   {
     "error": "Invalid Facebook page or page does not belong to your organization"
   }
   ```

### 11.3: Rule Not Found

**Steps:**
1. Access non-existent rule: `GET /api/ai-automations/invalid_id`
2. Verify 404 with helpful message

### 11.4: AI Generation Failure

**Setup:** Temporarily disable AI service or use invalid API key

**Steps:**
1. Execute rule
2. Verify:
   - Execution record created with `status='failed'`
   - Error message: "Failed to generate AI message"
   - Logs show AI generation error

**Expected Results:**
- ✅ All errors return appropriate HTTP status codes
- ✅ Error messages are user-friendly
- ✅ DB errors specifically mention "DB1/DB2 connectivity"
- ✅ Logs contain full error context

## Test 12: Performance & Concurrency

### Objective
Verify system handles concurrent executions and large batches.

### Steps

1. **Create 5+ rules** for same organization
2. **Trigger cron** (processes all enabled rules)
3. **Monitor logs** for:
   - Concurrency limits used
   - Processing time per rule
   - Total duration

4. **Create rule** targeting 100+ contacts
5. **Execute manually**
6. **Verify**:
   - Batch processing works (20 contacts per run)
   - Respects concurrency limits
   - Completes in reasonable time

**Expected Results:**
- ✅ Multiple rules process concurrently (per concurrency limit)
- ✅ Large batches handled efficiently
- ✅ No timeouts or crashes
- ✅ Logs show concurrency info

## Test 13: Multi-DB Schema Validation

### Objective
Ensure all DBs have consistent schema.

### Steps

1. **Run validation script**:
   ```bash
   npx tsx scripts/validate-automation-multi-db.ts
   ```

2. **Verify output**:
   ```
   Test 1: Validating automation schema in all databases...
     ✓ DB0: Found X rules, Y executions, Z stops
     ✓ DB1: Found X rules, Y executions, Z stops

   Test 2: Validating data integrity across databases...
     ✓ DB0: All rules have valid organizationId
     ✓ DB1: All rules have valid organizationId

   Test 3: Validating multi-DB routing...
     ✓ Router initialized with 2 databases

   Test 4: Testing cross-DB connectivity...
     ✓ DB0: Connected in Xms
     ✓ DB1: Connected in Xms

   ✅ All validation checks PASSED
   ```

**Expected Results:**
- ✅ All tests pass
- ✅ Schema exists in all DBs
- ✅ Data integrity verified
- ✅ Routing works correctly

## Post-Testing Validation

### Logs Review

Check for:
- [ ] All operations log routing information (orgId, dbIndex, dbHost)
- [ ] No errors or warnings in production logs
- [ ] Execution success rate > 90%

### Database Check

Verify:
- [ ] No orphaned execution records
- [ ] Rule statistics match actual executions
- [ ] Stop records are accurate

### UI/UX Check

Test:
- [ ] All buttons work
- [ ] Loading states display correctly
- [ ] Error messages are clear and actionable
- [ ] Execution history loads and displays properly
- [ ] Search and filtering work

## Production Deployment Checklist

Before deploying to production:

- [ ] All test cases pass
- [ ] Multi-DB validation script passes
- [ ] `ENABLE_MULTI_DB=true` set in production
- [ ] All `DATABASE_URL_X` configured in production
- [ ] Cron job configured in Vercel (`vercel.json`)
- [ ] `CRON_SECRET` set for security
- [ ] Facebook page tokens verified
- [ ] AI API keys verified
- [ ] Monitoring and alerts configured
- [ ] Documentation reviewed and updated

## Troubleshooting Common Issues

### Issue: "Rule not found in routed database"

**Diagnosis:**
```bash
# Check which DB the org routes to
# In logs, look for: Routed DB - dbIndex: X

# Check if rule exists in that DB
# Connect to DB_X and query AIAutomationRule
```

**Fix:** Migrate data to correct DB or verify routing configuration

### Issue: No contacts eligible

**Diagnosis:**
```bash
# Check rule criteria: tags, time interval, active hours
# Verify contacts exist in routed DB
# Check lastInteraction timestamps
```

**Fix:** Adjust rule criteria or update contact data

### Issue: High failure rate

**Diagnosis:**
- Check execution records for error patterns
- Verify Facebook page tokens
- Check AI API quota/errors

**Fix:** Renew tokens, increase API quota, or adjust prompts

## Success Criteria

All tests pass when:
- ✅ Multi-DB routing works consistently
- ✅ Org integrity is enforced
- ✅ Manual and scheduled executions succeed
- ✅ AI generates appropriate messages
- ✅ Time intervals are respected
- ✅ Stop-on-reply works
- ✅ Error handling is graceful
- ✅ Logs provide clear debugging information
- ✅ UI displays data correctly
- ✅ Performance is acceptable

---

**Testing Complete!** 🎉

Your AI Automation system is now production-ready with full multi-DB support, comprehensive logging, and robust error handling.

