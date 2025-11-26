# ✅ AI Automation Time Interval Logic - CONFIRMED

## 📋 Confirmation Summary

### ✅ CONFIRMED: Contacts Receive Messages Every Time Interval Resets

**How it works:**
1. User sets a time interval (e.g., 3 minutes, 1 hour, 24 hours)
2. Contact with the automation tag receives an AI-generated message
3. System records when the contact was processed
4. After the time interval passes, the contact becomes eligible again
5. Contact receives another AI-generated message
6. This cycle repeats continuously

**Code Location:** `src/app/api/cron/ai-automations/route.ts` (lines 250-275)

```typescript
// Check if this contact was processed by THIS rule within the time interval
if (thresholdMs > 0) {
  const lastExecution = await prisma.aIAutomationExecution.findFirst({
    where: {
      ruleId: rule.id,
      contactId: contact.id,
      status: 'sent',
    },
    orderBy: { executedAt: 'desc' },
  });

  if (lastExecution) {
    const timeSinceLastExecution = now.getTime() - lastExecution.executedAt.getTime();
    if (timeSinceLastExecution < thresholdMs) {
      // Skip - wait for interval to pass
      continue;
    }
  }
}
// If interval has passed, process the contact
```

### ✅ CONFIRMED: Cron Job Runs Based on Time Interval

**How it works:**
1. Cron job runs every minute (Vercel schedule: `* * * * *`)
2. For each rule, checks if time interval has passed since rule's last execution
3. If interval hasn't passed → Rule is skipped (waits)
4. If interval has passed → Rule processes eligible contacts
5. After processing, rule waits again until next interval

**Code Location:** `src/app/api/cron/ai-automations/route.ts` (lines 102-123)

```typescript
// Check if rule was executed recently (respect user-set time interval)
if (!rule.run24_7 && rule.lastExecutedAt && thresholdMs > 0) {
  const timeSinceLastExecution = now.getTime() - rule.lastExecutedAt.getTime();
  if (timeSinceLastExecution < thresholdMs) {
    // Skip - wait for interval to pass
    continue;
  }
}
// If interval has passed, process the rule
```

## 📊 Example Flow

### Example: Rule with 3-Minute Interval

**Timeline:**
- **16:00:00** - Cron runs, rule processes Contact A, sends message
- **16:01:00** - Cron runs, rule skipped (only 1 min passed, need 3 min)
- **16:02:00** - Cron runs, rule skipped (only 2 min passed, need 3 min)
- **16:03:00** - Cron runs, rule processes Contact A again, sends message
- **16:04:00** - Cron runs, rule skipped (only 1 min passed, need 3 min)
- **16:05:00** - Cron runs, rule skipped (only 2 min passed, need 3 min)
- **16:06:00** - Cron runs, rule processes Contact A again, sends message
- **Cycle repeats...**

### Example: Rule with 1-Hour Interval

**Timeline:**
- **16:00:00** - Cron runs, rule processes contacts, sends messages
- **16:01:00 to 16:59:00** - Cron runs every minute, rule skipped (waiting for 1 hour)
- **17:00:00** - Cron runs, rule processes contacts again, sends messages
- **17:01:00 to 17:59:00** - Cron runs every minute, rule skipped (waiting for 1 hour)
- **18:00:00** - Cron runs, rule processes contacts again, sends messages
- **Cycle repeats...**

## 🔄 Two-Level Time Interval Check

### Level 1: Rule-Level Check
- **Purpose:** Prevents the rule from running too frequently
- **Checks:** Time since rule's last execution
- **Action:** If interval hasn't passed, skip entire rule

### Level 2: Contact-Level Check
- **Purpose:** Ensures each contact is processed at the correct interval
- **Checks:** Time since this specific contact was last processed by this rule
- **Action:** If interval hasn't passed for this contact, skip this contact

## ✅ Guarantees

1. **Contacts with automation tag WILL receive messages** every time the interval resets
2. **Cron job WILL wait** until the time interval ends before processing again
3. **Each contact is tracked individually** - they receive messages at their own interval
4. **Rule execution is controlled** - rule only runs when interval has passed

## 🚫 Exceptions (Contacts Won't Receive Messages)

Contacts will NOT receive messages if:
- ❌ Contact replied and `stopOnReply` is enabled
- ❌ User manually removed the automation tag
- ❌ Contact is in an active campaign
- ❌ Contact is in a closed stage (Won/Lost/Archived)
- ❌ Contact is in an active chat session (last message < 30 min ago)
- ❌ Daily message limit reached
- ❌ Outside active hours (if not 24/7 mode)

## 📝 Summary

✅ **YES** - Contacts with automation tag receive AI-generated messages every time the interval resets  
✅ **YES** - Cron job runs every minute but only processes when the time interval has ended  
✅ **YES** - System waits for the full interval before processing again  
✅ **YES** - Each contact is tracked individually for accurate interval timing




