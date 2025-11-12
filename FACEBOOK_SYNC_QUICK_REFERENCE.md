# ⚡ Facebook Page Syncing - Quick Reference Guide

## 🚀 Quick Start

### For Users

**Start a Sync:**
1. Go to Settings > Integrations
2. Find your connected Facebook page
3. Click "Sync Contacts" button
4. Wait for "Sync started" notification
5. Monitor progress in real-time
6. You can close the tab - sync continues!

**Check Sync Status:**
- Progress shows in page card
- "Synced X contacts" with spinner
- Time elapsed counter
- Green checkmark when complete

**Enable Auto-Pipeline:**
1. Click "Settings" on page card
2. Select a pipeline from dropdown
3. Choose mode:
   - **Skip Existing**: Only assign new contacts
   - **Update Existing**: Re-evaluate all contacts
4. Click "Save"
5. Next sync will auto-assign contacts!

---

## 💻 For Developers

### Code Snippets

#### 1. Start Background Sync
```typescript
const response = await fetch('/api/facebook/sync-background', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ facebookPageId: 'clx123...' })
});

const { jobId } = await response.json();
console.log('Sync started with job ID:', jobId);
```

#### 2. Poll Sync Status
```typescript
const pollSyncStatus = async (jobId: string) => {
  const response = await fetch(`/api/facebook/sync-status/${jobId}`);
  const job = await response.json();
  
  if (job.status === 'COMPLETED') {
    console.log(`✅ Synced ${job.syncedContacts} contacts`);
    return true;
  } else if (job.status === 'FAILED') {
    console.error('❌ Sync failed:', job.errors);
    return false;
  }
  
  return null; // Still in progress
};

// Poll every 2 seconds
const interval = setInterval(async () => {
  const result = await pollSyncStatus(jobId);
  if (result !== null) {
    clearInterval(interval);
  }
}, 2000);
```

#### 3. Get Latest Sync for Page
```typescript
const response = await fetch(`/api/facebook/pages/${pageId}/latest-sync`);
const latestJob = await response.json();

if (latestJob && ['PENDING', 'IN_PROGRESS'].includes(latestJob.status)) {
  console.log('Sync already in progress');
  // Resume polling
}
```

#### 4. Enable Auto-Pipeline
```typescript
await fetch(`/api/facebook/pages/${pageId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    autoPipelineId: 'clx789...',
    autoPipelineMode: 'SKIP_EXISTING' // or 'UPDATE_EXISTING'
  })
});
```

#### 5. Manual Sync (Server-Side Only)
```typescript
import { syncContacts } from '@/lib/facebook/sync-contacts';

const result = await syncContacts(facebookPageId);
console.log(`Synced: ${result.synced}, Failed: ${result.failed}`);

if (result.tokenExpired) {
  console.error('Token expired - reconnection required');
}
```

#### 6. Direct Background Sync (Server-Side)
```typescript
import { startBackgroundSync } from '@/lib/facebook/background-sync';

const { jobId, message } = await startBackgroundSync(facebookPageId);
console.log(message, 'Job ID:', jobId);
```

---

## 📊 Database Queries

### Check Active Syncs
```sql
SELECT 
  sj.id,
  sj."facebookPageId",
  fp."pageName",
  sj.status,
  sj."syncedContacts",
  sj."startedAt",
  NOW() - sj."startedAt" as elapsed
FROM "SyncJob" sj
JOIN "FacebookPage" fp ON fp.id = sj."facebookPageId"
WHERE sj.status IN ('PENDING', 'IN_PROGRESS')
ORDER BY sj."createdAt" DESC;
```

### Sync History for Page
```sql
SELECT 
  status,
  "syncedContacts",
  "failedContacts",
  "completedAt" - "startedAt" as duration,
  "completedAt"
FROM "SyncJob"
WHERE "facebookPageId" = 'clx123...'
ORDER BY "createdAt" DESC
LIMIT 10;
```

### Contacts with AI Context
```sql
SELECT 
  COUNT(*) as total_contacts,
  COUNT("aiContext") as with_ai_context,
  ROUND(COUNT("aiContext")::numeric / COUNT(*) * 100, 2) as ai_coverage_percent
FROM "Contact"
WHERE "facebookPageId" = 'clx123...';
```

### Auto-Assignment Success Rate
```sql
SELECT 
  fp."pageName",
  COUNT(c.id) as total_contacts,
  COUNT(c."pipelineId") as assigned_contacts,
  ROUND(COUNT(c."pipelineId")::numeric / COUNT(c.id) * 100, 2) as assignment_rate
FROM "Contact" c
JOIN "FacebookPage" fp ON fp.id = c."facebookPageId"
WHERE fp."autoPipelineId" IS NOT NULL
GROUP BY fp."pageName";
```

### Find Stuck Syncs
```sql
-- Syncs running for more than 30 minutes
SELECT 
  sj.id,
  fp."pageName",
  sj.status,
  sj."syncedContacts",
  sj."startedAt",
  NOW() - sj."startedAt" as elapsed
FROM "SyncJob" sj
JOIN "FacebookPage" fp ON fp.id = sj."facebookPageId"
WHERE sj.status = 'IN_PROGRESS'
  AND sj."startedAt" < NOW() - INTERVAL '30 minutes'
ORDER BY sj."startedAt";
```

### Recent Sync Performance
```sql
SELECT 
  DATE_TRUNC('day', "completedAt") as sync_date,
  COUNT(*) as total_syncs,
  AVG("syncedContacts") as avg_contacts,
  AVG(EXTRACT(EPOCH FROM ("completedAt" - "startedAt"))) as avg_duration_seconds,
  SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as successful,
  SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed
FROM "SyncJob"
WHERE "completedAt" > NOW() - INTERVAL '7 days'
GROUP BY DATE_TRUNC('day', "completedAt")
ORDER BY sync_date DESC;
```

---

## 🐛 Debugging

### Common Issues & Solutions

#### 1. Sync Stuck in IN_PROGRESS
**Symptoms**: Sync shows "In progress" for > 1 hour

**Check**:
```sql
SELECT * FROM "SyncJob" 
WHERE status = 'IN_PROGRESS' 
  AND "startedAt" < NOW() - INTERVAL '1 hour';
```

**Fix**:
```sql
-- Manually mark as failed
UPDATE "SyncJob"
SET status = 'FAILED',
    "completedAt" = NOW(),
    errors = '[{"error": "Timeout - manually marked as failed"}]'
WHERE id = 'job_id_here';
```

#### 2. Token Expired
**Symptoms**: Sync fails immediately with "Token expired" error

**Check**:
```sql
SELECT 
  id, 
  "pageName", 
  "lastSyncedAt",
  "createdAt"
FROM "FacebookPage"
WHERE id = 'page_id_here';
```

**Fix**: User must reconnect page through Facebook OAuth

#### 3. AI Analysis Not Working
**Symptoms**: Contacts have no `aiContext`

**Check**:
```typescript
// Check API key configuration
import { getAvailableKeyCount } from '@/lib/ai/google-ai-service';

console.log('Available Google AI keys:', getAvailableKeyCount());
// Should return > 0
```

**Check Environment**:
```bash
echo $GOOGLE_AI_API_KEY
echo $GOOGLE_AI_API_KEY_2
# ... etc
```

#### 4. No Contacts Synced
**Symptoms**: `syncedContacts = 0` but no errors

**Possible Causes**:
- Page has no conversations
- All conversations are with the page itself
- Participants have no PSID

**Check Manually**:
```typescript
import { FacebookClient } from '@/lib/facebook/client';

const client = new FacebookClient(pageAccessToken);
const convos = await client.getMessengerConversations(pageId);

console.log('Conversations fetched:', convos.length);
console.log('First convo:', JSON.stringify(convos[0], null, 2));
```

#### 5. Duplicate Contacts
**Symptoms**: Same person appears twice

**Cause**: Person has both Messenger and Instagram, treated separately

**Check**:
```sql
SELECT 
  "firstName",
  "lastName",
  "messengerPSID",
  "instagramSID",
  "hasMessenger",
  "hasInstagram"
FROM "Contact"
WHERE "firstName" = 'John' AND "lastName" = 'Smith'
  AND "facebookPageId" = 'page_id_here';
```

**Note**: This is expected behavior. Future feature will merge duplicates.

---

## 📈 Performance Tuning

### Optimize Sync Speed

#### 1. Adjust AI Rate Limits
```typescript
// In sync-contacts.ts or background-sync.ts
// Current: 1-second delay after each analysis
await new Promise(resolve => setTimeout(resolve, 1000));

// Faster (if you have many API keys):
await new Promise(resolve => setTimeout(resolve, 500));

// Safer (if hitting rate limits):
await new Promise(resolve => setTimeout(resolve, 2000));
```

#### 2. Batch Progress Updates
```typescript
// Current: Update every 10 contacts
if (syncedCount % 10 === 0) {
  await prisma.syncJob.update({ ... });
}

// Less frequent (better performance):
if (syncedCount % 50 === 0) {
  await prisma.syncJob.update({ ... });
}

// More frequent (better UX):
if (syncedCount % 5 === 0) {
  await prisma.syncJob.update({ ... });
}
```

#### 3. Reduce AI Analysis
```typescript
// Skip AI for contacts without messages
if (!convo.messages?.data || convo.messages.data.length === 0) {
  // Skip AI analysis entirely
  continue;
}

// Or only analyze conversations with >X messages
if (convo.messages.data.length < 3) {
  // Skip shallow conversations
  continue;
}
```

#### 4. Increase Pagination Limit
```typescript
// In client.ts
async getMessengerConversations(pageId: string, limit = 100) {
  // Already at Facebook's maximum (100)
  // Cannot increase further
}
```

---

## 🎛️ Configuration Options

### Environment Variables
```bash
# Facebook
NEXT_PUBLIC_FACEBOOK_APP_ID=your_app_id
FACEBOOK_APP_SECRET=your_app_secret

# Google AI (add up to 8 for rotation)
GOOGLE_AI_API_KEY=key_1
GOOGLE_AI_API_KEY_2=key_2
GOOGLE_AI_API_KEY_3=key_3
# ... etc

# Database
DATABASE_URL=postgresql://...
DIRECT_URL=postgresql://...
```

### Facebook Page Settings
```typescript
interface FacebookPageSettings {
  // Auto-sync settings (not yet implemented)
  autoSync: boolean;           // Enable automatic scheduled syncs
  syncInterval: number;         // Seconds between syncs (default: 3600)
  
  // Auto-pipeline settings
  autoPipelineId: string | null;    // Pipeline to auto-assign to
  autoPipelineMode: 'SKIP_EXISTING' | 'UPDATE_EXISTING';
}
```

---

## 🔍 Monitoring & Alerts

### Health Checks

#### 1. Token Expiration Alert
```sql
-- Pages with tokens older than 50 days (expiry at 60 days)
SELECT 
  "pageName",
  "lastSyncedAt",
  "createdAt",
  NOW() - "createdAt" as age
FROM "FacebookPage"
WHERE "createdAt" < NOW() - INTERVAL '50 days'
  AND "isActive" = true;
```

#### 2. Failed Sync Alert
```sql
-- Recent sync failures
SELECT 
  fp."pageName",
  sj.status,
  sj."tokenExpired",
  sj.errors,
  sj."completedAt"
FROM "SyncJob" sj
JOIN "FacebookPage" fp ON fp.id = sj."facebookPageId"
WHERE sj.status = 'FAILED'
  AND sj."completedAt" > NOW() - INTERVAL '24 hours'
ORDER BY sj."completedAt" DESC;
```

#### 3. Long-Running Syncs
```sql
-- Syncs taking longer than expected
SELECT 
  fp."pageName",
  sj.status,
  sj."syncedContacts",
  NOW() - sj."startedAt" as elapsed
FROM "SyncJob" sj
JOIN "FacebookPage" fp ON fp.id = sj."facebookPageId"
WHERE sj.status = 'IN_PROGRESS'
  AND sj."startedAt" < NOW() - INTERVAL '15 minutes'
ORDER BY sj."startedAt";
```

#### 4. AI Coverage
```sql
-- Contacts missing AI context
SELECT 
  fp."pageName",
  COUNT(*) as total_contacts,
  COUNT(c."aiContext") as with_ai,
  COUNT(*) - COUNT(c."aiContext") as without_ai
FROM "Contact" c
JOIN "FacebookPage" fp ON fp.id = c."facebookPageId"
GROUP BY fp."pageName"
HAVING COUNT(*) - COUNT(c."aiContext") > 0;
```

---

## 🔧 Maintenance Tasks

### Weekly Tasks

#### 1. Clean Up Old Sync Jobs
```sql
-- Delete completed sync jobs older than 30 days
DELETE FROM "SyncJob"
WHERE status IN ('COMPLETED', 'FAILED')
  AND "completedAt" < NOW() - INTERVAL '30 days';
```

#### 2. Update AI Context for Active Contacts
```typescript
// Re-analyze contacts with recent activity but old AI context
const contacts = await prisma.contact.findMany({
  where: {
    lastInteraction: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
    aiContextUpdatedAt: { lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
  }
});

// Trigger re-sync for these contacts
```

#### 3. Check for Expired Tokens
```sql
-- List pages needing reconnection soon
SELECT 
  "pageName",
  "createdAt",
  60 - EXTRACT(DAY FROM NOW() - "createdAt") as days_until_expiry
FROM "FacebookPage"
WHERE "createdAt" < NOW() - INTERVAL '50 days'
  AND "isActive" = true
ORDER BY "createdAt";
```

### Monthly Tasks

#### 1. Performance Review
```sql
-- Average sync metrics by page
SELECT 
  fp."pageName",
  COUNT(sj.id) as total_syncs,
  AVG(sj."syncedContacts") as avg_contacts,
  AVG(EXTRACT(EPOCH FROM (sj."completedAt" - sj."startedAt"))) / 60 as avg_duration_minutes,
  SUM(CASE WHEN sj.status = 'COMPLETED' THEN 1 ELSE 0 END)::float / COUNT(sj.id) * 100 as success_rate
FROM "SyncJob" sj
JOIN "FacebookPage" fp ON fp.id = sj."facebookPageId"
WHERE sj."createdAt" > NOW() - INTERVAL '30 days'
GROUP BY fp."pageName";
```

#### 2. AI Analysis Quality Check
```sql
-- Contacts with low confidence AI recommendations
SELECT 
  c."firstName",
  c."lastName",
  c."aiContext",
  ca.metadata->'confidence' as confidence,
  ca.metadata->'aiRecommendation' as recommendation,
  ps.name as current_stage
FROM "Contact" c
JOIN "ContactActivity" ca ON ca."contactId" = c.id
JOIN "PipelineStage" ps ON ps.id = c."stageId"
WHERE ca.type = 'STAGE_CHANGED'
  AND ca.title = 'AI auto-assigned to pipeline'
  AND (ca.metadata->>'confidence')::int < 60
ORDER BY (ca.metadata->>'confidence')::int
LIMIT 50;
```

---

## 📚 Code Examples

### Custom Sync with Filters
```typescript
// Sync only recent conversations (last 7 days)
async function syncRecentConversations(facebookPageId: string) {
  const page = await prisma.facebookPage.findUnique({
    where: { id: facebookPageId }
  });
  
  if (!page) throw new Error('Page not found');
  
  const client = new FacebookClient(page.pageAccessToken);
  const cutoffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  
  const conversations = await client.getMessengerConversations(page.pageId);
  
  // Filter by updated_time
  const recentConvos = conversations.filter(convo => 
    new Date(convo.updated_time) > cutoffDate
  );
  
  console.log(`Found ${recentConvos.length} recent conversations`);
  
  // Process only recent ones
  for (const convo of recentConvos) {
    // ... sync logic
  }
}
```

### Retry Failed Contacts
```typescript
// Retry syncing contacts that failed last time
async function retryFailedContacts(jobId: string) {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
    include: { errors: true }
  });
  
  if (!job || !job.errors) return;
  
  const failedIds = (job.errors as any[])
    .filter(e => e.platform === 'Messenger')
    .map(e => e.id);
  
  console.log(`Retrying ${failedIds.length} failed contacts`);
  
  // Fetch and process these specific contacts
  // ... retry logic
}
```

### Export Sync Report
```typescript
// Generate CSV report of sync results
async function exportSyncReport(jobId: string) {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId }
  });
  
  if (!job) throw new Error('Job not found');
  
  const report = {
    jobId: job.id,
    status: job.status,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
    duration: job.completedAt && job.startedAt 
      ? (job.completedAt.getTime() - job.startedAt.getTime()) / 1000
      : null,
    syncedContacts: job.syncedContacts,
    failedContacts: job.failedContacts,
    totalContacts: job.totalContacts,
    successRate: job.totalContacts > 0
      ? (job.syncedContacts / job.totalContacts * 100).toFixed(2)
      : 0,
    errors: job.errors
  };
  
  console.log(JSON.stringify(report, null, 2));
  return report;
}
```

---

## 🎯 Best Practices Checklist

### Before Sync
- [ ] Verify Facebook page token is not expired
- [ ] Check Google AI API keys are configured
- [ ] Ensure no other sync is running for this page
- [ ] Database connection is stable
- [ ] Sufficient disk space available

### During Sync
- [ ] Monitor progress via polling
- [ ] Watch for error patterns in logs
- [ ] Check AI rate limit status
- [ ] Verify database write performance
- [ ] Monitor memory usage (large pages)

### After Sync
- [ ] Verify contact count increased
- [ ] Check AI context coverage
- [ ] Review auto-assignment results
- [ ] Investigate any failures
- [ ] Update lastSyncedAt timestamp

### Production Deployment
- [ ] Encrypt page access tokens
- [ ] Set up error alerting
- [ ] Configure backup sync schedule
- [ ] Monitor token expiration
- [ ] Set up database backups
- [ ] Configure rate limit monitoring
- [ ] Test recovery after crashes

---

## 📞 Need Help?

### Check Logs
```bash
# Server logs
tail -f /path/to/server.log | grep "Background Sync"
tail -f /path/to/server.log | grep "Google AI"

# Database logs
# Check your PostgreSQL logs for connection issues
```

### Debug Mode
```typescript
// Add more detailed logging
console.log('[DEBUG] Starting sync for page:', page.pageId);
console.log('[DEBUG] Fetched conversations:', conversations.length);
console.log('[DEBUG] AI keys available:', getAvailableKeyCount());
```

### Contact Support
- Check GitHub issues
- Review documentation
- Test with small pages first
- Provide sync job ID for debugging

---

*Quick reference guide for Facebook Page Syncing*
*Last Updated: November 12, 2025*
*System Version: 2.0*

