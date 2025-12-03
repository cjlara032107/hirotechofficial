# 🔍 How to Check Sync Logs

This guide explains how to check if syncing is working by monitoring logs.

---

## 📍 Where to Find Sync Logs

### 1. **Browser Console** (Client-Side Logs)

**Location:** Open your browser's Developer Tools (F12) → Console tab

**What to Look For:**

#### When Sync Starts:
```
[Sync] Instant sync started: { pageId, pageName, jobId, response }
[Sync] Updated activeSyncJobs: { pageId, jobId, totalActiveJobs }
```

#### Polling Activity:
```
[Sync Poll] Started polling for X active sync job(s)
[Sync Poll] Polling X active job(s)
[Sync Poll] Fetched status for job XXX in XXXms
[Sync Poll] Page XXX, Job XXX: { status, synced, failed, total }
```

#### Sync Progress Updates:
```
[Sync Poll] Page XXX, Job XXX: {
  status: "IN_PROGRESS",
  synced: 10,
  failed: 0,
  total: 100
}
```

#### When Sync Completes:
```
[Sync Poll] Job XXX finished with status: COMPLETED
Synced X contact(s) from [Page Name]
```

#### Errors:
```
[Sync Poll] Error polling sync job XXX
[Sync Poll] Timeout polling job XXX (took > 10s)
[Sync Poll] Failed to fetch status for job XXX
```

---

### 2. **Server Terminal** (Server-Side Logs)

**Location:** The terminal where you ran `npm run dev`

**What to Look For:**

#### Instant Sync Logs:
```
[Instant Sync XXX] 🚀 Starting instant sync execution...
[Instant Sync XXX] Streaming Messenger conversations...
[Instant Sync XXX] ✅ Messenger: X contacts stored
[Instant Sync XXX] ✅ Total contacts stored: X
[Instant Sync XXX] ✅ Completed in Xs: X contacts stored
```

#### Background Sync Logs (using logger):
```
[timestamp] ℹ️ [INFO] Starting contact sync for Facebook Page | jobId: XXX | pageId: XXX | operation: background-sync
[timestamp] 🔍 [DEBUG] Fetching Messenger conversations | jobId: XXX | operation: background-sync
[timestamp] ℹ️ [INFO] Fetched Messenger conversations | jobId: XXX | count: X | operation: background-sync
```

#### Sync Status API Logs:
```
[Sync Status API] Request completed: { jobId, status, totalTime, queryTime }
[Sync Status API] Slow database query: { jobId, queryTime }
```

---

## 🔍 How to Check if Syncing is Working

### Step 1: Open Browser Console

1. Open your app in the browser
2. Press `F12` (or right-click → Inspect)
3. Go to the **Console** tab
4. Clear the console (click the 🚫 icon or press `Ctrl+L`)

### Step 2: Start a Sync

1. Go to Settings → Integrations
2. Click "Sync" on a connected Facebook page
3. Watch the console for log messages

### Step 3: Monitor the Logs

**Expected Flow:**

1. **Sync Starts:**
   ```
   [Sync] Instant sync started: { ... }
   [Sync Poll] Started polling for 1 active sync job(s)
   ```

2. **Polling Begins:**
   ```
   [Sync Poll] Polling 1 active job(s)
   [Sync Poll] Fetched status for job XXX in 150ms
   [Sync Poll] Page XXX, Job XXX: { status: "PENDING", ... }
   ```

3. **Progress Updates (every 2 seconds):**
   ```
   [Sync Poll] Page XXX, Job XXX: { status: "IN_PROGRESS", synced: 5, total: 100 }
   [Sync Poll] Page XXX, Job XXX: { status: "IN_PROGRESS", synced: 10, total: 100 }
   [Sync Poll] Page XXX, Job XXX: { status: "IN_PROGRESS", synced: 15, total: 100 }
   ```

4. **Sync Completes:**
   ```
   [Sync Poll] Job XXX finished with status: COMPLETED
   Synced 100 contact(s) from [Page Name]
   ```

---

## ⚠️ Troubleshooting

### Issue: No Polling Messages

**Symptoms:** No `[Sync Poll]` messages in console

**Possible Causes:**
- Sync job wasn't created
- Page is not visible (tab is inactive)
- JavaScript error preventing polling

**Solution:**
1. Check if you see `[Sync] Instant sync started` message
2. Check if page is visible (tab is active)
3. Check for JavaScript errors in console
4. Refresh the page and try again

---

### Issue: Polling Timeout

**Symptoms:** 
```
[Sync Poll] Timeout polling job XXX (took > 10s)
```

**Possible Causes:**
- Sync status API is slow
- Database connection issues
- Network problems

**Solution:**
1. Check server terminal for errors
2. Check database connection
3. Check network connectivity
4. Check if sync status API endpoint is responding

---

### Issue: Sync Not Progressing

**Symptoms:** Status numbers don't change, stays at same values

**Possible Causes:**
- Background sync not actually running
- Job stuck in PENDING status
- Database connection issues

**Solution:**
1. Check server terminal for sync execution logs
2. Check if you see `[Instant Sync XXX] 🚀 Starting instant sync execution...`
3. Check database for job status
4. Restart the dev server

---

### Issue: Sync Fails Immediately

**Symptoms:** 
```
[Sync Poll] Failed to fetch status for job XXX: { status: 404, ... }
```

**Possible Causes:**
- Job wasn't created in database
- Job was deleted
- Database connection issues

**Solution:**
1. Check server terminal for errors
2. Check database connection
3. Try starting sync again
4. Check for authentication errors

---

## 📊 What Good Logs Look Like

### ✅ Healthy Sync Flow:

```
[Sync] Instant sync started: { pageId: "...", jobId: "abc-123" }
[Sync Poll] Started polling for 1 active sync job(s)
[Sync Poll] Polling 1 active job(s)
[Sync Poll] Fetched status for job abc-123 in 120ms
[Sync Poll] Page XXX, Job abc-123: { status: "PENDING", synced: 0, total: 0 }
[Sync Poll] Fetched status for job abc-123 in 95ms
[Sync Poll] Page XXX, Job abc-123: { status: "IN_PROGRESS", synced: 5, total: 100 }
[Sync Poll] Fetched status for job abc-123 in 110ms
[Sync Poll] Page XXX, Job abc-123: { status: "IN_PROGRESS", synced: 10, total: 100 }
...
[Sync Poll] Job abc-123 finished with status: COMPLETED
Synced 100 contact(s) from My Page
```

### ❌ Problematic Sync Flow:

```
[Sync] Instant sync started: { pageId: "...", jobId: "abc-123" }
[Sync Poll] Started polling for 1 active sync job(s)
[Sync Poll] Timeout polling job abc-123 (took > 10s)
[Sync Poll] Error polling sync job abc-123: { error: "Network error" }
```

---

## 🛠️ Advanced: Check Database Directly

If you have database access, you can check sync jobs directly:

```sql
-- Get recent sync jobs
SELECT 
  id,
  status,
  "syncedContacts",
  "failedContacts",
  "totalContacts",
  "createdAt",
  "startedAt",
  "completedAt",
  "tokenExpired"
FROM "SyncJob"
ORDER BY "createdAt" DESC
LIMIT 10;

-- Get active sync jobs
SELECT 
  id,
  status,
  "syncedContacts",
  "totalContacts",
  "startedAt"
FROM "SyncJob"
WHERE status IN ('PENDING', 'IN_PROGRESS')
ORDER BY "createdAt" DESC;
```

---

## 📝 Quick Checklist

When checking if syncing is working:

- [ ] Browser console shows `[Sync] Instant sync started`
- [ ] Browser console shows `[Sync Poll] Started polling`
- [ ] Browser console shows regular status updates (every 2 seconds)
- [ ] Status numbers are increasing (synced contacts going up)
- [ ] No timeout or error messages
- [ ] Server terminal shows sync execution logs
- [ ] Sync completes with success message

---

## 🚀 Next Steps

If sync is not working:

1. **Check Browser Console** - Look for error messages
2. **Check Server Terminal** - Look for server-side errors
3. **Check Network Tab** - Verify API requests are succeeding
4. **Check Database** - Verify sync jobs are being created
5. **Review Fixes** - Check `SYNC_ISSUES_ANALYSIS_AND_FIXES.md` for recent fixes

---

## 💡 Tips

- **Keep Console Open**: Keep the browser console open while syncing to see real-time updates
- **Filter Logs**: Use the console filter to search for `[Sync` to see only sync-related logs
- **Check Both Consoles**: Check both browser console (client) and server terminal (server) for complete picture
- **Monitor Progress**: Watch the `synced` number increase to confirm sync is progressing









