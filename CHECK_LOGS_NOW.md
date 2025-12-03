# 🔍 Check Sync Logs - Quick Guide

## Method 1: Browser Console (Real-time) ⚡

1. **Open your app** in the browser (http://localhost:3001)
2. **Press F12** to open Developer Tools
3. **Go to Console tab**
4. **Start a sync** (Settings → Integrations → Click "Sync")
5. **Watch for these messages:**

```
✅ Good signs:
[Sync] Instant sync started
[Sync Poll] Started polling for 1 active sync job(s)
[Sync Poll] Fetched status for job XXX in XXXms
[Sync Poll] Page XXX, Job XXX: { status: "IN_PROGRESS", synced: 5, total: 100 }

❌ Bad signs:
[Sync Poll] Timeout polling job XXX
[Sync Poll] Error polling sync job XXX
```

---

## Method 2: API Endpoint (Recent Jobs) 📊

**Open in browser:**
```
http://localhost:3001/api/debug/sync-logs?limit=10
```

**Or use curl:**
```bash
curl http://localhost:3001/api/debug/sync-logs?limit=10
```

**Response shows:**
- Recent sync jobs (last 10)
- Status of each job
- Progress information
- Errors if any
- Summary statistics

---

## Method 3: Server Terminal (Backend Logs) 🖥️

**Check the terminal where you ran `npm run dev`**

Look for:
```
[Instant Sync XXX] 🚀 Starting instant sync execution...
[Instant Sync XXX] Streaming Messenger conversations...
[Instant Sync XXX] ✅ Total contacts stored: X
[Instant Sync XXX] ✅ Completed in Xs: X contacts stored
```

---

## Method 4: Network Tab (API Calls) 🌐

1. **Open Developer Tools** (F12)
2. **Go to Network tab**
3. **Start a sync**
4. **Filter by "sync"**
5. **Check these requests:**
   - `POST /api/facebook/sync-instant` - Starts sync
   - `GET /api/facebook/sync-status/[jobId]` - Polls status (every 2s)

**Look for:**
- ✅ Status 200 = Success
- ❌ Status 404 = Job not found
- ❌ Status 500 = Server error
- ⏱️ Response time should be < 500ms

---

## Quick Status Check

### What Each Status Means:

| Status | Meaning | Action |
|--------|---------|--------|
| **PENDING** | Job created, waiting to start | Wait for it to start |
| **IN_PROGRESS** | Sync is running | Monitor progress |
| **COMPLETED** | Sync finished successfully | ✅ Done! |
| **FAILED** | Sync encountered error | Check errors array |
| **CANCELLED** | Sync was cancelled | Start new sync |

---

## Troubleshooting

### No logs appearing?
1. Check if page is visible (tab must be active)
2. Refresh the page
3. Check for JavaScript errors in console
4. Verify sync button was clicked

### Sync stuck at same number?
1. Check server terminal for execution logs
2. Check if job status is IN_PROGRESS
3. Check for errors in browser console
4. Try cancelling and restarting sync

### Timeout errors?
1. Check network connection
2. Check server terminal for errors
3. Check database connection
4. Check if sync status API is responding

---

## Expected Log Flow

```
1. [Sync] Instant sync started
2. [Sync Poll] Started polling
3. [Sync Poll] Fetched status (every 2s)
4. [Sync Poll] Status updates (synced numbers increase)
5. [Sync Poll] Job finished: COMPLETED
6. Success toast: "Synced X contacts"
```

---

## Need More Help?

- See `HOW_TO_CHECK_SYNC_LOGS.md` for detailed guide
- See `SYNC_ISSUES_ANALYSIS_AND_FIXES.md` for recent fixes
- Check browser console for specific error messages









