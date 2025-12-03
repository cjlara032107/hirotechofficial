# ⚡ Quick Sync Log Check

## 🎯 Quick Steps to Check if Syncing is Working

### 1. Open Browser Console
- Press `F12` in your browser
- Go to **Console** tab
- Clear console (`Ctrl+L`)

### 2. Start a Sync
- Go to Settings → Integrations
- Click "Sync" on a connected page

### 3. Look for These Messages

#### ✅ **Good Signs:**
```
[Sync] Instant sync started
[Sync Poll] Started polling for 1 active sync job(s)
[Sync Poll] Fetched status for job XXX in XXXms
[Sync Poll] Page XXX, Job XXX: { status: "IN_PROGRESS", synced: X, total: Y }
```

#### ❌ **Bad Signs:**
```
[Sync Poll] Timeout polling job XXX
[Sync Poll] Error polling sync job XXX
[Sync Poll] Failed to fetch status for job XXX
```

### 4. Check Server Terminal
Look for:
```
[Instant Sync XXX] 🚀 Starting instant sync execution...
[Instant Sync XXX] ✅ Total contacts stored: X
```

---

## 🔍 What Each Status Means

- **PENDING**: Sync job created, waiting to start
- **IN_PROGRESS**: Sync is actively running
- **COMPLETED**: Sync finished successfully
- **FAILED**: Sync encountered an error
- **CANCELLED**: Sync was cancelled by user

---

## ⚠️ Common Issues

| Issue | What to Look For | Solution |
|-------|-----------------|----------|
| **No polling** | No `[Sync Poll]` messages | Check if page is visible, refresh page |
| **Timeout** | `Timeout polling job` | Check server logs, check network |
| **Not progressing** | Status numbers don't change | Check server terminal for sync logs |
| **404 error** | `Failed to fetch status: 404` | Job may not exist, try starting sync again |

---

## 📞 Need Help?

1. Copy all console messages
2. Check server terminal output
3. Review `HOW_TO_CHECK_SYNC_LOGS.md` for detailed guide









