# ✨ Multi-DB Routing Diagnostic Logs - Summary

## 🎯 What Was Done

Comprehensive logging has been added to trace multi-database routing issues. You can now see exactly:
- Which database is chosen for each organization
- When fallbacks occur (default DB vs routed DB)
- Organization mismatches (page org vs session org)
- Complete lookup paths for jobs across all databases

---

## 📝 Files Modified

| File | Changes |
|------|---------|
| `src/app/api/facebook/sync-instant/route.ts` | • Routing intent logging<br>• DB selection logging<br>• Fallback detection<br>• Org mismatch logging |
| `src/app/api/facebook/sync-status/[jobId]/route.ts` | • Lookup start logging<br>• Step-by-step DB search<br>• All-DB scan logging<br>• 404 with full context |
| `src/lib/db/multi-db-router.ts` | • Dev-only routing logs<br>• Hash routing details<br>• DB selection logging |

---

## 🔍 Example: Sync Instant Flow

```
[Sync Instant API] ============================================
[Sync Instant API] MULTI-DB ROUTING INTENT
[Sync Instant API] - Organization ID: org_abc123...
[Sync Instant API] - Multi-DB Enabled: true
[Sync Instant API] - Routing Strategy: hash
[Sync Instant API] ============================================

[Sync Instant API] ============================================
[Sync Instant API] ROUTED DATABASE SELECTED
[Sync Instant API] - DB Index: 1
[Sync Instant API] - DB Host: aws-0-us-east-1.pooler.supabase.com
[Sync Instant API] - Total DBs Available: 3
[Sync Instant API] ============================================

[Sync Instant API] Page not found in routed database

[Sync Instant API] ============================================
[Sync Instant API] FALLBACK: PAGE FOUND IN DEFAULT DB
[Sync Instant API] - Note: Page exists in default DB but not in routed DB 1
[Sync Instant API] - Routed DB was: aws-0-us-east-1.pooler.supabase.com
[Sync Instant API] ============================================

[Sync Instant API] ============================================
[Sync Instant API] ⚠️  ROUTING MISMATCH - USING FALLBACK
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
[Sync Instant API] ============================================
```

**This tells you**: Organization is routed to DB 1, but the page data is actually in DB 0 (default). This indicates DB 1 is likely misconfigured or unreachable.

---

## 🔍 Example: Job Status Lookup

```
[Sync Status API] ============================================
[Sync Status API] JOB LOOKUP START
[Sync Status API] - Job ID: job_abc123...
[Sync Status API] - Multi-DB Enabled: true
[Sync Status API] - Lookup Strategy: Default DB first, then routed, then all DBs
[Sync Status API] ============================================

[Sync Status API] ============================================
[Sync Status API] STEP 1: CHECKING DEFAULT DATABASE (DB 0)
[Sync Status API] ============================================
[Sync Status API] ⚠️  Job NOT found in default DB

[Sync Status API] ============================================
[Sync Status API] STEP 2: CHECKING SESSION ORG ROUTED DB
[Sync Status API] ============================================
[Sync Status API] Routed to DB: { dbIndex: 1, dbHost: 'aws-0-us-east-1...' }
[Sync Status API] ⚠️  Job NOT found in session org routed DB 1

[Sync Status API] ============================================
[Sync Status API] STEP 3: SEARCHING ALL DATABASES
[Sync Status API] ============================================
[Sync Status API] - Searching DB 0 (aws-0-us-west-1...)...
[Sync Status API]   ⚠️  Not in DB 0
[Sync Status API] - Searching DB 1 (aws-0-us-east-1...)...
[Sync Status API]   ⚠️  Not in DB 1
[Sync Status API] - Searching DB 2 (aws-0-eu-west-1...)...
[Sync Status API] ============================================
[Sync Status API] ✅ JOB FOUND IN DB 2
[Sync Status API] - DB Index: 2
[Sync Status API] ============================================
```

**This tells you**: Job wasn't in default or session routed DB, but was found in DB 2 after scanning all databases.

---

## 🚨 Common Issues You Can Now Diagnose

### Issue 1: DB1/DB2 Not Reachable
**Logs show**:
```
[Sync Instant API] - Routed DB Host: aws-0-us-east-1.pooler.supabase.com
[Sync Instant API] Page NOT found in: ROUTED DB 1
[Sync Instant API] Page found in: DEFAULT DB (DB 0)
```
**Action**: Check if DATABASE_URL_1 is correct and host is reachable

### Issue 2: Data in Wrong Database
**Logs show**:
```
[Sync Instant API] ⚠️  ROUTING MISMATCH - USING FALLBACK
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
```
**Action**: Migrate organization data to correct database

### Issue 3: Organization Mismatch
**Logs show**:
```
[Sync Instant API] ❌ ORGANIZATION MISMATCH - ACCESS DENIED
[Sync Instant API] - Page Org ID: org_different...
[Sync Instant API] - Session Org ID: org_abc123...
```
**Action**: Session issue or user accessing wrong org

---

## 📊 How to Use

### Search for Routing Issues
```bash
# Find all fallback cases
grep "FALLBACK\|ROUTING MISMATCH" /var/log/app.log

# Find which DBs are being used
grep "ROUTED DATABASE SELECTED" /var/log/app.log

# Track specific organization
grep "org_abc123.*DB Index" /var/log/app.log
```

### Debug Specific Sync
```bash
# Get full sync trace
grep "page_xyz789" /var/log/app.log | grep -E "(ROUTING|FALLBACK|MISMATCH)"
```

### Check Job Lookups
```bash
# See complete lookup path
grep "job_abc123" /var/log/app.log
```

---

## ✅ What You Get

### Before
```
[Sync Instant API] Page not found
```
❌ **No context about where it looked or why**

### After
```
[Sync Instant API] MULTI-DB ROUTING INTENT
[Sync Instant API] - Organization ID: org_abc123...
[Sync Instant API] - Multi-DB Enabled: true
[Sync Instant API] - Routing Strategy: hash

[Sync Instant API] ROUTED DATABASE SELECTED
[Sync Instant API] - DB Index: 1
[Sync Instant API] - DB Host: aws-0-us-east-1.pooler.supabase.com

[Sync Instant API] Page not found in routed database
[Sync Instant API] FALLBACK: PAGE FOUND IN DEFAULT DB
[Sync Instant API] ⚠️  ROUTING MISMATCH - USING FALLBACK
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
```
✅ **Complete visibility into routing decisions and fallbacks**

---

## 🎯 Next Steps

### 1. Test It
```bash
# Start your app
npm run dev

# POST to sync-instant
curl -X POST http://localhost:3000/api/facebook/sync-instant \
  -H "Content-Type: application/json" \
  -d '{"facebookPageId": "your-page-id"}'

# Check logs for routing traces
```

### 2. Look for Patterns
- Are all orgs being routed to DB 0 (default)?
- Are DB 1/2 showing as unreachable?
- Are pages consistently in wrong database?

### 3. Fix Root Cause
Based on logs:
- Fix DATABASE_URL_1/DATABASE_URL_2 if misconfigured
- Verify DNS resolution to all DB hosts
- Migrate data if in wrong database
- Fix routing strategy if needed

---

## 📚 Documentation

Full details in **`🔍_MULTI_DB_ROUTING_LOGS.md`**:
- Complete log format examples
- All error scenarios
- Search queries
- Troubleshooting guide
- Expected behavior

---

## 🎉 Result

**You can now**:
- ✅ See which database is chosen for each org
- ✅ Identify when pages are in wrong database
- ✅ Detect DNS/connectivity failures to specific DBs
- ✅ Trace job lookups across all databases
- ✅ Debug organization mismatches
- ✅ Verify routing strategy is working correctly

**All without SSH access to production!**

The logs will pinpoint exactly where the routing fails and which database (DB0/1/2) has connectivity or data issues.

---

**Last Updated**: December 3, 2025
**Status**: ✅ Ready to Test
**Impact**: Zero functional changes, logging only

