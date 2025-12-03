# 🔍 Multi-Database Routing Diagnostic Logs

## Overview

Comprehensive logging has been added to trace multi-database routing issues, specifically to diagnose why pages aren't connecting when multi-DB is enabled.

---

## 🎯 What Was Added

### 1. **Sync Instant API** (`src/app/api/facebook/sync-instant/route.ts`)

#### Routing Intent Logging
When a sync is initiated, you'll now see:

```
[Sync Instant API] ============================================
[Sync Instant API] MULTI-DB ROUTING INTENT
[Sync Instant API] - Organization ID: org_abc123...
[Sync Instant API] - Multi-DB Enabled: true
[Sync Instant API] - Routing Strategy: hash
[Sync Instant API] - Page ID: page_xyz789...
[Sync Instant API] ============================================
```

#### Database Selection Logging
Shows which database was chosen for the operation:

```
[Sync Instant API] ============================================
[Sync Instant API] ROUTED DATABASE SELECTED
[Sync Instant API] - DB Index: 1
[Sync Instant API] - DB Host: aws-0-us-west-1.pooler.supabase.com
[Sync Instant API] - Total DBs Available: 3
[Sync Instant API] ============================================
```

#### Fallback Detection
When a page is found in default DB but not in routed DB:

```
[Sync Instant API] ============================================
[Sync Instant API] FALLBACK: PAGE FOUND IN DEFAULT DB
[Sync Instant API] - Page ID: page_xyz789...
[Sync Instant API] - Page Org ID: org_abc123...
[Sync Instant API] - Session Org ID: org_abc123...
[Sync Instant API] - Page Name: My Facebook Page
[Sync Instant API] - Note: Page exists in default DB but not in routed DB 1
[Sync Instant API] - Routed DB was: aws-0-us-west-1.pooler.supabase.com
[Sync Instant API] ============================================
```

#### Organization Mismatch Detection
When access is denied due to org mismatch:

```
[Sync Instant API] ============================================
[Sync Instant API] ❌ ORGANIZATION MISMATCH - ACCESS DENIED
[Sync Instant API] - Page ID: page_xyz789...
[Sync Instant API] - Page Org ID: org_different...
[Sync Instant API] - Session Org ID: org_abc123...
[Sync Instant API] - Page Name: My Facebook Page
[Sync Instant API] - User ID: user_123...
[Sync Instant API] - Routed DB Index: 1
[Sync Instant API] - Routed DB Host: aws-0-us-west-1.pooler.supabase.com
[Sync Instant API] - Cause: Page belongs to different organization
[Sync Instant API] - This indicates session issue or multi-DB routing problem
[Sync Instant API] ============================================
```

#### Routing Mismatch Warning
When page should be in routed DB but is only in default:

```
[Sync Instant API] ============================================
[Sync Instant API] ⚠️  ROUTING MISMATCH - USING FALLBACK
[Sync Instant API] - Page ID: page_xyz789...
[Sync Instant API] - Page found in: DEFAULT DB (DB 0)
[Sync Instant API] - Page NOT found in: ROUTED DB 1 (aws-0-us-west-1.pooler.supabase.com)
[Sync Instant API] - Page Org ID: org_abc123...
[Sync Instant API] - Session Org ID: org_abc123...
[Sync Instant API] - Action: Using page from default DB for sync
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
[Sync Instant API] ============================================
```

---

### 2. **Sync Status API** (`src/app/api/facebook/sync-status/[jobId]/route.ts`)

#### Lookup Start Logging
When checking sync job status:

```
[Sync Status API] ============================================
[Sync Status API] JOB LOOKUP START
[Sync Status API] - Job ID: job_abc123...
[Sync Status API] - Session Org ID: org_xyz789...
[Sync Status API] - Multi-DB Enabled: true
[Sync Status API] - Routing Strategy: hash
[Sync Status API] - Lookup Strategy: Default DB first, then routed, then all DBs
[Sync Status API] ============================================
```

#### Step-by-Step Database Search

**Step 1: Default Database**
```
[Sync Status API] ============================================
[Sync Status API] STEP 1: CHECKING DEFAULT DATABASE (DB 0)
[Sync Status API] ============================================
[Sync Status API] ✅ Job found in default DB:
[Sync Status API] - Job ID: job_abc123...
[Sync Status API] - Job Org ID: org_xyz789...
[Sync Status API] - Query Time: 45ms
```

**Step 2: Session Org Routed Database**
```
[Sync Status API] ============================================
[Sync Status API] STEP 2: CHECKING SESSION ORG ROUTED DB
[Sync Status API] - Session Org ID: org_xyz789...
[Sync Status API] ============================================
[Sync Status API] Routed to DB:
[Sync Status API] - DB Index: 2
[Sync Status API] - DB Host: aws-0-us-east-1.pooler.supabase.com
[Sync Status API] ⚠️  Job NOT found in session org routed DB 2
```

**Step 3: All Databases Scan**
```
[Sync Status API] ============================================
[Sync Status API] STEP 3: SEARCHING ALL DATABASES
[Sync Status API] ============================================
[Sync Status API] Scanning all databases:
[Sync Status API] - Job ID: job_abc123...
[Sync Status API] - Total Databases: 3
[Sync Status API] - Session Org ID: org_xyz789...
[Sync Status API] - Searching DB 0 (aws-0-us-west-1.pooler.supabase.com)...
[Sync Status API]   ⚠️  Not in DB 0
[Sync Status API] - Searching DB 1 (aws-0-us-east-1.pooler.supabase.com)...
[Sync Status API] ============================================
[Sync Status API] ✅ JOB FOUND IN DB 1
[Sync Status API] - Job ID: job_abc123...
[Sync Status API] - Job Org ID: org_xyz789...
[Sync Status API] - DB Index: 1
[Sync Status API] - DB Host: aws-0-us-east-1.pooler.supabase.com
[Sync Status API] ============================================
```

#### 404 With Full Context
When job is not found anywhere:

```
[Sync Status API] ============================================
[Sync Status API] ❌ JOB NOT FOUND AFTER ALL LOOKUPS
[Sync Status API] - Job ID: job_abc123...
[Sync Status API] - Session Org ID: org_xyz789...
[Sync Status API] - Multi-DB Enabled: true
[Sync Status API] - Routing Strategy: hash
[Sync Status API] - Lookups performed:
[Sync Status API]   1. Default DB (DB 0)
[Sync Status API]   2. Session org routed DB
[Sync Status API]   3. Job org routed DB
[Sync Status API]   4. All databases scanned
[Sync Status API] - Result: Job does not exist in any database
[Sync Status API] - Possible causes:
[Sync Status API]   • Job ID is invalid or expired
[Sync Status API]   • Job was deleted
[Sync Status API]   • Database connection issues
[Sync Status API] ============================================
```

---

### 3. **Multi-DB Router** (`src/lib/db/multi-db-router.ts`)

#### Development-Only Logging

**Routing Decision (Dev Only)**
```
[Multi-DB Router] getClient called:
[Multi-DB Router] - Routing Strategy: hash
[Multi-DB Router] - Key: org_abc123...
[Multi-DB Router] - Total Databases: 3
[Multi-DB Router] - Healthy Databases: 3
[Multi-DB Router] - Using Databases: 3
```

**Hash Routing Details (Dev Only)**
```
[Multi-DB Router] Hash routing:
[Multi-DB Router] - Key: org_abc123...
[Multi-DB Router] - Hash: 1234567890
[Multi-DB Router] - Selected Index: 1
[Multi-DB Router] - Total Databases: 3
```

**Chosen Database (Dev Only)**
```
[Multi-DB Router] Chose database:
[Multi-DB Router] - DB Index: 1
[Multi-DB Router] - DB Host: aws-0-us-east-1.pooler.supabase.com
[Multi-DB Router] - Health: healthy
```

---

## 🔍 How to Use These Logs

### 1. **Diagnose Routing Issues**

When a user reports "page not connecting":

1. **Find the sync attempt** in logs:
   ```bash
   grep "MULTI-DB ROUTING INTENT" /var/log/app.log | tail -5
   ```

2. **Check which DB was selected**:
   ```bash
   grep "ROUTED DATABASE SELECTED" /var/log/app.log | tail -5
   ```

3. **Look for fallbacks**:
   ```bash
   grep "FALLBACK\|ROUTING MISMATCH" /var/log/app.log | tail -10
   ```

### 2. **Identify Database Misconfigurations**

**Symptom**: Routing says DB 1 but page is in DB 0

```
[Sync Instant API] - Page NOT found in: ROUTED DB 1
[Sync Instant API] - Page found in: DEFAULT DB (DB 0)
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
```

**Action**: 
- Check if DATABASE_URL_1 is properly configured
- Verify DNS resolution for DB 1 host
- Check if DB 1 is reachable from your deployment environment

### 3. **Trace Job Lookups**

Follow a job lookup through all stages:

```bash
# Get full trace for a specific job
grep "job_abc123" /var/log/app.log

# You'll see:
# - JOB LOOKUP START
# - STEP 1: CHECKING DEFAULT DATABASE
# - STEP 2: CHECKING SESSION ORG ROUTED DB
# - STEP 3: SEARCHING ALL DATABASES
# - Final result (found or not found)
```

### 4. **Verify Organization Routing**

Check if an organization is consistently routed to the correct database:

```bash
# Search for org routing decisions
grep "org_abc123.*ROUTED DATABASE SELECTED" /var/log/app.log

# Should show same DB index each time (for hash routing)
```

---

## 🚨 Common Issues & What Logs Show

### Issue 1: DB1/DB2 DNS Failures

**Logs will show**:
```
[Multi-DB Router] ❌ Failed to initialize database 1: getaddrinfo ENOTFOUND
[Sync Instant API] - Routed DB was: failing-host.pooler.supabase.com
[Sync Instant API] FALLBACK: PAGE FOUND IN DEFAULT DB
```

**Solution**: Fix DNS/connectivity to DB 1 and DB 2

### Issue 2: Wrong Database for Organization

**Logs will show**:
```
[Sync Instant API] - Routed DB Index: 1
[Sync Instant API] - Page NOT found in: ROUTED DB 1
[Sync Instant API] - Page found in: DEFAULT DB (DB 0)
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
```

**Solution**: Data is in wrong database, need to migrate or fix routing

### Issue 3: Organization Mismatch

**Logs will show**:
```
[Sync Instant API] ❌ ORGANIZATION MISMATCH - ACCESS DENIED
[Sync Instant API] - Page Org ID: org_different...
[Sync Instant API] - Session Org ID: org_abc123...
```

**Solution**: Session issue or user accessing wrong org's data

### Issue 4: Job Not Found Anywhere

**Logs will show**:
```
[Sync Status API] ❌ JOB NOT FOUND AFTER ALL LOOKUPS
[Sync Status API] - Lookups performed:
[Sync Status API]   1. Default DB (DB 0)
[Sync Status API]   2. Session org routed DB
[Sync Status API]   3. Job org routed DB
[Sync Status API]   4. All databases scanned
```

**Solution**: Job doesn't exist, was deleted, or all DBs failed to respond

---

## 📊 Log Analysis Queries

### Find All Routing Decisions
```bash
grep "ROUTED DATABASE SELECTED" /var/log/app.log | \
  awk '{print $NF}' | sort | uniq -c
```

### Find All Fallback Cases
```bash
grep "FALLBACK\|ROUTING MISMATCH" /var/log/app.log
```

### Find Organization Mismatches
```bash
grep "ORGANIZATION MISMATCH" /var/log/app.log
```

### Check Database Distribution
```bash
grep "DB Index:" /var/log/app.log | awk '{print $(NF-1), $NF}' | sort | uniq -c
```

### Track Specific Organization
```bash
ORG_ID="org_abc123"
grep "$ORG_ID" /var/log/app.log | \
  grep -E "(ROUTED DATABASE|FALLBACK|MISMATCH)"
```

---

## 🎯 Quick Diagnostics Checklist

When multi-DB is enabled but pages aren't connecting:

- [ ] Check logs for `ROUTED DATABASE SELECTED` - which DB was chosen?
- [ ] Check logs for `FALLBACK` - is page in wrong database?
- [ ] Check logs for `Error checking routed database` - is DB unreachable?
- [ ] Check logs for `ORGANIZATION MISMATCH` - session issues?
- [ ] Verify DATABASE_URL_1 and DATABASE_URL_2 in environment
- [ ] Test DNS resolution to all DB hosts
- [ ] Check database health status

---

## 💡 Expected Behavior

### Healthy Multi-DB Routing

```
[Sync Instant API] MULTI-DB ROUTING INTENT
[Sync Instant API] - Multi-DB Enabled: true
[Sync Instant API] ROUTED DATABASE SELECTED
[Sync Instant API] - DB Index: 1
[Sync Instant API] Looking for page...
[Sync Instant API] Found page in routed database
[Sync Instant API] Starting instant sync...
```

### Unhealthy (Fallback Required)

```
[Sync Instant API] MULTI-DB ROUTING INTENT
[Sync Instant API] - Multi-DB Enabled: true
[Sync Instant API] ROUTED DATABASE SELECTED
[Sync Instant API] - DB Index: 1
[Sync Instant API] - DB Host: failing-host.pooler.supabase.com
[Sync Instant API] Page not found in routed database
[Sync Instant API] FALLBACK: PAGE FOUND IN DEFAULT DB
[Sync Instant API] ⚠️  ROUTING MISMATCH - USING FALLBACK
[Sync Instant API] - Recommendation: This org should be in DB 1 but page is in DB 0
```

---

## 🔧 Production vs Development

### Production
- Only essential routing logs shown
- Full diagnostic boxes for issues
- Masked credentials in all logs

### Development (NODE_ENV=development)
- Additional router internal logs
- Hash calculation details
- Round-robin index selection
- Load-aware routing metrics

---

## ✅ Summary

**What You Can Now Debug**:
- ✅ Which database an org is routed to
- ✅ Whether page exists in routed vs default DB
- ✅ DNS/connectivity failures to specific DBs
- ✅ Organization mismatches
- ✅ Full job lookup path across all DBs
- ✅ Routing strategy behavior (hash/round-robin)

**All logs are**:
- ✅ Structured with clear visual separators
- ✅ Production-safe (no sensitive data)
- ✅ Searchable by job ID, org ID, or DB index
- ✅ Comprehensive without being verbose

---

**Last Updated**: December 3, 2025
**Files Modified**: 
- `src/app/api/facebook/sync-instant/route.ts`
- `src/app/api/facebook/sync-status/[jobId]/route.ts`
- `src/lib/db/multi-db-router.ts`

