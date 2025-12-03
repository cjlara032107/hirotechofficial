# 🔧 Fix Vercel Environment Variables

## 🔍 Issue: Environment Variables Not Working

If Supabase is correct but connections are failing, the issue is likely with how environment variables are set in Vercel.

---

## ✅ Step-by-Step Fix

### Step 1: Verify Environment Variables Are Set

1. **Go to Vercel Dashboard:**
   - https://vercel.com/dashboard
   - Select project: **hirotechofficial-beta**
   - Go to **Settings** → **Environment Variables**

2. **Check these variables exist:**
   - ✅ `ENABLE_MULTI_DB` = `true`
   - ✅ `DB_COUNT` = `3`
   - ✅ `DATABASE_URL_0` = (your Database 0 URL)
   - ✅ `DATABASE_URL_1` = (your Database 1 URL)
   - ✅ `DATABASE_URL_2` = (your Database 2 URL)
   - ✅ `DIRECT_URL_0` = (your Database 0 direct URL)
   - ✅ `DIRECT_URL_1` = (your Database 1 direct URL)
   - ✅ `DIRECT_URL_2` = (your Database 2 direct URL)

### Step 2: Check Environment Scope

**CRITICAL:** Make sure each variable is set for:
- ✅ **Production**
- ✅ **Preview**
- ✅ **Development**

**How to check:**
- Click on each variable
- Look at the "Environment" column
- Should show: `Production, Preview, Development`

**If missing:**
- Click the variable
- Check the boxes for Production, Preview, Development
- Click **Save**

### Step 3: Remove Quotes from URLs

**IMPORTANT:** In Vercel, environment variable values should NOT have quotes.

**❌ Wrong (with quotes):**
```
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
```

**✅ Correct (without quotes):**
```
postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true
```

**To fix:**
1. Click on `DATABASE_URL_1`
2. Remove the quotes `"` from the beginning and end
3. Click **Save**
4. Repeat for `DATABASE_URL_2`

### Step 4: Verify URL Format

Make sure URLs match this exact format (no extra spaces, no quotes):

```
postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true
```

**Check for:**
- ✅ No quotes around the URL
- ✅ No extra spaces before/after
- ✅ Port is `6543` (for pooled) or `5432` (for direct)
- ✅ Includes `?pgbouncer=true` for pooled connections

### Step 5: Copy Exact URLs from Supabase

**For Database 1:**
1. Go to: https://vivelzjlltbytnhybdcm.supabase.co
2. **Settings** → **Database**
3. Scroll to **"Connection Pooling"**
4. Under **"Transaction mode"**, click **"Connection string"**
5. Copy the **URI** format (not the other formats)
6. Paste into Vercel `DATABASE_URL_1` (without quotes)

**For Database 2:**
1. Go to: https://kzvhbgqpxykganquikmv.supabase.co
2. **Settings** → **Database**
3. Scroll to **"Connection Pooling"**
4. Under **"Transaction mode"**, click **"Connection string"**
5. Copy the **URI** format
6. Paste into Vercel `DATABASE_URL_2` (without quotes)

### Step 6: Redeploy After Changes

**After updating environment variables:**

1. Go to **Deployments** tab
2. Click **"Redeploy"** on latest deployment
3. Select **"Rebuild"** (important - uses new env vars)
4. Click **"Redeploy"**

**OR** push a new commit to trigger auto-deploy:
```bash
git commit --allow-empty -m "Trigger redeploy for env vars"
git push origin jad
```

---

## 🔍 Common Issues

### Issue 1: Variables Not Set for All Environments

**Symptom:** Works locally but not in Vercel

**Fix:** Make sure variables are set for Production, Preview, AND Development

### Issue 2: Quotes in URLs

**Symptom:** Connection errors even with correct URLs

**Fix:** Remove quotes from environment variable values in Vercel

### Issue 3: Extra Spaces

**Symptom:** URLs look correct but don't work

**Fix:** Check for leading/trailing spaces, remove them

### Issue 4: Wrong Variable Names

**Symptom:** Variables not found

**Fix:** Make sure variable names are exactly:
- `DATABASE_URL_0` (not `DATABASE_URL0` or `DATABASE_URL_ 0`)
- `DATABASE_URL_1` (not `DATABASE_URL1`)
- `DATABASE_URL_2` (not `DATABASE_URL2`)

---

## ✅ Verification Checklist

After fixing, verify:

- [ ] All variables set for Production, Preview, Development
- [ ] No quotes around URL values
- [ ] No extra spaces in URLs
- [ ] URLs copied exactly from Supabase dashboard
- [ ] Redeployed after changes
- [ ] Check logs for success messages

---

## 🧪 Test After Fix

After redeploying, check logs for:

✅ **Success:**
```
[Multi-DB Router] ✅ Initialized database 1/3
[Multi-DB Router] ✅ Initialized database 2/3
[Multi-DB Router] ✅ Ready with 3 databases using hash routing
```

❌ **Still failing:**
```
[Multi-DB Router] ❌ Health check failed for database 1
```

If still failing, the Supabase projects might be paused or the URLs might be incorrect.

---

**Status:** 🔧 Fix environment variable configuration in Vercel




