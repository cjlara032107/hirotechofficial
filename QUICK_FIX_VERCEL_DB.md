# 🚨 Quick Fix: Disable Multi-DB Mode in Vercel

## ⚠️ Current Issue

Databases 1 and 2 are failing to connect, causing health check errors in logs.

## ✅ Quick Fix: Use Single Database

Since Database 0 is working perfectly, let's temporarily disable multi-DB mode:

### Step 1: Update Vercel Environment Variables

1. **Go to Vercel Dashboard:**
   - Visit: https://vercel.com/dashboard
   - Select your project: **hirotechofficial-beta**

2. **Go to Environment Variables:**
   - Click **Settings** → **Environment Variables**

3. **Update these variables:**
   - Find `ENABLE_MULTI_DB`
   - Change value from `true` to `false`
   - Click **Save**
   
   - Find `DB_COUNT`
   - Change value from `3` to `1`
   - Click **Save**

4. **Verify Database 0 is set:**
   - Make sure `DATABASE_URL_0` is set (it should be)
   - Make sure `DIRECT_URL_0` is set (it should be)

### Step 2: Redeploy

After updating environment variables:

1. Go to **Deployments** tab
2. Click **"Redeploy"** on the latest deployment
3. Select **"Rebuild"** (to use new environment variables)
4. Click **"Redeploy"**

### Step 3: Verify

After redeployment, check logs for:

✅ **Success:**
```
[DB] ✅ Single database mode
[Prisma] ✅ Connected to database
```

❌ **Should NOT see:**
```
[Multi-DB Router] ❌ Health check failed
```

---

## 🎯 What This Does

- ✅ App will work immediately with Database 0 only
- ✅ No more connection errors in logs
- ✅ All features will work normally
- ✅ You can fix databases 1 & 2 later

---

## 🔧 Fix Databases 1 & 2 Later (Optional)

When you're ready to re-enable multi-DB:

1. **Verify Supabase projects are active:**
   - https://vivelzjlltbytnhybdcm.supabase.co
   - https://kzvhbgqpxykganquikmv.supabase.co

2. **Get exact connection strings:**
   - Go to Settings → Database → Connection Pooling
   - Copy the exact pooled URL (port 6543)

3. **Update Vercel environment variables:**
   - Update `DATABASE_URL_1` and `DATABASE_URL_2` with exact URLs
   - Set `ENABLE_MULTI_DB=true`
   - Set `DB_COUNT=3`

4. **Redeploy**

---

**Status:** ⚠️ Quick fix available - disable multi-DB mode




