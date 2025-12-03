# 🔧 Fix Database Connection Issues in Vercel

## 🔍 Problem Identified

From the logs:
- ✅ **Database 0**: Working (slow but connected)
- ❌ **Database 1**: Cannot reach `pooler.vivelzjlltbytnhybdcm.supabase.co:6543`
- ❌ **Database 2**: Cannot reach `pooler.kzvhbgqpxykganquikmv.supabase.co:6543`

---

## 🎯 Quick Fix Options

### Option 1: Use Single Database (Temporary) ⭐ Recommended

Since Database 0 is working, temporarily disable multi-DB mode:

**In Vercel Dashboard → Environment Variables:**

1. Set `ENABLE_MULTI_DB=false`
2. Set `DB_COUNT=1`
3. Keep `DATABASE_URL_0` and `DIRECT_URL_0` (they're working)
4. **Redeploy** after updating

This will make your app work immediately with Database 0 only.

---

### Option 2: Fix Database URLs (Permanent)

The issue is likely that databases 1 and 2 URLs are incorrect or the projects are inactive.

#### Step 1: Verify Supabase Projects Are Active

**Database 1:**
- Visit: https://vivelzjlltbytnhybdcm.supabase.co
- Check if project is active (not paused)
- If paused, unpause it

**Database 2:**
- Visit: https://kzvhbgqpxykganquikmv.supabase.co
- Check if project is active (not paused)
- If paused, unpause it

#### Step 2: Get Correct Pooled URLs

For each database:

1. Go to Supabase Dashboard → **Settings** → **Database**
2. Scroll to **"Connection Pooling"** section
3. Under **"Transaction mode"**, copy the connection string
4. It should look like one of these formats:

**Format A (with AWS region):**
```
postgresql://postgres.[ref]:[password]@aws-1-[region].pooler.supabase.com:6543/postgres?pgbouncer=true
```

**Format B (without AWS region):**
```
postgresql://postgres.[ref]:[password]@pooler.[ref].supabase.co:6543/postgres?pgbouncer=true
```

#### Step 3: Update Vercel Environment Variables

**In Vercel Dashboard → Environment Variables:**

Update these variables with the **exact** URLs from Supabase:

1. `DATABASE_URL_1` - Use the exact pooled URL from Database 1 dashboard
2. `DIRECT_URL_1` - Use the exact direct URL from Database 1 dashboard
3. `DATABASE_URL_2` - Use the exact pooled URL from Database 2 dashboard
4. `DIRECT_URL_2` - Use the exact direct URL from Database 2 dashboard

**Important:** Make sure to:
- ✅ Copy the **exact** connection string from Supabase
- ✅ Don't modify the password or any part of the URL
- ✅ Use port **6543** for pooled connections
- ✅ Use port **5432** for direct connections
- ✅ Include `?pgbouncer=true` for pooled URLs

#### Step 4: Redeploy

After updating environment variables:
1. Go to Vercel Dashboard → **Deployments**
2. Click **"Redeploy"** on the latest deployment
3. Or push a new commit to trigger auto-deploy

---

## 🔍 Check Current URLs in Vercel

**Current URLs (from your local .env.local):**

```env
# Database 1
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"

# Database 2
DATABASE_URL_2="postgresql://postgres.kzvhbgqpxykganquikmv:demet5732595@pooler.kzvhbgqpxykganquikmv.supabase.co:6543/postgres?pgbouncer=true"
```

**Compare with Database 0 (working):**

```env
# Database 0 (working)
DATABASE_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
```

**Notice:** Database 0 uses `aws-1-ap-southeast-1.pooler.supabase.com` format, while 1 and 2 use `pooler.[ref].supabase.co` format.

**Possible Fix:** Databases 1 and 2 might need the AWS region prefix. Check the Supabase dashboard for the exact format.

---

## 🚨 If Supabase Projects Are Paused

If the Supabase projects are paused (free tier inactivity):

1. **Unpause the projects:**
   - Go to Supabase Dashboard
   - Click on each project
   - Click "Restore" or "Unpause"

2. **Wait 1-2 minutes** for projects to fully start

3. **Get fresh connection strings:**
   - Go to Settings → Database
   - Copy the connection strings again (they might have changed)

4. **Update Vercel environment variables** with new strings

5. **Redeploy**

---

## ✅ Verification Steps

After fixing, check the logs for:

✅ **Success:**
```
[Multi-DB Router] ✅ Initialized database 1/3
[Multi-DB Router] ✅ Initialized database 2/3
[Multi-DB Router] ✅ Initialized database 3/3
[Multi-DB Router] ✅ Ready with 3 databases using hash routing
```

❌ **Still failing:**
```
[Multi-DB Router] ❌ Health check failed for database 1
[Multi-DB Router] ❌ Health check failed for database 2
```

---

## 🎯 Recommended Action

**For immediate fix:**
1. Set `ENABLE_MULTI_DB=false` in Vercel
2. Set `DB_COUNT=1` in Vercel
3. Redeploy
4. App will work with Database 0 only

**For permanent fix:**
1. Verify Supabase projects are active
2. Get exact connection strings from Supabase dashboards
3. Update Vercel environment variables
4. Redeploy

---

**Status:** ⚠️ Databases 1 & 2 need connection string verification




