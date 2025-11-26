# 🔧 Fix "FATAL: Tenant or user not found" Error

## The Problem

The build is failing because Prisma can't connect to your database during migrations. The error "FATAL: Tenant or user not found" means the database credentials are incorrect or the environment variables aren't set in Vercel.

---

## Solution 1: Verify Environment Variables in Vercel (Most Important)

### Step 1: Go to Vercel Dashboard

1. Go to: https://vercel.com/dashboard
2. Click on your project: **hirotechofficial-beta**
3. Go to **Settings** → **Environment Variables**

### Step 2: Check These Variables Exist

Make sure you have **BOTH** of these set:

**`DATABASE_URL`** (for regular queries):
```
postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true
```

**`DIRECT_URL`** (for migrations - port 5432):
```
postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres
```

### Step 3: Verify They're Set for All Environments

Make sure both variables are enabled for:
- ✅ **Production**
- ✅ **Preview**
- ✅ **Development** (if you use it)

### Step 4: Check the Format

**Important:** Make sure there are **NO extra spaces** or quotes in the values. Copy them exactly as shown above.

---

## Solution 2: Verify Database Credentials

The connection string format should be:
```
postgresql://[USER]:[PASSWORD]@[HOST]:[PORT]/[DATABASE]
```

For Supabase:
- **User:** `postgres.qudsmrrfbatasnyvuxch` (your project reference)
- **Password:** `demet5732595` (your database password)
- **Host:** `aws-1-ap-southeast-1.pooler.supabase.com`
- **Port:** `5432` for DIRECT_URL, `6543` for DATABASE_URL
- **Database:** `postgres`

### Check Your Supabase Dashboard

1. Go to: https://app.supabase.com/project/qudsmrrfbatasnyvuxch
2. Go to **Settings** → **Database**
3. Check **Connection string** → **URI**
4. Verify the password matches what you have in Vercel

---

## Solution 3: Test Database Connection Locally

Test if your connection string works:

```bash
# Test DIRECT_URL connection
npx prisma db pull --schema=prisma/schema.prisma
```

If this works locally but fails in Vercel, the environment variables aren't set correctly in Vercel.

---

## Solution 4: Skip Migrations Temporarily (Quick Fix)

If you need to deploy quickly and fix migrations later, you can temporarily skip migrations:

**Update `vercel.json`:**
```json
{
  "buildCommand": "prisma generate && next build"
}
```

This will skip `prisma migrate deploy` and just build the app. You can run migrations manually later via Supabase SQL Editor.

**⚠️ Warning:** This means your database schema might not be up to date. Only use this if you're sure your database is already set up correctly.

---

## Solution 5: Use Supabase Connection Pooler Correctly

For Supabase, make sure you're using the correct connection strings:

**For DATABASE_URL (with connection pooling):**
- Use port **6543** (pooler)
- Add `?pgbouncer=true` parameter
- Format: `postgresql://postgres.[PROJECT_REF]:[PASSWORD]@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true`

**For DIRECT_URL (for migrations):**
- Use port **5432** (direct)
- NO pgbouncer parameter
- Format: `postgresql://postgres.[PROJECT_REF]:[PASSWORD]@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres`

---

## Most Likely Fix

**99% of the time, this error means:**

1. **Environment variables aren't set in Vercel** → Go to Dashboard and add them
2. **Wrong password** → Check Supabase dashboard for correct password
3. **Wrong format** → Make sure no extra spaces/quotes in the connection string

---

## After Fixing

1. **Update environment variables** in Vercel Dashboard
2. **Redeploy** (or wait for auto-deploy from Git push)
3. **Check build logs** to see if it works

---

**Next Step:** Go to Vercel Dashboard → Settings → Environment Variables and verify both `DATABASE_URL` and `DIRECT_URL` are set correctly! 🔧





