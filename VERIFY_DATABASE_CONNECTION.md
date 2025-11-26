# 🔍 Verify Database Connection - Fix "Tenant or user not found"

## The Error

The build is still failing with: **"FATAL: Tenant or user not found"**

This means Prisma can't connect to your Supabase database during migrations.

---

## Step 1: Verify Your Supabase Connection String

### Go to Supabase Dashboard

1. Go to: https://app.supabase.com/project/qudsmrrfbatasnyvuxch
2. Click **Settings** (gear icon) → **Database**
3. Scroll to **Connection string** section
4. Select **URI** tab
5. Copy the connection string

### Check the Format

The connection string should look like:
```
postgresql://postgres.[PROJECT_REF]:[PASSWORD]@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres
```

**Important points:**
- Username format: `postgres.qudsmrrfbatasnyvuxch` (with the dot!)
- Password: Your actual database password
- Port 5432 for DIRECT_URL (direct connection)
- Port 6543 for DATABASE_URL (with pooling)

---

## Step 2: Verify Password is Correct

The password in your connection string is: `demet5732595`

**Verify this is correct:**
1. Go to Supabase Dashboard → **Settings** → **Database**
2. Check if you can see/reset the database password
3. Make sure it matches what you have in Vercel

---

## Step 3: Test Connection String Format

Your current connection strings:

**DATABASE_URL (port 6543 - pooling):**
```
postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true
```

**DIRECT_URL (port 5432 - direct):**
```
postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres
```

**Check:**
- ✅ Username has the dot: `postgres.qudsmrrfbatasnyvuxch`
- ✅ Password is correct: `demet5732595`
- ✅ Port 5432 for DIRECT_URL
- ✅ Port 6543 for DATABASE_URL
- ✅ No extra spaces or quotes

---

## Step 4: Alternative Connection String Format

If the above doesn't work, try using the **Transaction** mode connection string from Supabase:

1. In Supabase Dashboard → **Settings** → **Database**
2. Under **Connection string**, select **Transaction** mode
3. Copy that connection string
4. Use it for `DIRECT_URL` (remove the `?pgbouncer=true` part if present)

---

## Step 5: Check Vercel Environment Variables

Make absolutely sure in Vercel Dashboard:

1. Go to **Settings** → **Environment Variables**
2. Verify `DIRECT_URL` exists
3. Check the value is EXACTLY:
   ```
   postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres
   ```
4. Make sure there are:
   - ❌ NO quotes around the value
   - ❌ NO extra spaces
   - ❌ NO line breaks
5. Verify it's enabled for **Production**, **Preview**, and **Development**

---

## Step 6: Try Alternative - Use Connection Pooling for Both

Sometimes Supabase requires using the pooler for both. Try this:

**DATABASE_URL:**
```
postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true
```

**DIRECT_URL (try with pooler too):**
```
postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true
```

**Note:** This might not work for migrations, but worth trying.

---

## Step 7: Skip Migrations Temporarily (Quick Fix)

If you need to deploy now and fix migrations later:

**Update `vercel.json`:**
```json
{
  "buildCommand": "prisma generate && next build"
}
```

This skips `prisma migrate deploy`. You can run migrations manually via Supabase SQL Editor later.

**⚠️ Only do this if your database schema is already set up!**

---

## Step 8: Verify Database is Accessible

1. Go to Supabase Dashboard
2. Check if your database is **Active** and **Running**
3. Try opening **Table Editor** - can you see tables?
4. If database is paused, **Resume** it

---

## Most Common Issues

1. **Wrong password** → Check Supabase Dashboard
2. **Wrong username format** → Should be `postgres.qudsmrrfbatasnyvuxch` (with dot)
3. **Environment variable not set** → Check Vercel Dashboard
4. **Database paused** → Resume in Supabase Dashboard
5. **Extra spaces/quotes** → Remove them from Vercel env vars

---

## Quick Test

After updating, the build should get past the database connection step. If it still fails, the password or connection string format is likely wrong.

**Next Step:** Double-check your Supabase connection string in the dashboard and make sure it matches exactly what you have in Vercel! 🔧





