# Database 2 Configuration - Add This to .env.local

## 📝 Add These Lines to Your `.env.local` File

Open your `.env.local` file and add these lines:

```bash
# Database 1 (your new Supabase project - Database 2)
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
DIRECT_URL_1="postgresql://postgres:demet5732595@db.vivelzjlltbytnhybdcm.supabase.co:5432/postgres"
```

## ⚠️ Important: Get the Exact Pooled URL

The pooled connection string above is an **estimate**. To get the **exact** pooled connection string:

1. Go to: https://vivelzjlltbytnhybdcm.supabase.co
2. Click **Settings** → **Database**
3. Scroll to **"Connection Pooling"** section
4. Under **"Transaction mode"**, click **"Connection string"**
5. Copy the URI format
6. It should look like:
   ```
   postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true
   ```

## 🔧 Update Your Multi-DB Settings

Also update these in `.env.local`:

```bash
# Enable multi-database routing
ENABLE_MULTI_DB=true
DB_COUNT=2
DB_ROUTING_STRATEGY=hash
```

## 📋 Complete Example .env.local

Your complete `.env.local` should look like this:

```bash
# Multi-Database Configuration
ENABLE_MULTI_DB=true
DB_COUNT=2
DB_ROUTING_STRATEGY=hash

# Database 0 (your original Supabase)
DATABASE_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"

# Database 1 (your new Supabase - Database 2)
# ⚠️ Get the exact pooled URL from Supabase Dashboard → Settings → Database → Connection Pooling
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
DIRECT_URL_1="postgresql://postgres:demet5732595@db.vivelzjlltbytnhybdcm.supabase.co:5432/postgres"

# Fallback (for backward compatibility)
DATABASE_URL="${DATABASE_URL_0}"
DIRECT_URL="${DIRECT_URL_0}"
```

## ✅ After Adding Database 2

1. **Run migrations on the new database**:
   ```bash
   npx tsx scripts/migrate-all-databases.ts
   ```

2. **Restart your dev server**:
   ```bash
   npm run dev
   ```

3. **Verify it's working**:
   - Visit: `http://localhost:3000/api/health/db-router`
   - Should show 2 databases with health status

## 📊 Connection Capacity

With 2 databases:
- **Total**: 2 × 200 = **400 pooled connections** (free tier)
- **Per instance**: 2 × 20 = **40 connections per Vercel instance**
- **Supports**: ~10 concurrent Vercel instances




