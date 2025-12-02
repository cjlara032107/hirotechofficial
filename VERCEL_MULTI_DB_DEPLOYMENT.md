# 🚀 Vercel Deployment with Multi-Database Mode

## ✅ Pre-Deployment Checks

### Build Status
- ✅ **Linting:** No errors found
- ✅ **Build:** Successful
- ✅ **Multi-DB Mode:** Enabled locally

---

## 🔧 Required Environment Variables for Vercel

Go to **Vercel Dashboard** → **Your Project** → **Settings** → **Environment Variables**

Add these variables for **Production**, **Preview**, and **Development**:

### 🗄️ Multi-Database Configuration (NEW - REQUIRED)

```env
# Enable multi-database mode
ENABLE_MULTI_DB=true
DB_COUNT=3

# Database 0 (Original)
DATABASE_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"

# Database 1
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
DIRECT_URL_1="postgresql://postgres:demet5732595@db.vivelzjlltbytnhybdcm.supabase.co:5432/postgres"

# Database 2
DATABASE_URL_2="postgresql://postgres.kzvhbgqpxykganquikmv:demet5732595@pooler.kzvhbgqpxykganquikmv.supabase.co:6543/postgres?pgbouncer=true"
DIRECT_URL_2="postgresql://postgres:demet5732595@db.kzvhbgqpxykganquikmv.supabase.co:5432/postgres"
```

### 🔴 Core Configuration (Existing)

```env
NEXT_PUBLIC_APP_URL=https://your-project-name.vercel.app
NEXTAUTH_URL=https://your-project-name.vercel.app
AUTH_SECRET=35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK
NEXTAUTH_SECRET="35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK="
NODE_ENV=production
```

### 🔐 Supabase Auth (Existing)

```env
NEXT_PUBLIC_SUPABASE_URL=https://qudsmrrfbatasnyvuxch.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1ZHNtcnJmYmF0YXNueXZ1eGNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5MjgxMDMsImV4cCI6MjA3ODUwNDEwM30.S2WNnRwW0XHyrj5KwGOgcKHuxN4EXKi5rBTX7mscuLA
```

### 📘 Facebook Integration (Existing)

```env
FACEBOOK_APP_ID=802438925861067
FACEBOOK_APP_SECRET=99e11ff061cd03fa9348547f754f96b9
FACEBOOK_WEBHOOK_VERIFY_TOKEN=your-custom-webhook-verify-token
```

### ⚡ Redis (Existing)

```env
REDIS_URL=redis://default:KGg04axFynrwFjFjFaEEX5yK3lPAVpyN@redis-14778.c326.us-east-1-3.ec2.redns.redis-cloud.com:14778
```

### 🔒 Encryption Key (Existing)

```env
ENCRYPTION_KEY=f902ad293f5f9af42c98b007dfdc0eede8614ac2be7a985c23347e051f3bcf81
```

---

## 📋 Deployment Steps

### Step 1: Add Multi-Database Environment Variables

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Select your project
3. Go to **Settings** → **Environment Variables**
4. Add the multi-database variables listed above
5. **Important:** Set them for:
   - ✅ **Production**
   - ✅ **Preview**
   - ✅ **Development**

### Step 2: Verify Existing Variables

Make sure all existing variables are still set:
- `NEXT_PUBLIC_APP_URL`
- `NEXTAUTH_URL`
- `AUTH_SECRET`
- `NEXTAUTH_SECRET`
- `DATABASE_URL` (keep for backward compatibility)
- `DIRECT_URL` (keep for backward compatibility)
- All Supabase, Facebook, Redis, and Encryption variables

### Step 3: Deploy to Vercel

**Option A: Via Git Push (Recommended)**
```bash
git add .
git commit -m "Enable multi-database mode"
git push origin main
```
Vercel will automatically deploy.

**Option B: Via Vercel CLI**
```bash
# Install Vercel CLI if not already installed
npm i -g vercel

# Deploy
vercel --prod
```

### Step 4: Verify Deployment

After deployment, check:

1. **Build Logs:**
   - Should see: `[Multi-DB Router] 🚀 Initializing 3 databases...`
   - Should see: `[DB] ✅ Multi-database routing enabled`

2. **Health Check:**
   - Visit: `https://your-project.vercel.app/api/health/db-router`
   - Should return:
     ```json
     {
       "success": true,
       "multiDbEnabled": true,
       "status": {
         "totalDatabases": 3,
         "healthyDatabases": 3
       }
     }
     ```

3. **Application:**
   - Test login
   - Test database operations
   - Check logs for any errors

---

## 🔍 Connection Pool Capacity in Vercel

With 3 databases enabled on Vercel:

- **Per Instance:** 60 connections (3 × 20)
- **Total Pooled:** 600 connections (3 × 200 free tier)
- **Supports:** ~10 concurrent Vercel instances

---

## ⚠️ Important Notes

1. **Backward Compatibility:**
   - Keep `DATABASE_URL` and `DIRECT_URL` set for backward compatibility
   - The system will use multi-DB router when `ENABLE_MULTI_DB=true`

2. **Migrations:**
   - Run migrations on all 3 databases before deploying:
     ```bash
     npx tsx scripts/migrate-all-databases.ts
     ```

3. **Database URLs:**
   - All URLs use **pooled connections** (port 6543) for better performance
   - Direct URLs (port 5432) are only used for migrations

4. **Environment Detection:**
   - Vercel automatically sets `VERCEL=1`
   - System will use 20 connections per database (Vercel mode)

---

## 🐛 Troubleshooting

### Build Fails: "DATABASE_URL_X not found"
**Solution:** Make sure all `DATABASE_URL_0`, `DATABASE_URL_1`, `DATABASE_URL_2` are set in Vercel

### Multi-DB Not Enabled After Deployment
**Solution:** 
- Verify `ENABLE_MULTI_DB=true` in Vercel
- Verify `DB_COUNT=3` in Vercel
- Check build logs for initialization messages

### Database Connection Errors
**Solution:**
- Verify all database URLs are correct
- Check Supabase dashboards to ensure databases are active
- Verify pooled connection URLs use port 6543

### Health Check Shows Single Database Mode
**Solution:**
- Check environment variables are set correctly
- Redeploy after adding variables
- Check server logs for initialization messages

---

## ✅ Post-Deployment Checklist

- [ ] All multi-DB environment variables added to Vercel
- [ ] `ENABLE_MULTI_DB=true` set in Vercel
- [ ] `DB_COUNT=3` set in Vercel
- [ ] All 3 `DATABASE_URL_X` variables set
- [ ] All 3 `DIRECT_URL_X` variables set
- [ ] Build completed successfully
- [ ] Health check shows multi-DB enabled
- [ ] Application functions correctly
- [ ] Database operations working
- [ ] No connection pool errors in logs

---

**Status:** ✅ Ready for Deployment
**Last Updated:** $(date)

