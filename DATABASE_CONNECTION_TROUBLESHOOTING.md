# 🔴 Database Connection Error - Troubleshooting Guide

**Error:** Can't reach database server at `aws-1-ap-southeast-1.pooler.supabase.com:5432`

**Date:** November 12, 2025

---

## 🔍 Most Likely Causes

### 1. ⏸️ Supabase Database Paused (Most Common)

**Supabase free tier databases automatically pause after 7 days of inactivity.**

#### ✅ Solution:
1. Go to your Supabase dashboard: https://supabase.com/dashboard
2. Find your project: `mrqytcrgqdncxeyfazgg`
3. Look for a "Resume" or "Unpause" button
4. Click it to wake up the database
5. Wait 30-60 seconds for it to start
6. Refresh your Next.js app

---

### 2. 🌐 Internet Connection Issue

#### ✅ Solution:
1. Check your internet connection
2. Try accessing: https://supabase.com
3. If you can't access Supabase website, check your network

---

### 3. 🔒 IP Restriction or Firewall

#### ✅ Solution:
1. Go to Supabase Dashboard
2. Navigate to Settings > Database
3. Check "Connection Pooler" settings
4. Ensure your IP is allowed (or allow all IPs for development)
5. Make sure pgBouncer is enabled (it's in your connection string)

---

### 4. 🔑 Invalid Database Credentials

#### ✅ Solution:
Your current connection string:
```
postgresql://postgres.mrqytcrgqdncxeyfazgg:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres?pgbouncer=true
```

To get a fresh connection string:
1. Go to Supabase Dashboard
2. Project Settings > Database
3. Copy the "Connection Pooling" connection string
4. Update your `.env.local` with the new DATABASE_URL

---

### 5. ☁️ Supabase Service Issue

#### ✅ Solution:
1. Check Supabase status: https://status.supabase.com
2. Wait if there's an ongoing incident
3. Try again in a few minutes

---

## 🚀 Quick Fix Steps (Do This First)

### Step 1: Wake Up Your Database
```bash
# Option 1: Using Supabase Dashboard
1. Visit https://supabase.com/dashboard
2. Click on your project
3. Look for "Paused" status
4. Click "Resume Database"

# Option 2: Using Supabase CLI (if installed)
npx supabase db start
```

### Step 2: Test Connection
```bash
# Try to connect using psql (if installed)
psql "postgresql://postgres.mrqytcrgqdncxeyfazgg:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres?pgbouncer=true"

# Or test with Prisma
npx prisma db pull
```

### Step 3: Restart Your Dev Server
```bash
# Kill the current server (Ctrl+C)
# Then restart
npm run dev
```

---

## 🔧 Alternative: Use Local PostgreSQL

If you want to develop offline or avoid pausing issues:

### Option 1: Use Local PostgreSQL
```bash
# Install PostgreSQL locally
# Mac:
brew install postgresql@14
brew services start postgresql@14

# Windows:
# Download from https://www.postgresql.org/download/

# Create local database
createdb hiro_local

# Update .env.local
DATABASE_URL="postgresql://localhost:5432/hiro_local"

# Push schema
npx prisma db push
```

### Option 2: Use Docker PostgreSQL
```bash
# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: hiro
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
EOF

# Start PostgreSQL
docker-compose up -d

# Update .env.local
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/hiro"

# Push schema
npx prisma db push
```

---

## 🔍 Verify Connection

### Test 1: Prisma Studio
```bash
npx prisma studio
```
If this opens, your database is connected!

### Test 2: Database Pull
```bash
npx prisma db pull
```
If this succeeds, connection is working!

### Test 3: Simple Query
Create a test script:
```typescript
// test-db.ts
import { prisma } from './src/lib/db';

async function test() {
  try {
    const count = await prisma.user.count();
    console.log('✅ Database connected! Users:', count);
  } catch (error) {
    console.error('❌ Database error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

test();
```

Run it:
```bash
npx tsx test-db.ts
```

---

## 📞 Need More Help?

### Check Supabase Logs
1. Go to Supabase Dashboard
2. Navigate to Logs
3. Look for connection errors

### Check Network
```bash
# Test if you can reach Supabase
ping aws-1-ap-southeast-1.pooler.supabase.com

# Check port connectivity
nc -zv aws-1-ap-southeast-1.pooler.supabase.com 5432
```

### Environment Variables
```bash
# Make sure .env.local is loaded
cat .env.local | grep DATABASE_URL

# Check Next.js environment
npm run dev
# Look for environment variable logs
```

---

## ✅ After Fix Checklist

Once database is connected:

1. [ ] Can access Supabase Dashboard
2. [ ] Database shows "Active" status
3. [ ] `npx prisma studio` works
4. [ ] Dev server starts without errors
5. [ ] Can view contacts page
6. [ ] AI analysis still works

---

## 🎯 Most Likely Solution

**90% of the time, this error means your Supabase database is paused.**

**Quick Fix:**
1. Go to https://supabase.com/dashboard
2. Find your project
3. Click "Resume" or "Unpause"
4. Wait 60 seconds
5. Refresh your app

**Done!** ✅

---

**Created:** November 12, 2025  
**Issue:** Database Connection Error  
**Status:** Troubleshooting Guide

