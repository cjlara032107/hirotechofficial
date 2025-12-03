# Multi-Database Routing Setup Guide

## ✅ Implementation Complete

The multi-database routing system has been implemented and is ready to use. Your current Supabase database is configured as `DATABASE_URL_0`.

## 📋 Current Status

- ✅ Multi-database router created (`src/lib/db/multi-db-router.ts`)
- ✅ Updated `db.ts` to support both single and multi-DB modes
- ✅ Health check endpoint created (`/api/health/db-router`)
- ✅ Migration script created (`scripts/migrate-all-databases.ts`)
- ✅ Helper function for organization-based routing (`getPrismaForOrg`)
- ✅ Example route updated (contacts API)

## 🚀 Quick Start

### Step 1: Configure Environment Variables

Add to your `.env.local`:

```bash
# Start with single database (your current setup)
ENABLE_MULTI_DB=false
DB_COUNT=1

# Your current database as DB 0
DATABASE_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"

# Keep existing for backward compatibility
DATABASE_URL="${DATABASE_URL_0}"
DIRECT_URL="${DIRECT_URL_0}"
```

### Step 2: Test Current Setup

```bash
npm run dev
```

Visit: `http://localhost:3000/api/health/db-router`

You should see:
```json
{
  "success": true,
  "multiDbEnabled": false,
  "message": "Single database mode"
}
```

### Step 3: When Ready to Add More Databases

1. **Create 4 more Supabase projects** (free tier is fine to start)
   - Go to https://supabase.com/dashboard
   - Create new projects: `hiro-db-1`, `hiro-db-2`, `hiro-db-3`, `hiro-db-4`

2. **Get connection strings** from each project:
   - Dashboard → Settings → Database
   - Copy "Connection Pooling" URL (port 6543) for `DATABASE_URL_X`
   - Copy "Direct Connection" URL (port 5432) for `DIRECT_URL_X`

3. **Update `.env.local`**:
   ```bash
   ENABLE_MULTI_DB=true
   DB_COUNT=5
   DB_ROUTING_STRATEGY=hash
   
   # Database 0 (your current one - already set)
   DATABASE_URL_0="..."
   DIRECT_URL_0="..."
   
   # Database 1
   DATABASE_URL_1="postgresql://postgres.[ref1]:[pass]@pooler.supabase.com:6543/postgres?pgbouncer=true"
   DIRECT_URL_1="postgresql://postgres.[ref1]:[pass]@pooler.supabase.com:5432/postgres"
   
   # Database 2
   DATABASE_URL_2="..."
   DIRECT_URL_2="..."
   
   # Database 3
   DATABASE_URL_3="..."
   DIRECT_URL_3="..."
   
   # Database 4
   DATABASE_URL_4="..."
   DIRECT_URL_4="..."
   ```

4. **Run migrations on all databases**:
   ```bash
   npx tsx scripts/migrate-all-databases.ts
   ```

5. **Restart your dev server**:
   ```bash
   npm run dev
   ```

6. **Verify multi-DB is working**:
   - Visit: `http://localhost:3000/api/health/db-router`
   - Should show 5 databases with health status

## 📊 Connection Pool Capacity

With 5 databases:

| Supabase Tier | Total Pooled Connections |
|---------------|-------------------------|
| Free (5 × Free) | 1,000 connections |
| Pro + Small (5 × Small) | 2,000 connections |
| Pro + Medium (5 × Medium) | 3,000 connections |

**Per-instance limit**: 20 connections (Vercel)
- 5 databases × 20 = 100 connections per Vercel instance
- With 10 instances: 1,000 total connections (perfect for free tier)

## 🔧 How It Works

### Routing Strategy

**Hash-based (default)**: Routes based on `organizationId`
- Same organization always goes to same database
- Keeps related data together
- Best for your use case

**Usage in API routes**:
```typescript
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';

// Automatically routes to correct database
const prisma = getPrismaForOrg(session.user.organizationId);
const contacts = await prisma.contact.findMany({...});
```

### Backward Compatibility

Existing code using `prisma` directly will still work:
- **Single-DB mode**: Uses your current database
- **Multi-DB mode**: Uses round-robin (distributes evenly)

For optimal routing, use `getPrismaForOrg(organizationId)`.

## 📁 Files Created

1. `src/lib/db/multi-db-router.ts` - Main router implementation
2. `src/lib/db/get-prisma-for-org.ts` - Helper for organization routing
3. `src/app/api/health/db-router/route.ts` - Health check endpoint
4. `scripts/migrate-all-databases.ts` - Migration script
5. `.env.multi-db.example` - Environment variables template

## 🔍 Monitoring

### Health Check Endpoint

```bash
GET /api/health/db-router
```

Returns:
```json
{
  "success": true,
  "multiDbEnabled": true,
  "status": {
    "totalDatabases": 5,
    "healthyDatabases": 5,
    "degradedDatabases": 0,
    "downDatabases": 0,
    "routingStrategy": "hash",
    "databases": [...]
  }
}
```

### Logs

Watch for these log messages:
- `[Multi-DB Router] 🚀 Initializing X databases...`
- `[Multi-DB Router] ✅ Ready with X databases using hash routing`
- `[DB] ✅ Multi-database routing enabled`

## ⚠️ Important Notes

1. **Data Distribution**: When you enable multi-DB, existing data stays in DB 0. New data will be distributed based on `organizationId` hash.

2. **Migrations**: Always run migrations on ALL databases when schema changes:
   ```bash
   npx tsx scripts/migrate-all-databases.ts
   ```

3. **Cross-Database Queries**: Not supported. If you need to join data across organizations, query separately and merge in code.

4. **Rollback**: To disable multi-DB, set `ENABLE_MULTI_DB=false` and restart.

## 🎯 Next Steps

1. Test with current single database (ENABLE_MULTI_DB=false)
2. Create 4 more Supabase projects when ready
3. Add connection strings to `.env.local`
4. Enable multi-DB (ENABLE_MULTI_DB=true)
5. Run migrations on all databases
6. Monitor health endpoint

## 📞 Troubleshooting

### "No databases configured" error
- Check that `DATABASE_URL_0` is set
- Verify `DB_COUNT` matches number of databases

### Health check shows databases as "down"
- Verify connection strings are correct
- Check Supabase projects are active
- Ensure network connectivity

### Migrations fail
- Verify `DIRECT_URL_X` is set for each database
- Check database credentials are correct
- Ensure you have migration permissions

---

**Status**: ✅ Ready to use with single database. Add more databases when needed!




