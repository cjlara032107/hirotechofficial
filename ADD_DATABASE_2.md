# Adding Database 2 Configuration

## Your Database 2 Connection Strings

Based on your Supabase project `vivelzjlltbytnhybdcm`, here are the formatted connection strings:

### Pooled Connection (for application queries)
```bash
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
```

### Direct Connection (for migrations)
```bash
DIRECT_URL_1="postgresql://postgres:demet5732595@db.vivelzjlltbytnhybdcm.supabase.co:5432/postgres"
```

**Note**: The pooled connection uses:
- `pooler.` instead of `db.`
- Port `6543` instead of `5432`
- `?pgbouncer=true` query parameter
- Username format: `postgres.[project-ref]` instead of just `postgres`

## Where to Add This

Add these lines to your `.env.local` file:

```bash
# Database 1 (your new Supabase project)
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
DIRECT_URL_1="postgresql://postgres:demet5732595@db.vivelzjlltbytnhybdcm.supabase.co:5432/postgres"
```

## Important: Get the Correct Pooled URL

The pooled connection string format above is an estimate. **To get the exact pooled connection string:**

1. Go to your Supabase Dashboard: https://vivelzjlltbytnhybdcm.supabase.co
2. Navigate to: **Settings** → **Database**
3. Scroll to **Connection Pooling** section
4. Under **Transaction mode**, copy the connection string
5. It should look like:
   ```
   postgresql://postgres.vivelzjlltbytnhybdcm:[YOUR-PASSWORD]@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true
   ```

## Complete .env.local Example

After adding Database 2, your `.env.local` should have:

```bash
# Multi-Database Configuration
ENABLE_MULTI_DB=true
DB_COUNT=2
DB_ROUTING_STRATEGY=hash

# Database 0 (your original Supabase)
DATABASE_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL_0="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"

# Database 1 (your new Supabase - Database 2)
DATABASE_URL_1="postgresql://postgres.vivelzjlltbytnhybdcm:demet5732595@pooler.vivelzjlltbytnhybdcm.supabase.co:6543/postgres?pgbouncer=true"
DIRECT_URL_1="postgresql://postgres:demet5732595@db.vivelzjlltbytnhybdcm.supabase.co:5432/postgres"

# Fallback (for backward compatibility)
DATABASE_URL="${DATABASE_URL_0}"
DIRECT_URL="${DIRECT_URL_0}"
```

## After Adding Database 2

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

## Connection Capacity

With 2 databases:
- **Free tier**: 2 × 200 = **400 pooled connections**
- **Per instance**: 2 × 20 = **40 connections per Vercel instance**
- **Supports**: ~10 concurrent Vercel instances




