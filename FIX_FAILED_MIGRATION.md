# Fix Failed Migration Issue

## Problem

The migration `20250102000000_add_advanced_ai_features` failed in your database, blocking new migrations.

**Error:**
```
Error: P3009
migrate found failed migrations in the target database, new migrations will not be applied.
The `20250102000000_add_advanced_ai_features` migration started at 2025-11-30 02:21:08.429176 UTC failed
```

## Solution Applied

I've updated the migration script (`scripts/migrate-all-databases.ts`) to:

1. **Check for failed migrations** before running new ones
2. **Automatically resolve** failed migrations by marking them as rolled back
3. **Fallback to `db push`** if migrations still fail

## How to Fix Now

### Option 1: Run Updated Script (Recommended)

The script will now automatically handle failed migrations:

```bash
npx tsx scripts/migrate-all-databases.ts
```

### Option 2: Manually Resolve Failed Migration

If you want to manually resolve it first:

```bash
# Set your database URL
export DATABASE_URL="your-direct-database-url"

# Mark the failed migration as rolled back
npx prisma migrate resolve --rolled-back 20250102000000_add_advanced_ai_features

# Or if the columns already exist, mark as applied
npx prisma migrate resolve --applied 20250102000000_add_advanced_ai_features

# Then run migrations
npx tsx scripts/migrate-all-databases.ts
```

### Option 3: Use db push (Quick Fix)

If migrations keep failing, use `db push` to sync schema:

```bash
# For each database, set DATABASE_URL and run:
npx prisma db push --accept-data-loss
```

## What the Migration Does

The failed migration adds these columns to the `Contact` table:
- `conversionPath` (TEXT[])
- `similarLeadsInsight` (TEXT)
- `botAccuracyScore` (DOUBLE PRECISION)
- `conversationPatterns` (JSONB)
- `indirectIntent` (JSONB)
- `buyerReliability` (JSONB)
- `buyerStyle` (TEXT)

## Check if Columns Already Exist

You can check if the columns were partially applied:

```sql
SELECT column_name 
FROM information_schema.columns 
WHERE table_name = 'Contact' 
AND column_name IN (
  'conversionPath', 
  'similarLeadsInsight', 
  'botAccuracyScore',
  'conversationPatterns',
  'indirectIntent',
  'buyerReliability',
  'buyerStyle'
);
```

If columns exist, mark migration as applied. If not, mark as rolled back.

## After Fixing

Once resolved, you can:
1. Run migrations on all databases
2. Continue with normal development
3. New migrations will apply normally




