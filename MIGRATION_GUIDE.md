# Production Migration Guide

## Issue
The production database is missing the `contactInfo` and `bestContactTimes` columns that were added to the Prisma schema. This causes Prisma errors (P2022) when the application tries to query or update contacts.

## Solution
Apply the migration to add these columns to your production database.

## Method 1: Using SQL Script (Recommended for Supabase)

1. **Connect to your Supabase database:**
   - Go to your Supabase project dashboard
   - Navigate to SQL Editor
   - Or use `psql` with your connection string

2. **Run the migration SQL:**
   ```sql
   -- Add contactInfo column (JSONB for storing extracted contact information)
   ALTER TABLE "Contact" ADD COLUMN IF NOT EXISTS "contactInfo" JSONB;

   -- Add bestContactTimes column (JSONB for storing reply time analysis)
   ALTER TABLE "Contact" ADD COLUMN IF NOT EXISTS "bestContactTimes" JSONB;

   -- Add comments for documentation
   COMMENT ON COLUMN "Contact"."contactInfo" IS 'Stores extracted contact information (age, phone, email, socials, etc.)';
   COMMENT ON COLUMN "Contact"."bestContactTimes" IS 'Stores best contact times analysis with multiple estimates and days of week';
   ```

3. **Verify the migration:**
   ```sql
   SELECT column_name, data_type 
   FROM information_schema.columns 
   WHERE table_name = 'Contact' 
   AND column_name IN ('contactInfo', 'bestContactTimes');
   ```

## Method 2: Using Node.js Script

1. **Set up environment variables:**
   - Make sure your `.env.local` or production environment has `DATABASE_URL` set

2. **Run the migration script:**
   ```bash
   node apply-production-migration.js
   ```

   Or with explicit env file:
   ```bash
   node -r dotenv/config -e "require('dotenv').config({ path: '.env.production' }); require('./apply-production-migration.js')"
   ```

## Method 3: Using Prisma Migrate (If you have direct database access)

1. **Set your production DATABASE_URL:**
   ```bash
   export DATABASE_URL="your-production-database-url"
   ```

2. **Run Prisma migrate:**
   ```bash
   npx prisma migrate deploy
   ```

   Or manually:
   ```bash
   npx prisma migrate resolve --applied add_contact_info_fields
   ```

## Verification

After applying the migration, verify it worked by:

1. **Check Vercel logs** - The P2022 errors should stop appearing
2. **Test contact analysis** - Try analyzing a contact and verify it works
3. **Check database** - Query the Contact table to see the new columns

## Temporary Workaround

The code has been updated to handle missing columns gracefully:
- Queries use `select` instead of `include` to avoid selecting non-existent fields
- Update operations catch P2022 errors and retry without the new fields
- The application will continue to work, but new features (contact info extraction, best contact times) won't be saved until the migration is applied

## After Migration

Once the migration is applied:
- Contact analysis will start saving extracted contact information
- Best contact times will be calculated and stored
- All features will work as intended

## Rollback (If Needed)

If you need to rollback (not recommended after data is stored):

```sql
ALTER TABLE "Contact" DROP COLUMN IF EXISTS "contactInfo";
ALTER TABLE "Contact" DROP COLUMN IF EXISTS "bestContactTimes";
```

**Warning:** This will delete all stored contact information and best contact times data.


