# ✅ Migration Application Instructions

**Status:** Migration files created, ready to apply

---

## 📋 What Was Done

1. ✅ **Created migration SQL file**: `prisma/migrations/20241220000000_add_risk_scoring_and_approval/migration.sql`
2. ✅ **Generated Prisma Client**: New types are available (`ApprovalStatus` enum)
3. ✅ **Created migration script**: `scripts/apply-risk-scoring-migration.ts` (alternative method)

---

## 🚀 How to Apply the Migration

### Option 1: Using Prisma Migrate (Recommended)

**Prerequisites:**
- Set `DATABASE_URL` and `DIRECT_URL` environment variables

**Steps:**

1. **Set Environment Variables**

   Create or update your `.env` or `.env.local` file:
   ```env
   DATABASE_URL="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
   DIRECT_URL="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"
   ```

   **Note:** 
   - `DATABASE_URL` uses port **6543** with `?pgbouncer=true` (for connection pooling)
   - `DIRECT_URL` uses port **5432** without `?pgbouncer=true` (for migrations)

2. **Run Migration**
   ```bash
   npx prisma migrate deploy
   ```

   Or for development:
   ```bash
   npx prisma migrate dev --name add_risk_scoring_and_approval
   ```

3. **Verify Migration**
   ```bash
   npx prisma studio
   ```
   Check that the `Contact` table has the new columns:
   - `riskScore`
   - `riskLevel`
   - `approvalStatus`
   - `riskReasons`
   - `approvedAt`, `approvedBy`
   - `rejectedAt`, `rejectedBy`
   - `feedback`, `feedbackAt`

---

### Option 2: Using Migration Script (If DIRECT_URL Not Available)

**Steps:**

1. **Set DATABASE_URL** in your environment:
   ```env
   DATABASE_URL="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
   ```

2. **Run the script:**
   ```bash
   npx tsx scripts/apply-risk-scoring-migration.ts
   ```

   This script will:
   - Create the `ApprovalStatus` enum
   - Add all new columns to the `Contact` table
   - Create all necessary indexes
   - Skip if columns/indexes already exist (safe to run multiple times)

---

### Option 3: Manual SQL Execution (If Both Options Fail)

If you have direct database access, you can run the SQL manually:

**File:** `prisma/migrations/20241220000000_add_risk_scoring_and_approval/migration.sql`

1. Connect to your database (via Supabase dashboard or psql)
2. Copy the contents of the migration file
3. Execute the SQL directly

---

## ✅ Verification

After applying the migration, verify:

1. **Check Prisma Client Types:**
   ```typescript
   import { ApprovalStatus } from '@prisma/client';
   // Should work without errors
   ```

2. **Check Database Schema:**
   ```sql
   SELECT column_name, data_type 
   FROM information_schema.columns 
   WHERE table_name = 'Contact' 
   AND column_name IN ('riskScore', 'approvalStatus', 'riskReasons');
   ```

3. **Test the Code:**
   - Sync contacts (should calculate risk scores)
   - Check `/contacts/approval-queue` (should show pending contacts)

---

## 🎯 What the Migration Adds

### New Enum:
- `ApprovalStatus`: `PENDING`, `APPROVED`, `REJECTED`, `AUTO_APPROVED`

### New Columns in Contact Table:
- `riskScore` (INTEGER) - Risk score 0-100
- `riskLevel` (TEXT) - LOW, MEDIUM, HIGH, CRITICAL
- `approvalStatus` (ApprovalStatus) - Approval status
- `riskReasons` (TEXT[]) - Array of risk reasons
- `approvedAt` (TIMESTAMP) - When approved
- `approvedBy` (TEXT) - User ID who approved
- `rejectedAt` (TIMESTAMP) - When rejected
- `rejectedBy` (TEXT) - User ID who rejected
- `feedback` (TEXT) - User feedback
- `feedbackAt` (TIMESTAMP) - When feedback was given

### New Indexes:
- `Contact_approvalStatus_idx`
- `Contact_riskScore_idx`
- `Contact_organizationId_approvalStatus_idx`
- `Contact_organizationId_riskScore_idx`

---

## 🚨 Important Notes

1. **Backup First**: Always backup your database before running migrations
2. **Test Environment**: Test in a development/staging environment first
3. **Downtime**: This migration is non-destructive (only adds columns), so minimal downtime
4. **Rollback**: If needed, you can rollback by dropping the columns and enum

---

## 📝 Next Steps After Migration

1. ✅ **Code is ready** - All TypeScript code is already updated
2. ✅ **Prisma Client generated** - Types are available
3. ⏳ **Apply migration** - Run one of the options above
4. ✅ **Test sync** - Sync contacts and verify risk scores are calculated
5. ✅ **Test approval queue** - Navigate to `/contacts/approval-queue`

---

## 🎉 Summary

**Migration Status:** ✅ Ready to apply

**Files Created:**
- ✅ Migration SQL: `prisma/migrations/20241220000000_add_risk_scoring_and_approval/migration.sql`
- ✅ Migration Script: `scripts/apply-risk-scoring-migration.ts`
- ✅ Prisma Client: Generated with new types

**Action Required:**
- Set `DATABASE_URL` and `DIRECT_URL` environment variables
- Run migration using one of the options above

**After Migration:**
- All code will work automatically
- Risk scoring will be calculated during sync
- Approval queue will be available at `/contacts/approval-queue`

