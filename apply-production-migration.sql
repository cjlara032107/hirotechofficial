-- Production Migration: Add contactInfo and bestContactTimes columns
-- Run this on your production database to fix the P2022 errors

-- Add contactInfo column (JSONB for storing extracted contact information)
ALTER TABLE "Contact" ADD COLUMN IF NOT EXISTS "contactInfo" JSONB;

-- Add bestContactTimes column (JSONB for storing reply time analysis)
ALTER TABLE "Contact" ADD COLUMN IF NOT EXISTS "bestContactTimes" JSONB;

-- Add comments for documentation
COMMENT ON COLUMN "Contact"."contactInfo" IS 'Stores extracted contact information (age, phone, email, socials, etc.)';
COMMENT ON COLUMN "Contact"."bestContactTimes" IS 'Stores best contact times analysis with multiple estimates and days of week';

-- Verify columns were added
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'Contact' 
AND column_name IN ('contactInfo', 'bestContactTimes');



