-- Add media columns to Campaign table
ALTER TABLE "Campaign" 
ADD COLUMN IF NOT EXISTS "mediaUrl" TEXT,
ADD COLUMN IF NOT EXISTS "mediaType" TEXT;









