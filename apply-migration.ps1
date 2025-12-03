# Migration Application Script
# This script applies the database migration for enhanced AI fields

Write-Host "Applying database migration..." -ForegroundColor Cyan

# Check if DATABASE_URL is set
if (-not $env:DATABASE_URL) {
    Write-Host "ERROR: DATABASE_URL environment variable is not set." -ForegroundColor Red
    Write-Host "Please set DATABASE_URL in your environment or .env file." -ForegroundColor Yellow
    exit 1
}

# Set DIRECT_URL to DATABASE_URL if not already set (for non-pooled connections)
if (-not $env:DIRECT_URL) {
    Write-Host "DIRECT_URL not set. Using DATABASE_URL as DIRECT_URL..." -ForegroundColor Yellow
    $env:DIRECT_URL = $env:DATABASE_URL
}

# Apply migration
Write-Host "Running: npx prisma migrate deploy" -ForegroundColor Cyan
npx prisma migrate deploy

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nMigration applied successfully!" -ForegroundColor Green
    Write-Host "Regenerating Prisma client..." -ForegroundColor Cyan
    npx prisma generate
    Write-Host "`nDone! All enhanced AI fields have been added to the database." -ForegroundColor Green
} else {
    Write-Host "`nMigration failed. Please check the error messages above." -ForegroundColor Red
    exit 1
}













