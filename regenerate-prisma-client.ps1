# Regenerate Prisma Client Script
# This script regenerates the Prisma client after migration

Write-Host "Regenerating Prisma Client..." -ForegroundColor Cyan

# Check if Prisma client file is locked
$prismaClientPath = "node_modules\.prisma\client\query_engine-windows.dll.node"
if (Test-Path $prismaClientPath) {
    Write-Host "Note: If you get a file lock error, stop your dev server first." -ForegroundColor Yellow
}

# Load environment variables
if (Test-Path .env.local) {
    Get-Content .env.local | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            $key = $matches[1]
            $value = $matches[2] -replace '^"|"$', ''
            [Environment]::SetEnvironmentVariable($key, $value, 'Process')
        }
    }
}

# Set DIRECT_URL if not set
if (-not $env:DIRECT_URL -and $env:DATABASE_URL) {
    $env:DIRECT_URL = $env:DATABASE_URL
}

# Regenerate Prisma client
Write-Host "Running: npx prisma generate" -ForegroundColor Cyan
npx prisma generate

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nPrisma client regenerated successfully!" -ForegroundColor Green
    Write-Host "You can now use the new enhanced AI fields in your application." -ForegroundColor Green
} else {
    Write-Host "`nError regenerating Prisma client." -ForegroundColor Red
    Write-Host "If you see a file lock error (EPERM), please:" -ForegroundColor Yellow
    Write-Host "1. Stop your dev server (Ctrl+C)" -ForegroundColor Yellow
    Write-Host "2. Run this script again" -ForegroundColor Yellow
    Write-Host "3. Restart your dev server" -ForegroundColor Yellow
    exit 1
}













