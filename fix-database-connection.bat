@echo off
echo ====================================
echo Database Connection Pool Fix
echo ====================================
echo.

echo [1/5] Checking environment variables...
if not defined DATABASE_URL (
    echo ERROR: DATABASE_URL not set!
    echo Please add DATABASE_URL to your .env.local file
    echo Format: postgresql://...@host:6543/postgres?pgbouncer=true
    pause
    exit /b 1
)

if not defined DIRECT_URL (
    echo ERROR: DIRECT_URL not set!
    echo Please add DIRECT_URL to your .env.local file
    echo Format: postgresql://...@host:5432/postgres
    pause
    exit /b 1
)

echo OK: Environment variables found
echo.

echo [2/5] Clearing Next.js cache...
if exist .next (
    rmdir /s /q .next
    echo OK: Cache cleared
) else (
    echo OK: No cache to clear
)
echo.

echo [3/5] Clearing Prisma client cache...
if exist node_modules\.prisma (
    rmdir /s /q node_modules\.prisma
    echo OK: Prisma cache cleared
) else (
    echo OK: No Prisma cache to clear
)
echo.

echo [4/5] Regenerating Prisma Client...
call npx prisma generate
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to generate Prisma Client
    pause
    exit /b 1
)
echo OK: Prisma Client regenerated
echo.

echo [5/5] Starting development server...
echo.
echo ====================================
echo Fix Applied Successfully!
echo ====================================
echo.
echo Next steps:
echo 1. Verify your .env.local has correct URLs
echo 2. DATABASE_URL should use port 6543 (pooled)
echo 3. DIRECT_URL should use port 5432 (direct)
echo.
echo Starting server now...
echo.

call npm run dev

