@echo off
echo ========================================
echo Production Database Migration
echo ========================================
echo.
echo This script will add the contactInfo and bestContactTimes
echo columns to your Contact table in the production database.
echo.
echo Make sure your DATABASE_URL is set in .env.local
echo.
pause

echo.
echo Running migration...
echo.

node apply-production-migration.js

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Migration completed successfully!
    echo ========================================
) else (
    echo.
    echo ========================================
    echo Migration failed! Check the error above.
    echo ========================================
)

pause


