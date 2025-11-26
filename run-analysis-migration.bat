@echo off
echo Running database migration for AnalysisJob model...
echo.

REM Check if .env file exists
if not exist .env (
    echo ERROR: .env file not found!
    echo.
    echo Please create a .env file with the following variables:
    echo   DATABASE_URL=your_database_connection_string
    echo   DIRECT_URL=your_direct_database_connection_string
    echo.
    pause
    exit /b 1
)

echo Applying migration...
npx prisma migrate deploy

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Migration completed successfully!
    echo.
) else (
    echo.
    echo Migration failed. Please check the error messages above.
    echo.
)

pause


