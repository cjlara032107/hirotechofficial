@echo off
echo ================================================
echo   NGROK TUNNEL STARTER
echo ================================================
echo.

REM Check if ngrok.exe exists
if not exist "ngrok.exe" (
    echo [ERROR] ngrok.exe not found!
    echo.
    echo Please download ngrok from: https://ngrok.com/download
    echo Place ngrok.exe in the project root directory.
    echo.
    pause
    exit /b 1
)

REM Check if ngrok is already running
tasklist /FI "IMAGENAME eq ngrok.exe" 2>NUL | find /I /N "ngrok.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [WARNING] Ngrok is already running!
    echo.
    echo To stop it, run: stop-ngrok.bat
    echo Or manually: taskkill /F /IM ngrok.exe
    echo.
    pause
    exit /b 0
)

REM Check if dev server is running on port 3000
netstat -an | findstr ":3000" >nul
if "%ERRORLEVEL%"=="0" (
    echo [INFO] Dev server detected on port 3000
) else (
    echo [WARNING] No server detected on port 3000
    echo Make sure to start your dev server: npm run dev
    echo.
)

echo.
echo [INFO] Starting ngrok tunnel on port 3000...
echo [INFO] Log file: ngrok.log
echo.
echo ================================================
echo   Keep this window open to keep tunnel active!
echo   Press Ctrl+C to stop ngrok
echo ================================================
echo.

REM Start ngrok
start "Ngrok Tunnel" ngrok.exe http 3000 --log ngrok.log

REM Wait a moment for ngrok to start
timeout /t 3 /nobreak >nul

REM Try to get the URL from ngrok API
echo [INFO] Fetching ngrok URL...
curl -s http://localhost:4040/api/tunnels > temp_ngrok.json 2>nul

if exist temp_ngrok.json (
    REM Try to extract URL (basic parsing)
    findstr /C:"public_url" temp_ngrok.json >nul
    if "%ERRORLEVEL%"=="0" (
        echo.
        echo ================================================
        echo   NGROK TUNNEL STARTED!
        echo ================================================
        echo.
        echo Check http://localhost:4040 for your public URL
        echo.
        echo Next steps:
        echo 1. Copy the HTTPS URL from ngrok dashboard
        echo 2. Update .env.local with:
        echo    NEXT_PUBLIC_APP_URL=https://your-url.ngrok-free.dev
        echo    NEXTAUTH_URL=https://your-url.ngrok-free.dev
        echo 3. Update Facebook App settings
        echo 4. Restart dev server
        echo.
    ) else (
        echo [INFO] Ngrok is starting... Check http://localhost:4040
    )
    del temp_ngrok.json 2>nul
) else (
    echo [INFO] Ngrok is starting... Check http://localhost:4040
)

echo.
echo Ngrok Dashboard: http://localhost:4040
echo.
pause









