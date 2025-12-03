@echo off
echo ================================================
echo   STOPPING NGROK TUNNEL
echo ================================================
echo.

REM Check if ngrok is running
tasklist /FI "IMAGENAME eq ngrok.exe" 2>NUL | find /I /N "ngrok.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [INFO] Stopping ngrok...
    taskkill /F /IM ngrok.exe >nul 2>&1
    
    if "%ERRORLEVEL%"=="0" (
        echo [SUCCESS] Ngrok stopped successfully
    ) else (
        echo [ERROR] Failed to stop ngrok
    )
) else (
    echo [INFO] Ngrok is not running
)

echo.
pause









