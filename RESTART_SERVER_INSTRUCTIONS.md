# Server Restart Instructions

## Issue
All API routes are returning 500 Internal Server Error, even simple test routes.

## Solution
The Next.js dev server needs to be restarted to pick up the middleware and route changes.

## Steps to Restart

1. **Stop the current dev server:**
   - In the terminal running `npm run dev`, press `Ctrl+C`
   - Wait for it to fully stop

2. **Kill any remaining Node processes (if needed):**
   ```bash
   taskkill /F /IM node.exe
   ```

3. **Clear Next.js cache (optional but recommended):**
   ```bash
   rmdir /s /q .next
   ```

4. **Restart the dev server:**
   ```bash
   npm run dev
   ```

5. **Wait for the server to start:**
   - Look for "Ready" message
   - Check for any compilation errors

6. **Test the health endpoint:**
   - Visit: `http://localhost:3000/api/test`
   - Should return: `{"ok":true,"message":"Test route working"}`

## What Was Fixed

1. **Middleware** - Now allows all `/api/*` routes to bypass it completely
2. **Health Route** - Removed database imports that could cause startup errors
3. **Error Handling** - Added comprehensive try-catch blocks

## If Still Getting 500 Errors

Check the terminal output for:
- TypeScript compilation errors
- Module import errors
- Database connection errors
- Missing environment variables

The middleware should now be completely bypassed for API routes, so the error is likely in:
- Route handler code
- Module imports
- Build/compilation issues








