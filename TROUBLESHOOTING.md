# Troubleshooting Guide - Internal Server Errors

## 🚨 Quick Diagnosis

If you're experiencing **500 Internal Server Error**, follow this flowchart:

```
500 Error → Run Diagnostics → Check Results → Apply Fix
     ↓
npm run diagnose
     ↓
View Report
     ↓
[FAILED] → Run quick-fix.bat
[PASSED] → Check specific issue
```

## 🔧 Common Issues & Solutions

### 1. Prisma Client Lock (MOST COMMON)

**Symptoms:**
- 500 error on all pages
- Login fails
- Registration fails
- `npx prisma generate` fails with EPERM error

**Cause:**
- Multiple Node.js processes running
- Files locked by crashed processes

**Solution:**
```bash
.\quick-fix.bat
```

**Manual Steps:**
1. `taskkill /F /IM node.exe /T`
2. `npm run clean-prisma`
3. `npx prisma generate`
4. `npm run dev`

---

### 2. Missing Environment Variables

**Symptoms:**
- 500 error on specific routes
- "Missing required fields" errors
- Facebook integration fails

**Diagnosis:**
```bash
npm run diagnose
# or
curl http://localhost:3000/api/test-env
```

**Solution:**
Create `.env.local` with:

```env
DATABASE_URL="postgresql://user:password@localhost:5432/dbname"
NEXTAUTH_SECRET="your-secret-min-32-chars"
NEXT_PUBLIC_SUPABASE_URL="https://your-project.supabase.co"
NEXT_PUBLIC_SUPABASE_ANON_KEY="your-anon-key"
FACEBOOK_APP_ID="your-app-id"
FACEBOOK_APP_SECRET="your-app-secret"
REDIS_URL="redis://localhost:6379"
```

---

### 3. Database Connection Failed

**Symptoms:**
- "Can't reach database server"
- "P1001: Can't reach database server"
- 500 on login/register

**Diagnosis:**
```bash
npx prisma studio
# If fails, database is not running
```

**Solution:**
1. Start PostgreSQL service
2. Verify DATABASE_URL is correct
3. Test connection: `npx prisma db push`

**Windows:**
```bash
# Check if PostgreSQL is running
tasklist | findstr "postgres"

# Start PostgreSQL service
net start postgresql-x64-14
```

---

### 4. Prisma Client Out of Sync

**Symptoms:**
- "Invalid prisma.user.findUnique() invocation"
- "Unknown field" errors
- Type errors in IDE

**Solution:**
```bash
npx prisma generate
npx prisma db push
npm run dev
```

---

### 5. Redis Connection Failed

**Symptoms:**
- Campaigns don't send
- Worker crashes
- "ECONNREFUSED" errors

**Diagnosis:**
```bash
redis-cli ping
# Should return: PONG
```

**Solution:**

**Windows:**
```bash
# Navigate to redis-server folder
cd redis-server
.\redis-server.exe
```

**Or use Docker:**
```bash
docker run -d -p 6379:6379 redis:alpine
```

---

### 6. Port Already in Use

**Symptoms:**
- "Port 3000 is already in use"
- Server fails to start

**Solution:**
```bash
# Find process using port 3000
netstat -ano | findstr :3000

# Kill the process (replace PID with actual PID)
taskkill /PID <PID> /F
```

---

### 7. Module Not Found Errors

**Symptoms:**
- "Cannot find module '@prisma/client'"
- "Cannot find module 'bcrypt'"
- Build fails

**Solution:**
```bash
# Clean install
rm -rf node_modules
npm install

# Regenerate Prisma
npx prisma generate
```

---

### 8. TypeScript Errors

**Symptoms:**
- Type errors in IDE
- Build fails with TS errors
- "Property does not exist" errors

**Solution:**
```bash
# Regenerate types
npx prisma generate

# Restart TypeScript server in VS Code
Ctrl+Shift+P → TypeScript: Restart TS Server
```

---

### 9. NextAuth Session Issues

**Symptoms:**
- Constantly redirected to login
- Session not persisting
- "Invalid session" errors

**Solution:**

1. **Check NEXTAUTH_SECRET:**
   ```bash
   # Generate new secret
   openssl rand -base64 32
   ```

2. **Clear cookies:**
   - Open DevTools → Application → Cookies
   - Clear all `next-auth.*` cookies

3. **Check middleware:**
   Ensure `src/middleware.ts` is not blocking API routes

---

### 10. Facebook OAuth Redirect Issues

**Symptoms:**
- Redirects to localhost instead of production
- "URL Blocked" by Facebook
- OAuth flow fails

**Solution:**

1. **Set NEXT_PUBLIC_APP_URL:**
   ```env
   NEXT_PUBLIC_APP_URL=https://your-domain.com
   ```

2. **Update Facebook App:**
   - Go to developers.facebook.com
   - Add OAuth redirect URIs:
     - `https://your-domain.com/api/facebook/callback`
     - `https://your-domain.com/api/facebook/callback-popup`

3. **Restart server** to load new env vars

---

## 🛠️ Diagnostic Tools

### 1. Full System Diagnosis
```bash
npm run diagnose
```

Checks:
- Environment files
- Environment variables
- Node modules
- Prisma client
- Database connection
- Redis connection
- Running processes

### 2. Test Environment Variables
```bash
curl http://localhost:3000/api/test-env
```

### 3. Check Database
```bash
npx prisma studio
```

### 4. Check Running Processes
```bash
tasklist | findstr "node.exe"
```

### 5. Check Logs
```bash
# Start with full logging
npm run dev 2>&1 | tee dev.log
```

---

## 🔄 Reset Everything

If nothing else works, nuclear option:

```bash
# 1. Stop all processes
.\stop-all.bat

# 2. Clean everything
rmdir /s /q node_modules
rmdir /s /q .next
npm run clean-prisma

# 3. Reinstall
npm install

# 4. Setup database
npx prisma generate
npx prisma db push

# 5. Restart
npm run dev
```

---

## 📊 Error Code Reference

### HTTP 500 - Internal Server Error
**Common Causes:**
1. Prisma client not generated
2. Database connection failed
3. Missing environment variables
4. File permissions error
5. Module not found

**First Step:** Run `npm run diagnose`

### HTTP 401 - Unauthorized
**Common Causes:**
1. Invalid credentials
2. Session expired
3. NEXTAUTH_SECRET mismatch

**Fix:** Clear cookies and log in again

### HTTP 400 - Bad Request
**Common Causes:**
1. Invalid request body
2. Missing required fields
3. Validation errors

**Fix:** Check API request format

### HTTP 404 - Not Found
**Common Causes:**
1. Wrong URL
2. Route not defined
3. API route file missing

**Fix:** Check route definition

---

## 🎯 Prevention Checklist

Before starting development:

- [ ] `.env.local` file exists with all required vars
- [ ] PostgreSQL is running
- [ ] Redis is running (for campaigns)
- [ ] No other Node processes running
- [ ] Prisma client is generated
- [ ] Dependencies are installed

To stop development:

- [ ] Press `Ctrl+C` in dev server terminal
- [ ] Press `Ctrl+C` in worker terminal
- [ ] Wait for "Server closed" message
- [ ] Close terminals properly

Weekly maintenance:

- [ ] Run `npm run clean-prisma`
- [ ] Run `npm install`
- [ ] Run `npx prisma generate`
- [ ] Check for updates

---

## 🆘 Still Having Issues?

### 1. Check Documentation
- `FIX_INTERNAL_SERVER_ERROR.md` - Detailed fix guide
- `DIAGNOSIS_SUMMARY.md` - Root cause analysis
- `ENV_SETUP_GUIDE.md` - Environment setup

### 2. Run Full Diagnostic
```bash
npm run diagnose
```

### 3. Check Specific Components

**Database:**
```bash
npx prisma studio
```

**Auth:**
```bash
curl http://localhost:3000/api/auth/session
```

**Facebook:**
```bash
curl http://localhost:3000/api/debug/facebook-config
```

### 4. Enable Debug Mode
```bash
set DEBUG=*
npm run dev
```

### 5. Check System Services

**PostgreSQL:**
```bash
net start postgresql-x64-14
```

**Redis:**
```bash
cd redis-server
.\redis-server.exe
```

---

## 📝 Reporting Issues

If you still have issues, gather this info:

1. **Error message** (full stack trace)
2. **npm run diagnose** output
3. **Browser console errors** (F12 → Console)
4. **Network tab** (F12 → Network)
5. **Environment** (OS, Node version, npm version)
6. **Steps to reproduce**

Run diagnostics:
```bash
npm run diagnose > diagnosis.txt
node --version >> diagnosis.txt
npm --version >> diagnosis.txt
```

Attach `diagnosis.txt` when reporting issues.

---

## ✅ Health Check Commands

```bash
# Quick health check
npm run diagnose

# Full system check
npm run diagnose && \
npx prisma generate && \
npx prisma db push --skip-generate && \
npm run dev
```

---

---

## 📱 Facebook & Instagram Integration Issues

### 11. Facebook API Errors

**Common Error Codes:**

| Code | Meaning | Solution |
|------|---------|----------|
| **190** | Access token expired | Reconnect Facebook page in Settings |
| **200** | Permission denied | Check required permissions in Facebook App |
| **100** | Invalid parameter | Contact may have blocked page or deleted account |
| **613** | Rate limit exceeded | Wait 5-10 minutes, then retry |
| **4** | Rate limit (alternative) | Wait 5-10 minutes, then retry |
| **17** | Rate limit (alternative) | Wait 5-10 minutes, then retry |
| **10903** | Outside 24hr window | Use appropriate message tag |
| **10** | User privacy restriction | Contact opted out of messaging |

**Diagnosis:**
```bash
# Check Facebook connection status
curl http://localhost:3000/api/facebook/pages/connected

# Test Facebook credentials
npm run validate:env
```

**Solution:**
1. **Token Expired (190):**
   - Go to Settings > Integrations
   - Disconnect and reconnect Facebook page
   - Re-authenticate with required permissions

2. **Rate Limited (613, 4, 17):**
   - Wait 5-10 minutes
   - Reduce campaign sending speed
   - Check campaign rate limit settings

3. **Permission Error (200, 10):**
   - Verify Facebook App has required permissions:
     - `pages_messaging`
     - `pages_manage_metadata`
     - `pages_read_engagement`
     - `instagram_basic` (for Instagram)
     - `instagram_manage_messages` (for Instagram)

---

### 12. Campaign Not Sending Messages

**Symptoms:**
- Campaign stuck in "SENDING" status
- Messages show as "PENDING"
- No error messages displayed

**Diagnosis:**
```bash
# Check if BullMQ worker is running
# Worker should be started separately:
node -r esbuild-register src/lib/campaigns/worker.ts

# Check Redis connection
npm run test:redis

# Check campaign status
curl http://localhost:3000/api/campaigns
```

**Solution:**

1. **Start BullMQ Worker:**
   ```bash
   # In separate terminal
   node -r esbuild-register src/lib/campaigns/worker.ts
   ```

2. **Check Redis:**
   ```bash
   # Windows
   cd redis-server
   .\redis-server.exe
   
   # Or Docker
   docker run -d -p 6379:6379 redis:alpine
   ```

3. **Fix Stuck Campaigns:**
   ```bash
   npm run fix:campaigns
   ```

4. **Check Campaign Logs:**
   - View browser console for errors
   - Check server logs for API errors
   - Verify Facebook page access token is valid

---

### 13. Contact Sync Issues

**Symptoms:**
- Sync takes too long or hangs
- Contacts not appearing after sync
- "Failed to sync contact" errors
- Sync shows 0 contacts

**Diagnosis:**
```bash
# Check sync status
curl http://localhost:3000/api/facebook/sync

# Test Facebook API access
curl http://localhost:3000/api/debug/facebook-config
```

**Common Causes:**

1. **AI Analysis Slowdown:**
   - AI analysis takes 5-10 seconds per contact
   - For 100 contacts: 8-17 minutes
   - **Solution:** Use "Instant Sync" mode (skips AI initially)

2. **Token Expired:**
   - Facebook access token expired
   - **Solution:** Reconnect Facebook page

3. **Rate Limiting:**
   - Too many API calls to Facebook
   - **Solution:** Wait 10-15 minutes, then retry

4. **Large Conversation Count:**
   - Pages with 1000+ conversations take 30-90 seconds
   - **Solution:** Use background sync for large pages

**Solution:**
1. Use "Instant Sync" for faster initial sync
2. Reconnect Facebook page if token expired
3. Wait and retry if rate limited
4. Check Facebook App permissions

---

### 14. JSON Parse Errors in Browser Console

**Symptoms:**
- Console shows: `Unexpected token '<', "<!DOCTYPE "... is not valid JSON`
- API calls fail silently
- UI doesn't update after actions

**Cause:**
- Server returns HTML error page instead of JSON
- Usually indicates 500 error or authentication failure

**Diagnosis:**
1. Open browser DevTools (F12)
2. Go to Network tab
3. Find failed request
4. Check Response tab - should see HTML instead of JSON

**Solution:**
1. **Check Server Logs:**
   - Look for error stack traces
   - Common causes: Prisma errors, missing env vars

2. **Run Diagnostics:**
   ```bash
   npm run diagnose
   ```

3. **Check Authentication:**
   - Clear cookies and log in again
   - Verify session is valid

4. **Fix Root Cause:**
   - Usually Prisma client lock or database connection
   - Follow Issue #1 (Prisma Client Lock) steps

---

### 15. AI Analysis Not Working

**Symptoms:**
- Contact analysis shows "Pending" or "Failed"
- AI scores not updating
- Analysis jobs stuck at 0%

**Diagnosis:**
```bash
# Check NVIDIA API keys
npm run check:keys

# Test NVIDIA API
npm run test:keys

# Check API key rate limits
npm run check:rate-limit
```

**Common Causes:**

1. **Missing API Keys:**
   - NVIDIA API key not configured
   - **Solution:** Add `NVIDIA_API_KEY` to `.env.local`

2. **Rate Limit Exhausted:**
   - All API keys have hit rate limits
   - **Solution:** Wait 24 hours or add more API keys

3. **Invalid API Key:**
   - API key format incorrect or revoked
   - **Solution:** Generate new API key from NVIDIA

**Solution:**
1. **Add API Key:**
   ```bash
   npm run add:missing-keys
   ```

2. **Check Rate Limits:**
   - Go to Settings > API Keys
   - View rate limit status
   - Add additional keys if needed

3. **Verify Key Format:**
   - NVIDIA keys should start with `nvapi-`
   - Check key is active in NVIDIA dashboard

---

### 16. Database Connection Pool Exhausted

**Symptoms:**
- Intermittent 500 errors
- "Connection pool timeout" errors
- "P2024" Prisma errors
- Errors during high load (campaigns, syncs)

**Cause:**
- Too many concurrent database connections
- Default pool size (5) too small for workload

**Diagnosis:**
```bash
# Check database pool settings
npm run verify:db-pool

# Check connection pool usage
# Look for P2024 errors in logs
```

**Solution:**
1. **Increase Pool Size:**
   - Edit `DATABASE_URL` in `.env.local`
   - Add `?connection_limit=10&pool_timeout=20`
   - Example: `postgresql://user:pass@host:5432/db?connection_limit=10&pool_timeout=20`

2. **Reduce Concurrent Operations:**
   - Lower campaign batch size
   - Reduce sync concurrency
   - Process operations sequentially

3. **Add Connection Retry:**
   - System automatically retries on pool exhaustion
   - Wait 1-2 seconds and retry

---

### 17. Webhook Not Receiving Events

**Symptoms:**
- New messages not appearing in inbox
- Conversations not updating
- Delivery/read receipts not updating

**Diagnosis:**
```bash
# Check webhook configuration
curl http://localhost:3000/api/webhooks/facebook

# Test webhook locally (requires ngrok)
npm run ngrok:start
# Then update Facebook App webhook URL to ngrok URL
```

**Common Causes:**

1. **Webhook URL Not Configured:**
   - Facebook App webhook URL not set
   - **Solution:** Configure in Facebook App settings

2. **Verify Token Mismatch:**
   - Token in Facebook App doesn't match `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
   - **Solution:** Update token in Facebook App or `.env.local`

3. **Webhook Not Subscribed:**
   - Missing event subscriptions
   - **Solution:** Subscribe to: `messages`, `messaging_postbacks`, `message_deliveries`, `message_reads`

4. **Local Development:**
   - Facebook can't reach localhost
   - **Solution:** Use ngrok or deploy to staging

**Solution:**
1. **Configure Webhook in Facebook App:**
   - URL: `https://your-domain.com/api/webhooks/facebook`
   - Verify Token: Use value from `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
   - Subscribe to required events

2. **For Local Development:**
   ```bash
   # Start ngrok
   npm run ngrok:start
   
   # Update Facebook App webhook URL to ngrok URL
   # Example: https://abc123.ngrok.io/api/webhooks/facebook
   ```

3. **Test Webhook:**
   - Send test message from Facebook
   - Check server logs for webhook events
   - Verify events appear in inbox

---

## 🔗 Related Documentation

- [FIX_INTERNAL_SERVER_ERROR.md](./FIX_INTERNAL_SERVER_ERROR.md) - Detailed fix instructions
- [DIAGNOSIS_SUMMARY.md](./DIAGNOSIS_SUMMARY.md) - Root cause analysis
- [ENV_SETUP_GUIDE.md](./ENV_SETUP_GUIDE.md) - Environment variables
- [README.md](./README.md) - General documentation
- [QUICK_START_CAMPAIGNS.md](./QUICK_START_CAMPAIGNS.md) - Campaign setup
- [PERFORMANCE_EXPECTATIONS.md](./PERFORMANCE_EXPECTATIONS.md) - Performance benchmarks
- [LIMITATIONS_AND_KNOWN_ISSUES.md](./LIMITATIONS_AND_KNOWN_ISSUES.md) - Known limitations

