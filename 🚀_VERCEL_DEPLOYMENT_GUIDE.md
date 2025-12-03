# 🚀 Vercel Deployment Guide for HIRO V1.2

## ✅ Pre-Deployment Checklist

### 1. Code Quality ✓
- [x] All linting errors resolved
- [x] Backend AI analysis production-ready (30-step fix completed)
- [x] Comprehensive logging added
- [x] Multi-DB routing logs implemented
- [x] Error handling robust
- [x] Health checks in place

### 2. Configuration Files ✓
- [x] `vercel.json` configured with:
  - Build command: `npm run vercel-build`
  - Install command: `npm install --legacy-peer-deps`
  - 7 cron jobs configured
  - Region: `iad1` (Washington, D.C.)
- [x] `.gitignore` properly excluding sensitive files
- [x] `package.json` with `vercel-build` script

### 3. Environment Variables Required

#### **Database Configuration**
```bash
# Primary Database (REQUIRED)
DATABASE_URL="postgresql://..."

# Multi-DB Configuration (if ENABLE_MULTI_DB=true)
DATABASE_URL_0="postgresql://..."  # Primary
DATABASE_URL_1="postgresql://..."  # Secondary
DATABASE_URL_2="postgresql://..."  # Tertiary

# Multi-DB Settings
ENABLE_MULTI_DB="true"              # or "false"
DB_ROUTING_STRATEGY="hash"          # or "round-robin"
```

#### **Supabase Configuration**
```bash
NEXT_PUBLIC_SUPABASE_URL="https://your-project.supabase.co"
NEXT_PUBLIC_SUPABASE_ANON_KEY="eyJ..."
SUPABASE_SERVICE_ROLE_KEY="eyJ..."
```

#### **NextAuth Configuration**
```bash
AUTH_SECRET="generate-with-openssl-rand-base64-32"
AUTH_URL="https://your-domain.vercel.app"
AUTH_TRUST_HOST="true"
```

#### **AI Service Configuration**
```bash
AI_PRIMARY_MODEL="openai/gpt-oss-120b"
AI_FALLBACK_MODEL="openai/gpt-oss-80b"
NVIDIA_API_KEY="nvapi-..."  # Optional if using DB-based keys
```

#### **Facebook Integration**
```bash
FACEBOOK_APP_ID="your-app-id"
FACEBOOK_APP_SECRET="your-app-secret"
FACEBOOK_WEBHOOK_VERIFY_TOKEN="your-verify-token"
```

#### **Redis Configuration (if applicable)**
```bash
REDIS_URL="redis://..."
```

#### **Application Settings**
```bash
NODE_ENV="production"
NEXT_PUBLIC_APP_URL="https://your-domain.vercel.app"
```

---

## 🚀 Deployment Steps

### Option 1: Deploy via Vercel Dashboard (Recommended)

1. **Connect Repository**
   ```bash
   # First, commit and push all changes
   git add .
   git commit -m "Production-ready deployment with enhanced logging"
   git push origin main
   ```

2. **Import to Vercel**
   - Go to [vercel.com/new](https://vercel.com/new)
   - Import your Git repository
   - Vercel will auto-detect Next.js configuration

3. **Configure Environment Variables**
   - In Vercel Dashboard → Your Project → Settings → Environment Variables
   - Add all variables from the list above
   - Set them for Production, Preview, and Development environments

4. **Deploy**
   - Click "Deploy"
   - Vercel will:
     - Install dependencies with `npm install --legacy-peer-deps`
     - Generate Prisma client
     - Build Next.js application
     - Deploy to global edge network

### Option 2: Deploy via Vercel CLI

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Login to Vercel**
   ```bash
   vercel login
   ```

3. **Link Project**
   ```bash
   vercel link
   ```

4. **Set Environment Variables**
   ```bash
   # Set each variable
   vercel env add DATABASE_URL production
   vercel env add NEXT_PUBLIC_SUPABASE_URL production
   # ... (repeat for all variables)
   
   # Or pull from .env.local
   vercel env pull .env.vercel
   ```

5. **Deploy to Production**
   ```bash
   # Deploy to production
   vercel --prod
   
   # Or deploy to preview first
   vercel
   ```

---

## 🔍 Post-Deployment Verification

### 1. Check Deployment Status
```bash
# View deployment logs
vercel logs [deployment-url]

# Check build logs in Vercel Dashboard
```

### 2. Test Health Endpoint
```bash
curl https://your-domain.vercel.app/api/health
```

**Expected Response:**
```json
{
  "timestamp": "2025-12-03T...",
  "overallStatus": "healthy",
  "checks": {
    "databaseConnection": { "status": "healthy", ... },
    "multiDbRouter": { "status": "healthy", ... },
    "aiService": { "status": "healthy", ... },
    "memoryUsage": { "status": "healthy", ... }
  },
  "systemMetrics": { ... }
}
```

### 3. Test Multi-DB Routing Logs
```bash
# Test Facebook sync
curl -X POST https://your-domain.vercel.app/api/facebook/sync-instant \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"facebookPageId":"your-page-id"}'

# Check logs in Vercel Dashboard for:
# ✓ [SYNC-INSTANT] Routing decision
# ✓ [SYNC-INSTANT] Routed DB
# ✓ [SYNC-INSTANT] Fallback detection
# ✓ [SYNC-INSTANT] Org match checks
```

### 4. Verify Cron Jobs
- Go to Vercel Dashboard → Your Project → Cron Jobs
- Verify all 7 cron jobs are scheduled:
  - ✓ AI Automations (every 5 min)
  - ✓ Send Scheduled (every 5 min)
  - ✓ API Keys (hourly)
  - ✓ Recover Stuck Syncs (every 10 min)
  - ✓ Pipeline Updates (every 5 min)
  - ✓ Monitoring (every 5 min)
  - ✓ Auto Sync (daily at 4 PM UTC)

### 5. Monitor Logs
```bash
# Real-time logs
vercel logs --follow

# Filter by function
vercel logs --follow --output src/app/api/facebook/sync-instant/route.ts
```

---

## 🔧 Common Issues & Solutions

### Issue 1: Build Fails at Prisma Generate
**Solution:** Ensure `DATABASE_URL` is set in environment variables, even for build time.

### Issue 2: "Engine is not yet connected"
**Solution:** Check that:
- Database connection pool settings are correct
- `ENABLE_MULTI_DB` and `DATABASE_URL_*` variables match your setup
- Prisma is fully initialized before queries

### Issue 3: Cron Jobs Not Running
**Solution:** 
- Verify cron endpoints exist and return 200 OK
- Check Vercel Dashboard → Cron Jobs for execution history
- Ensure no middleware is blocking cron requests

### Issue 4: High Memory Usage
**Solution:**
- Monitor `/api/health` endpoint's `memoryUsage` check
- Review logs for memory-intensive operations
- Consider upgrading Vercel plan if consistently > 500MB

### Issue 5: Multi-DB Routing Issues
**Solution:**
- Check logs for `[MULTI-DB-ROUTER]` entries
- Verify `DB_ROUTING_STRATEGY` is set correctly
- Ensure all `DATABASE_URL_*` variables are valid
- Review `[SYNC-INSTANT]` and `[SYNC-STATUS]` logs for routing decisions

---

## 📊 Monitoring & Observability

### Key Logs to Monitor

1. **Multi-DB Routing**
   ```
   [MULTI-DB-ROUTER] getClient
   [SYNC-INSTANT] Routing decision
   [SYNC-STATUS] Lookup start
   ```

2. **AI Analysis**
   ```
   [AI-ANALYSIS] Start
   [AI-ANALYSIS] Retry attempt
   [AI-ANALYSIS] Fallback used
   [AI-ANALYSIS] Complete
   ```

3. **Error Tracking**
   ```
   [ERROR-LOGGER] Error logged
   [PRISMA-SAFE-OP] Error caught
   [HEALTH-CHECK] Component unhealthy
   ```

### Vercel Analytics
- Enable in Vercel Dashboard → Your Project → Analytics
- Monitor:
  - Request volume
  - Response times
  - Error rates
  - Geographic distribution

### Custom Monitoring
- Query error logs: `GET /api/admin/error-logs`
- System metrics: `GET /api/health`
- Queue stats: `GET /api/ai/queue-stats`

---

## 🎯 Performance Optimization

### Already Implemented ✓
- Connection pooling (`connection_limit=10`, `pool_timeout=20`)
- Request timeouts (30s for AI, configurable for DB)
- Memory optimization (message truncation)
- Retry logic with exponential backoff
- Comprehensive error handling
- Health checks for all services

### Recommended Settings
```bash
# Vercel Function Configuration
# Add to vercel.json if needed:
{
  "functions": {
    "src/app/api/**/*.ts": {
      "maxDuration": 30,
      "memory": 1024
    }
  }
}
```

---

## 🔐 Security Checklist

- [x] `.env` files excluded from Git
- [x] API keys stored in Vercel environment variables
- [x] Database credentials secured
- [x] Auth secret generated securely
- [x] AUTH_TRUST_HOST enabled for Vercel
- [x] Input validation on all endpoints
- [x] Error messages don't leak sensitive data
- [x] Rate limiting implemented (API key manager)

---

## 📝 Next Steps After Deployment

1. **Set Up Monitoring Alerts**
   - Configure Vercel to send alerts on deployment failures
   - Set up external monitoring (e.g., UptimeRobot, Pingdom)

2. **Test All Features**
   - User authentication
   - Facebook page sync
   - AI contact analysis
   - Pipeline management
   - Cron jobs execution

3. **Enable Observability**
   - Review logs daily for errors
   - Monitor `/api/health` endpoint
   - Track AI key usage and rotation

4. **Performance Tuning**
   - Review response times in Vercel Analytics
   - Optimize slow endpoints
   - Consider caching strategies

5. **Database Maintenance**
   - Run migrations if needed
   - Monitor connection pool usage
   - Review multi-DB routing effectiveness

---

## 📚 Reference Documents

- `🎉_BACKEND_AI_ANALYSIS_PRODUCTION_READY.md` - 30-step backend fix summary
- `📋_PRODUCTION_LOGGING_GUIDE.md` - Comprehensive logging guide
- `✨_ENHANCED_LOGGING_SUMMARY.md` - Logging enhancements overview
- `🔍_MULTI_DB_ROUTING_LOGS.md` - Multi-DB routing logs details
- `🎯_LOGGING_QUICK_REFERENCE.md` - Quick reference for log searches

---

## 🆘 Emergency Response

If critical issues occur post-deployment:

1. **Rollback**
   ```bash
   vercel rollback [deployment-url]
   ```

2. **View Live Logs**
   ```bash
   vercel logs --follow
   ```

3. **Check Health**
   ```bash
   curl https://your-domain.vercel.app/api/health
   ```

4. **Disable Cron Jobs** (if causing issues)
   - Go to Vercel Dashboard → Cron Jobs
   - Temporarily disable problematic jobs

---

## ✅ Deployment Ready!

Your application is now **production-ready** with:
- ✓ Robust error handling
- ✓ Comprehensive logging
- ✓ Multi-DB routing support
- ✓ Health monitoring
- ✓ AI analysis optimization
- ✓ All linting errors resolved

**You're ready to deploy! 🚀**

