# 🚀 JAD Branch - NVIDIA API Setup Guide

**Branch:** `jad`  
**AI Provider:** NVIDIA API  
**Model:** `openai/gpt-oss-20b`  
**API Endpoint:** `https://integrate.api.nvidia.com/v1`

---

## ✅ Current Configuration

Your project is now on the `jad` branch which uses **NVIDIA API** instead of OpenRouter.

### Key Differences from `main` branch:

| Feature | `main` branch | `jad` branch |
|---------|--------------|--------------|
| AI Provider | OpenRouter | NVIDIA API |
| Model | `google/gemini-2.0-flash-exp:free` | `openai/gpt-oss-20b` |
| API Endpoint | `https://openrouter.ai/api/v1` | `https://integrate.api.nvidia.com/v1` |
| API Key Format | `sk-or-v1-...` (OpenRouter) | `nvapi-...` (NVIDIA) |
| Key Rotation | Up to 17 keys | Single key (or fallback) |

---

## 🔑 Required Environment Variables

### For Local Development (`.env.local`):

```env
# ==================================
# NVIDIA API CONFIGURATION
# ==================================
# Get your NVIDIA API key from: https://build.nvidia.com/
# API key should start with "nvapi-"
NVIDIA_API_KEY=nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Fallback (optional - will use if NVIDIA_API_KEY not set)
GOOGLE_AI_API_KEY=nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ==================================
# APPLICATION CONFIGURATION
# ==================================
NEXT_PUBLIC_APP_URL=https://overinhibited-delphia-superpatiently.ngrok-free.dev

# ==================================
# DATABASE CONFIGURATION
# ==================================
DATABASE_URL="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL="postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"

# ==================================
# NEXTAUTH CONFIGURATION
# ==================================
NEXTAUTH_SECRET="35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK="
NEXTAUTH_URL=https://overinhibited-delphia-superpatiently.ngrok-free.dev

# ==================================
# FACEBOOK API CONFIGURATION
# ==================================
FACEBOOK_APP_ID=802438925861067
FACEBOOK_APP_SECRET=99e11ff061cd03fa9348547f754f96b9
FACEBOOK_WEBHOOK_VERIFY_TOKEN=your-custom-webhook-verify-token

# ==================================
# SUPABASE CONFIGURATION
# ==================================
NEXT_PUBLIC_SUPABASE_URL=https://qudsmrrfbatasnyvuxch.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1ZHNtcnJmYmF0YXNueXZ1eGNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5MjgxMDMsImV4cCI6MjA3ODUwNDEwM30.S2WNnRwW0XHyrj5KwGOgcKHuxN4EXKi5rBTX7mscuLA

# ==================================
# REDIS CONFIGURATION
# ==================================
REDIS_URL=redis://default:KGg04axFynrwFjFjFaEEX5yK3lPAVpyN@redis-14778.c326.us-east-1-3.ec2.redns.redis-cloud.com:14778

# ==================================
# ENVIRONMENT
# ==================================
NODE_ENV=development
```

---

## 🌐 Vercel Deployment Setup

### Step 1: Update Vercel Environment Variables

Go to your Vercel project settings → Environment Variables and add:

**Required:**
- `NVIDIA_API_KEY` = `nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

**Optional (fallback):**
- `GOOGLE_AI_API_KEY` = `nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (same as NVIDIA_API_KEY)

**All other variables** (DATABASE_URL, FACEBOOK_APP_ID, etc.) should already be set from your previous setup.

### Step 2: Configure Vercel to Deploy from `jad` Branch

1. Go to **Vercel Dashboard** → Your Project → **Settings** → **Git**
2. Under **Production Branch**, change from `main` to `jad`
3. Or create a new deployment from the `jad` branch

### Step 3: Redeploy

After updating environment variables:
- Vercel will auto-redeploy if you have auto-deploy enabled
- Or manually trigger a new deployment from the `jad` branch

---

## 🔍 How to Get NVIDIA API Key

1. **Sign up/Login** at [NVIDIA Build](https://build.nvidia.com/)
2. **Navigate to** API Keys section
3. **Create a new API key** (starts with `nvapi-`)
4. **Copy the key** and add it to your environment variables

---

## ✅ Verification

### Test NVIDIA API Locally:

1. **Start dev server:**
   ```bash
   npm run dev
   ```

2. **Check console logs** - You should see:
   ```
   [NVIDIA] Model Configuration:
     Model: openai/gpt-oss-20b
     BaseURL: https://integrate.api.nvidia.com/v1
   ```

3. **Test AI features:**
   - Sync a contact from Facebook
   - Check if AI Context analysis works
   - Look for `[NVIDIA]` logs in the console

### Common Issues:

#### ❌ "No API key available"
**Solution:** Make sure `NVIDIA_API_KEY` is set in `.env.local` and restart dev server

#### ❌ "401 Unauthorized" or "User not found"
**Solution:** 
- Verify API key starts with `nvapi-`
- Check key is active in NVIDIA dashboard
- Ensure no extra spaces in environment variable

#### ❌ "429 Rate Limit"
**Solution:**
- NVIDIA API has rate limits
- Wait a few minutes between requests
- Consider upgrading your NVIDIA API plan

---

## 📊 Model Information

**Current Model:** `openai/gpt-oss-20b`

This is NVIDIA's hosted version of the GPT-OSS-20B model. It's:
- ✅ Free tier available
- ✅ Fast response times
- ✅ Good for conversation analysis
- ✅ Suitable for follow-up message generation

---

## 🔄 Switching Back to Main Branch

If you want to switch back to OpenRouter (main branch):

```bash
git checkout main
git pull origin main
```

Then update environment variables to use OpenRouter API keys instead.

---

## 📝 Next Steps

1. ✅ Add `NVIDIA_API_KEY` to `.env.local`
2. ✅ Add `NVIDIA_API_KEY` to Vercel environment variables
3. ✅ Configure Vercel to deploy from `jad` branch
4. ✅ Test locally with `npm run dev`
5. ✅ Deploy to Vercel and verify

---

**Status:** ✅ Ready to use NVIDIA API on `jad` branch!







