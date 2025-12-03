# 🚀 Complete Setup Instructions for Analyze Contact API

## ✅ Current Status

Based on the diagnostic script, here's what we found:

### ✅ Working:
- ✅ Supabase URL and Anon Key are configured
- ✅ Edge function endpoint is accessible
- ✅ Database connection is working
- ✅ API keys exist in database

### ⚠️ Issues Found:
1. **API Key Authentication Failed (403 Forbidden)**
   - The API key from database is getting rejected by NVIDIA API
   - This could mean the key is invalid, expired, or rate-limited

2. **Edge Function Using Fallback**
   - Edge function works but is using fallback scoring instead of AI analysis
   - This means `NVIDIA_API_KEY` is not set in Supabase Edge Function secrets

## 🔧 Step-by-Step Fix Instructions

### Step 1: Verify API Key in Database

1. Go to your application: Settings → API Keys
2. Check if you have active NVIDIA API keys
3. If keys are rate-limited, wait for them to reset or add new keys

### Step 2: Set API Key in Supabase Edge Function (CRITICAL)

The edge function needs the API key in its environment. You have two options:

#### Option A: Via Supabase Dashboard (Recommended)

1. Go to: https://app.supabase.com
2. Select your project: `qudsmrrfbatasnyvuxch`
3. Navigate to: **Edge Functions** → **analyze-contact** → **Settings** → **Secrets**
4. Click **Add Secret**
5. Add:
   - **Name:** `NVIDIA_API_KEY`
   - **Value:** Your NVIDIA API key (starts with `nvapi-`)
6. Click **Save**

#### Option B: Via Supabase CLI

```bash
# Install Supabase CLI if not already installed
npm install -g supabase

# Login to Supabase
supabase login

# Link to your project
supabase link --project-ref qudsmrrfbatasnyvuxch

# Set the secret
supabase secrets set NVIDIA_API_KEY=your-api-key-here
```

### Step 3: Get Your NVIDIA API Key

If you don't have an API key:

1. Go to: https://build.nvidia.com/
2. Sign up or log in
3. Navigate to: **API Keys** or **Get API Key**
4. Create a new API key
5. Copy the key (it should start with `nvapi-`)

### Step 4: Test Everything

Run the setup script again to verify:

```bash
npm run setup:analyze-contact
```

You should see:
- ✅ Database API Keys: Success
- ✅ Environment Variables: Success  
- ✅ NVIDIA API Test: Success
- ✅ Supabase Edge Function: Success (not using fallback)

## 📋 Quick Checklist

- [ ] API key exists in database (Settings → API Keys)
- [ ] API key is valid and not rate-limited
- [ ] `NVIDIA_API_KEY` is set in Supabase Edge Function secrets
- [ ] Edge function test shows "AI analysis" not "fallback"
- [ ] Contact analysis returns proper AI-generated summaries

## 🧪 Testing

After setup, test with a real contact:

1. Go to Contacts page
2. Select a contact with messages
3. Click "Analyze"
4. Check the AI Analysis section
5. Verify it shows a detailed AI-generated summary (not fallback text)

## 🔍 Troubleshooting

### Issue: "Analysis failed but assigned score based on X messages"

**Cause:** Edge function doesn't have API key or API call is failing

**Fix:**
1. Check Supabase Edge Function logs: Dashboard → Edge Functions → analyze-contact → Logs
2. Look for: `❌ No API key found` or `❌ API error`
3. Set `NVIDIA_API_KEY` in Supabase Edge Function secrets (see Step 2)

### Issue: "403 Forbidden" when testing API

**Cause:** API key is invalid, expired, or rate-limited

**Fix:**
1. Check API key validity in NVIDIA dashboard
2. Add a new API key if current one is expired
3. Wait for rate limits to reset if key is rate-limited

### Issue: Edge function always uses fallback

**Cause:** API key not set in Supabase or API calls failing

**Fix:**
1. Verify `NVIDIA_API_KEY` is set in Supabase Edge Function secrets
2. Check edge function logs for errors
3. Test API key directly (see test script)

## 📝 Files Modified

- ✅ `supabase/functions/analyze-contact/index.ts` - Enhanced logging and validation
- ✅ `scripts/test-analyze-contact-api.ts` - Test script for API
- ✅ `scripts/setup-analyze-contact-complete.ts` - Complete setup diagnostic
- ✅ `package.json` - Added test commands

## 🎯 Next Steps

1. **Set API key in Supabase** (most important!)
2. **Run test script** to verify everything works
3. **Test with a real contact** to confirm analysis works
4. **Monitor edge function logs** for any issues

## 📞 Support

If you continue to have issues:

1. Check Supabase Edge Function logs for detailed error messages
2. Run `npm run setup:analyze-contact` to get detailed diagnostics
3. Verify API key is valid in NVIDIA dashboard
4. Check that edge function is deployed: `supabase functions list`

---

**Last Updated:** Based on current diagnostic results
**Status:** ⚠️ Needs API key in Supabase Edge Function secrets

