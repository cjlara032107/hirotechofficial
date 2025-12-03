# Fixing API Key 403 Error

## 🔍 Problem Identified

The diagnostic shows:
- ✅ API key is configured (from database)
- ✅ API key appears valid (format check passed)
- ❌ **403 status code** when testing connectivity
- ❌ Model test fails with 403

## 🐛 Root Cause

**403 Forbidden** means:
- The API key exists and is formatted correctly
- BUT authentication is being rejected by NVIDIA API
- This could mean:
  1. API key is invalid/expired
  2. API key doesn't have access to the model
  3. API key format is wrong (should start with `nvapi-`)
  4. API key needs to be regenerated

## 🔧 How to Fix

### Step 1: Verify API Key Format

**Check your API key:**
- Should start with: `nvapi-`
- Should be long (typically 50+ characters)
- Should be from NVIDIA API (not OpenAI)

**In your database:**
```sql
-- Check API keys (don't show full key, just prefix)
SELECT 
  id,
  name,
  status,
  LEFT(encrypted_key, 20) as key_prefix,
  rate_limited_at,
  last_used_at,
  total_requests,
  failed_requests
FROM "ApiKey"
ORDER BY created_at DESC;
```

### Step 2: Test API Key Manually

**Test with curl:**
```bash
curl -X POST https://integrate.api.nvidia.com/v1/chat/completions \
  -H "Authorization: Bearer YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-oss-120b",
    "messages": [{"role": "user", "content": "test"}],
    "max_tokens": 5
  }'
```

**Expected responses:**
- ✅ **200 OK**: Key works!
- ❌ **401 Unauthorized**: Key is invalid/expired
- ❌ **403 Forbidden**: Key doesn't have access to this model/endpoint
- ❌ **429 Too Many Requests**: Rate limited

### Step 3: Regenerate API Key

**If key is invalid:**
1. Go to NVIDIA API dashboard
2. Generate a new API key
3. Make sure it has access to:
   - `openai/gpt-oss-120b` model
   - Chat completions endpoint
4. Update in your app: Settings → API Keys

### Step 4: Check API Key Permissions

**Verify the key has:**
- ✅ Access to NVIDIA API
- ✅ Access to `openai/gpt-oss-120b` model
- ✅ Chat completions permission
- ✅ Not expired
- ✅ Not revoked

### Step 5: Update API Key in Database

**If you have a new key:**
1. Go to Settings → API Keys in your app
2. Add the new key
3. OR update existing key
4. Make sure status is ACTIVE

## 🔍 Diagnostic Endpoint Fixed

I've fixed the diagnostic endpoint to:
- ✅ Use correct Prisma schema fields (`status` instead of `isValid`)
- ✅ Use `rateLimitedAt` instead of `rateLimitedUntil`
- ✅ Properly count active keys

**Re-run diagnostic:**
```
GET /api/ai/diagnostic
```

## 📋 Next Steps

1. **Check API key format** - Should start with `nvapi-`
2. **Test key manually** - Use curl command above
3. **Regenerate if needed** - Get new key from NVIDIA
4. **Update in app** - Settings → API Keys
5. **Re-run diagnostic** - Should show connectivity ✅

## ⚠️ Common Issues

**Issue: Key doesn't start with `nvapi-`**
- This might be an OpenAI key, not NVIDIA
- Get NVIDIA API key from: https://build.nvidia.com/

**Issue: Key works in curl but not in app**
- Check if key is properly encrypted in database
- Verify decryption is working
- Check if key is being truncated

**Issue: 403 on specific model**
- Model might not be available for your account
- Try different model: `meta/llama-3.1-8b-instruct`
- Check NVIDIA API status page

## 🎯 Expected Result After Fix

**Diagnostic should show:**
```json
{
  "apiKey": {
    "configured": true,
    "source": "database",
    "valid": true,
    "count": 1
  },
  "model": {
    "name": "openai/gpt-oss-120b",
    "available": true
  },
  "connectivity": {
    "reachable": true,
    "latency": 1234
  },
  "recommendations": []
}
```

Once this shows all green, AI analysis should work!








