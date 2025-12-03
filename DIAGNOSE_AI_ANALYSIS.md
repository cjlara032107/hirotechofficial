# AI Analysis Diagnostic Guide

## 🔍 Problem Identified

The output you're seeing:
```
"Analyzed 9 messages. This contact has engaged in a moderate conversation with 9 messages, with concise messages averaging 10 characters, with very recent activity (within the last day), indicating a contacted lead with moderate potential."
```

This is **FALLBACK SCORING**, not AI analysis. This means:
- ❌ AI analysis is failing
- ✅ Fallback scoring is working (but it's rule-based, not AI)

## 📍 Where This Text Comes From

**File:** `src/lib/facebook/analyze-selected-contacts.ts` (Line 425)
```typescript
summary: `Analyzed ${messagesToAnalyze.length} messages. ${fallback.reasoning}`,
```

**Fallback reasoning generated in:** `src/lib/ai/fallback-scoring.ts` (Line 252)

## 🔧 Diagnostic Steps

### Step 1: Check API Key Configuration

**Check if API key exists:**
```bash
# Check environment variable
echo $NVIDIA_API_KEY

# OR check in your app
# Go to: Settings → API Keys
```

**What to look for:**
- ✅ Valid NVIDIA API key starting with `nvapi-`
- ❌ No API key configured
- ❌ Invalid/expired API key
- ❌ Rate limited API key

### Step 2: Check Server Logs

**Where to find logs:**
1. **Development:** Terminal running `npm run dev`
2. **Production:** Vercel logs or server logs

**Look for these error patterns:**

```bash
# No API key
[Fast AI] No API key available, will use fallback
[NVIDIA] No API key available. Add one through Settings → API Keys

# API errors
[Fast AI] API returned error: ...
[NVIDIA] API returned error in conversation analysis response: ...

# JSON parsing errors
[Fast AI] JSON parsing failed: ...
[Fast AI] Response content (first 500 chars): ...

# Timeout errors
[Fast AI] Analysis failed: AI timeout
[Pipeline Analysis] ❌ Fast AI analysis failed: Analysis timeout after 90 seconds

# Rate limit errors
[NVIDIA] 🚫 All API keys are rate-limited
[NVIDIA] Rate limit hit, retrying...
```

### Step 3: Check API Endpoints

**Main Analysis Endpoints:**

1. **Pipeline Analysis:**
   - Endpoint: `POST /api/facebook/analyze-pipeline`
   - File: `src/app/api/facebook/analyze-pipeline/route.ts`
   - Calls: `startPipelineAnalysis()` → `processContact()` → `analyzeContact()`

2. **Selected Contacts Analysis:**
   - Endpoint: `POST /api/contacts/bulk` (with analysis)
   - File: `src/app/api/contacts/bulk/route.ts`
   - Calls: `analyzeSelectedContacts()` → `analyzeWithFallback()` or `analyzeConversation()`

3. **Background Analysis:**
   - Endpoint: `POST /api/contacts/bulk` (background mode)
   - File: `src/lib/facebook/background-analysis.ts`
   - Calls: `analyzeSelectedContacts()`

### Step 4: Check Frontend-Backend Connection

**Frontend Component:**
- File: `src/app/(dashboard)/contacts/[id]/page.tsx` (Line 409-424)
- Displays: `contact.aiContext` from database
- Data comes from: Server-side query in `getContact()`

**Data Flow:**
```
Frontend (Contact Detail Page)
  ↓
Server Component (ContactProfile)
  ↓
Database Query (getContact)
  ↓
contact.aiContext (stored in database)
  ↓
Displayed in "AI Analysis Details" card
```

**Check if data is being saved:**
- Look for database updates in logs
- Check if `aiContext` field is being populated
- Verify `aiContextUpdatedAt` timestamp

### Step 5: Test API Endpoint Directly

**Test the analysis endpoint:**

```bash
# Test with curl (replace with your actual values)
curl -X POST http://localhost:3000/api/facebook/analyze-pipeline \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "facebookPageId": "your-page-id",
    "forceUpdateExisting": true
  }'
```

**Or test in browser console:**
```javascript
fetch('/api/facebook/analyze-pipeline', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    facebookPageId: 'your-page-id',
    forceUpdateExisting: true
  })
})
.then(r => r.json())
.then(console.log)
.catch(console.error);
```

## 🐛 Common Issues & Fixes

### Issue 1: No API Key
**Symptoms:**
- Logs show: `[Fast AI] No API key available`
- All contacts get fallback scoring

**Fix:**
1. Go to Settings → API Keys
2. Add NVIDIA API key (starts with `nvapi-`)
3. OR set `NVIDIA_API_KEY` environment variable

### Issue 2: API Key Invalid/Expired
**Symptoms:**
- Logs show: `[NVIDIA] 🔐 Authentication failed (401/403)`
- API returns 401/403 errors

**Fix:**
1. Verify API key is valid
2. Check API key hasn't expired
3. Regenerate API key if needed

### Issue 3: Rate Limited
**Symptoms:**
- Logs show: `[NVIDIA] 🚫 All API keys are rate-limited`
- Analysis works sometimes but fails often

**Fix:**
1. Add more API keys for rotation
2. Wait for rate limit to reset
3. Reduce concurrent analysis requests

### Issue 4: JSON Parsing Fails
**Symptoms:**
- Logs show: `[Fast AI] JSON parsing failed`
- Response preview shows non-JSON content

**Fix:**
- Already fixed in latest code (improved parsing)
- Check if model is returning valid JSON
- Verify prompt is clear enough

### Issue 5: Timeout
**Symptoms:**
- Logs show: `[Fast AI] Analysis failed: AI timeout`
- Analysis takes longer than 45 seconds

**Fix:**
- Increase timeout in `fast-detailed-analysis.ts`
- Check network latency
- Verify model is responding

### Issue 6: Model Not Available
**Symptoms:**
- Logs show model-specific errors
- API returns 404 or model not found errors

**Fix:**
- Verify model name: `openai/gpt-oss-120b`
- Check NVIDIA API status
- Try alternative model if needed

## 📊 How to Verify It's Working

### Success Indicators ✅

**In Logs:**
```
[Fast AI] ✅ Received response (2847 chars)
[Fast AI] ✅ Analysis successful: score=72, stage=Hot Lead, summary=2847 chars
[Pipeline Analysis job-abc123] ✅ Fast AI analysis successful
```

**In Database:**
- `aiContext` field contains detailed analysis (500+ chars)
- `aiContext` references specific conversation content
- `aiContextUpdatedAt` timestamp is recent

**In Frontend:**
- "AI Analysis Details" shows detailed summary
- Summary mentions specific conversation details
- Not generic "Analyzed X messages..." text

### Failure Indicators ❌

**In Logs:**
```
[Fast AI] No API key available
[Fast AI] API returned error: ...
[Fast AI] JSON parsing failed: ...
[Pipeline Analysis] ⚠️ Fast AI analysis returned null
```

**In Database:**
- `aiContext` contains generic fallback text
- Text starts with "Analyzed X messages..."
- No specific conversation references

**In Frontend:**
- Shows generic fallback scoring text
- No detailed analysis
- Predictable scores

## 🔍 Quick Diagnostic Commands

### Check API Key
```bash
# In your terminal
grep -r "NVIDIA_API_KEY" .env* 2>/dev/null || echo "No API key in .env files"
```

### Check Recent Logs
```bash
# Look for AI analysis logs
grep -E "\[Fast AI\]|\[Pipeline Analysis\]|\[NVIDIA\]" logs/*.log | tail -50
```

### Check Database
```sql
-- Check if contacts have AI analysis
SELECT 
  id,
  name,
  aiContext IS NOT NULL as has_ai_context,
  LENGTH(aiContext) as context_length,
  aiContextUpdatedAt
FROM Contact
WHERE aiContext LIKE 'Analyzed%'  -- Fallback pattern
LIMIT 10;
```

## 🎯 Next Steps

1. **Check your logs** - Look for the error patterns above
2. **Verify API key** - Make sure it's configured and valid
3. **Test a single contact** - Analyze one contact and watch logs
4. **Check network** - Verify API calls are reaching NVIDIA
5. **Review error messages** - Share specific errors for targeted fixes

## 📝 What to Share for Help

If you need help debugging, share:

1. **Error logs** - Copy/paste relevant error messages
2. **API key status** - Is it configured? (don't share the key itself)
3. **Network status** - Can you reach NVIDIA API?
4. **Model availability** - Is `openai/gpt-oss-120b` available?
5. **Recent changes** - What changed before this started?

This will help identify the exact issue and provide a targeted fix.








