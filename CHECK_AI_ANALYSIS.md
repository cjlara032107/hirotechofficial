# Quick Check: AI Analysis Status

## 🚀 Quick Diagnostic

### Step 1: Check API Key Status
Visit this endpoint in your browser or use curl:
```
GET /api/ai/diagnostic
```

**Or in browser console:**
```javascript
fetch('/api/ai/diagnostic')
  .then(r => r.json())
  .then(console.log)
  .catch(console.error);
```

This will show:
- ✅ API key configured? (database or environment)
- ✅ API key valid?
- ✅ Model available?
- ✅ API reachable?
- ✅ Recommendations

### Step 2: Check Server Logs

**Look for these patterns when analyzing a contact:**

**✅ Success:**
```
[Fast AI] ✅ Received response (2847 chars)
[Fast AI] ✅ Analysis successful: score=72, stage=Hot Lead
[Pipeline Analysis job-xxx] ✅ Fast AI analysis successful
```

**❌ Failure:**
```
[Fast AI] No API key available
[Fast AI] API returned error: ...
[Fast AI] JSON parsing failed: ...
[Pipeline Analysis] ⚠️ Fast AI analysis returned null
```

### Step 3: Check Frontend-Backend Connection

**The data flow:**
1. Frontend calls: `POST /api/facebook/analyze-pipeline` or `POST /api/contacts/bulk`
2. Backend processes: `analyzeSelectedContacts()` → `analyzeWithFallback()` → `analyzeConversationFast()`
3. Database stores: `contact.aiContext` and `contact.aiContextUpdatedAt`
4. Frontend displays: `contact.aiContext` in "AI Analysis Details" card

**To verify:**
1. Open browser DevTools → Network tab
2. Analyze a contact
3. Check if API calls succeed (200 status)
4. Check response data

### Step 4: Common Issues

**Issue: No API Key**
- **Symptom:** Logs show "No API key available"
- **Fix:** Add API key in Settings → API Keys

**Issue: Invalid API Key**
- **Symptom:** Logs show "Authentication failed (401/403)"
- **Fix:** Verify API key is valid and starts with `nvapi-`

**Issue: Rate Limited**
- **Symptom:** Logs show "All API keys are rate-limited"
- **Fix:** Add more API keys or wait for rate limit reset

**Issue: Model Not Available**
- **Symptom:** Logs show "404" or "model not found"
- **Fix:** Check NVIDIA API status, verify model name

**Issue: Timeout**
- **Symptom:** Logs show "AI timeout"
- **Fix:** Check network, increase timeout if needed

## 📋 What to Check Right Now

1. **Run diagnostic:** `GET /api/ai/diagnostic`
2. **Check logs:** Look for `[Fast AI]` or `[Pipeline Analysis]` messages
3. **Verify API key:** Settings → API Keys (should have at least one)
4. **Test analysis:** Analyze 1 contact and watch logs
5. **Check output:** See if it's detailed AI analysis or generic fallback

## 🎯 Expected Results

**If working correctly:**
- Diagnostic shows: API key ✅, Model available ✅, Connectivity ✅
- Logs show: `✅ Analysis successful`
- Output: Detailed summary (500+ chars) with specific conversation references

**If not working:**
- Diagnostic shows: Issues with API key, model, or connectivity
- Logs show: Error messages
- Output: Generic "Analyzed X messages..." fallback text

## 🔧 Next Steps Based on Diagnostic

**If API key not configured:**
→ Add API key in Settings → API Keys

**If API key invalid:**
→ Verify key is correct, regenerate if needed

**If model not available:**
→ Check NVIDIA API status, verify model name

**If connectivity fails:**
→ Check network, firewall, API status

**If everything looks good but still failing:**
→ Check specific error messages in logs for targeted fix








