# Adding API Keys - Quick Guide

## 🚀 Method 1: Using Bulk API Endpoint (Recommended)

### Step 1: Prepare the keys array

The API endpoint accepts an array of keys. You can use this in browser console or with curl:

**Browser Console:**
```javascript
fetch('/api/api-keys/bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    keys: [
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
    ]
  })
})
.then(r => r.json())
.then(console.log)
.catch(console.error);
```

**Or with curl:**
```bash
curl -X POST http://localhost:3000/api/api-keys/bulk \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "keys": [
      "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",
      "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",
      ...
    ]
  }'
```

### Step 2: Check the response

You'll get a response like:
```json
{
  "summary": {
    "total": 21,
    "added": 21,
    "skipped": 0,
    "errors": 0,
    "totalActiveKeys": 21
  },
  "results": [...]
}
```

## 🛠️ Method 2: Using the Script

Run the bulk import script:

```bash
npx tsx scripts/bulk-add-api-keys.ts
```

**Note:** Make sure you have:
- `ENCRYPTION_KEY` environment variable set
- Database connection configured
- `tsx` installed: `npm install -g tsx`

## ✅ Verify Keys Were Added

### Check via Diagnostic Endpoint:
```
GET /api/ai/diagnostic
```

Should show:
```json
{
  "apiKey": {
    "configured": true,
    "source": "database",
    "valid": true,
    "count": 21
  }
}
```

### Check via API Keys Endpoint (Developer only):
```
GET /api/api-keys
```

## 🔍 After Adding Keys

1. **Test connectivity:**
   - Visit `/api/ai/diagnostic`
   - Should show `connectivity.reachable: true`

2. **Test AI analysis:**
   - Analyze a contact
   - Check logs for `[Fast AI] ✅ Analysis successful`
   - Should see detailed analysis, not fallback scoring

3. **Monitor key usage:**
   - Keys will rotate automatically
   - Check `/api/api-keys/usage-stats` for usage statistics

## 📝 Notes

- Keys are encrypted before storage
- Duplicate keys are automatically skipped
- All keys are set to `ACTIVE` status
- Keys are rotated in round-robin fashion
- Rate-limited keys are automatically skipped

## 🎯 Expected Result

After adding the keys:
- ✅ 21 API keys in database
- ✅ All keys active and ready
- ✅ AI analysis should work
- ✅ No more 403 errors
- ✅ Detailed AI analysis output








