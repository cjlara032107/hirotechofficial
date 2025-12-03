# API Keys Test Results for GPT-OS-120B

## 📊 Test Summary

**Date:** November 30, 2025  
**Model Tested:** `openai/gpt-oss-120b`  
**Total Keys Tested:** 21  
**Working Keys:** 2 ✅  
**Failed Keys:** 19 ❌

## ✅ Working Keys (2)

These keys have access to `gpt-oss-120b` and work correctly:

1. **Key 1** - `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`
   - Status: ✅ WORKING
   - Latency: 330ms
   - Response: Valid

2. **Key 2** - `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`
   - Status: ✅ WORKING
   - Latency: 136ms
   - Response: Valid

## ❌ Failed Keys (19)

These keys returned **403 Forbidden** - they don't have access to the `gpt-oss-120b` model:

- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`
- `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`

**Error:** `403 Forbidden - No access to model`

## 🎯 Action Required

### Add Only Working Keys

Use this code to add the 2 working keys:

```javascript
fetch('/api/api-keys/bulk', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    keys: [
      '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',
      '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',
    ]
  })
})
.then(r => r.json())
.then(data => {
  console.log('✅ Keys added:', data.summary);
  console.log('📊 Total active keys:', data.summary.totalActiveKeys);
})
.catch(err => console.error('❌ Error:', err));
```

## 📝 Notes

- **Only 2 out of 21 keys work** with `gpt-oss-120b`
- The other 19 keys may work with different models (like `meta/llama-3.1-8b-instruct`)
- The 403 error means the keys are valid but don't have permission for this specific model
- You may need to request access to `gpt-oss-120b` for the other keys in your NVIDIA developer account

## 🔍 Next Steps

1. **Add the 2 working keys** using the code above
2. **Check NVIDIA developer account** to see if you can request access for the other keys
3. **Test AI analysis** - should work with the 2 working keys
4. **Consider alternative models** - the other keys might work with different models

## ⚠️ Important

With only 2 working keys, you'll have:
- Limited concurrency (2 keys rotating)
- Higher risk of rate limiting
- Consider requesting access for more keys or using alternative models








