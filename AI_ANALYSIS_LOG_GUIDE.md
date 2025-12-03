# AI Analysis Log Guide

## How to Check AI Analysis Logs

### 1. **Console Logs (Development Server)**

When running `npm run dev`, AI analysis logs appear in the console with these prefixes:

#### NVIDIA API Logs
- `[NVIDIA] Model Configuration:` - Shows which model is being used
- `[NVIDIA] Sending request - Model: ...` - Shows when a request is sent
- `[NVIDIA] Received response - Choices: ...` - Shows response received
- `[NVIDIA] ✅ Generated summary (X chars)` - Success with character count
- `[NVIDIA] ❌ Analysis failed:` - Error occurred
- `[NVIDIA] Rate limit hit, retrying...` - Rate limit detected
- `[NVIDIA] 🔐 Authentication failed` - API key issue

#### Pipeline Analysis Logs
- `[Pipeline Analysis {jobId}] 🚀 Starting pipeline analysis job...` - Job started
- `[Pipeline Analysis {jobId}] ✅ Successfully analyzed X contact(s)` - Success
- `[Pipeline Analysis {jobId}] ❌ Failed to analyze X contact(s)` - Failures
- `[Pipeline Analysis {jobId}] Processed batch: X contacts assigned` - Batch complete

### 2. **What to Look For**

#### ✅ **Good Signs:**
- `[NVIDIA] ✅ Generated summary (500+ chars)` - Detailed analysis
- `[Pipeline Analysis] ✅ Successfully analyzed` - Analysis completed
- No error messages

#### ⚠️ **Warning Signs:**
- `[NVIDIA] ✅ Generated summary (200-500 chars)` - Short analysis (may not be detailed enough)
- `[NVIDIA] ✅ Generated summary (<200 chars)` - Very short (likely fallback)
- `[NVIDIA] Rate limit hit` - API rate limits
- `[NVIDIA] 🔐 Authentication failed` - API key issues

#### ❌ **Error Signs:**
- `[NVIDIA] ❌ Analysis failed:` - AI analysis failed
- `[Pipeline Analysis] ❌ Failed to analyze` - Contact analysis failed
- `[NVIDIA] No API key available` - Missing API keys
- `[NVIDIA] No choices in response` - API returned invalid response

### 3. **Checking Database Logs (Requires DATABASE_URL)**

If you have database access, run:
```bash
npx tsx scripts/check-ai-analysis-logs.ts
```

This will show:
- Recent pipeline analysis jobs and their status
- Recent contacts with AI analysis results
- API key status
- Summary statistics

### 4. **Key Log Patterns**

#### Successful Analysis Flow:
```
[NVIDIA] Sending request - Model: openai/gpt-oss-120b, Messages: 1, Prompt length: X chars
[NVIDIA] Received response - Choices: 1, Usage: {...}
[NVIDIA] ✅ Generated summary (8000 chars)
[Pipeline Analysis {jobId}] ✅ Successfully analyzed 1 contact(s)
```

#### Failed Analysis Flow:
```
[NVIDIA] Sending request - Model: openai/gpt-oss-120b, Messages: 1, Prompt length: X chars
[NVIDIA] ❌ Analysis failed: [error message]
[Pipeline Analysis {jobId}] ❌ Failed to analyze 1 contact(s)
```

#### Rate Limit Flow:
```
[NVIDIA] Sending request - Model: openai/gpt-oss-120b, Messages: 1, Prompt length: X chars
[NVIDIA] Rate limit hit, retrying (attempt 2/3) after 2000ms...
[NVIDIA] ✅ Generated summary (8000 chars)
```

### 5. **Common Issues and Solutions**

#### Issue: Short AI Analysis (<200 chars)
**Log Pattern:**
```
[NVIDIA] ✅ Generated summary (150 chars)
```
**Solution:** Check if AI is actually being called or if fallback is being used. Look for `[NVIDIA] ❌ Analysis failed` before this.

#### Issue: No AI Analysis
**Log Pattern:**
```
[Pipeline Analysis {jobId}] ⚠️ No AI Context
```
**Solution:** Check for `[NVIDIA] ❌ Analysis failed` or `[NVIDIA] No API key available`.

#### Issue: Rate Limits
**Log Pattern:**
```
[NVIDIA] Rate limit hit, retrying (attempt 1/3) after 2000ms...
```
**Solution:** System will auto-retry. If persists, add more API keys or wait.

#### Issue: Authentication Failed
**Log Pattern:**
```
[NVIDIA] 🔐 Authentication failed (401) - Invalid or expired API key
```
**Solution:** Check API keys in Settings → API Keys or verify `NVIDIA_API_KEY` environment variable.

### 6. **Model Configuration**

Current model: `openai/gpt-oss-120b`
- Temperature: 0.7 (for detailed, creative responses)
- Max Tokens: 8000 (for comprehensive analysis)
- Base URL: `https://integrate.api.nvidia.com/v1`

### 7. **Log File Locations**

If logs are written to files:
- Development: Console output (stdout/stderr)
- Production: Check Vercel logs or your hosting platform's log viewer
- Build logs: `build_output.log`, `build-test.log`, etc.

### 8. **Quick Diagnostic Commands**

```bash
# Check if dev server is running and see live logs
npm run dev

# Check build logs
cat build_output.log | grep -i "nvidia\|pipeline\|analysis"

# Check for errors
cat build_output.log | grep -i "error\|failed\|❌"
```

### 9. **Expected Analysis Lengths**

- **Detailed AI Analysis:** 500-8000+ characters
- **Fast AI Analysis:** 200-5000 characters  
- **Enhanced (Rule-based):** 200-1000 characters
- **Fallback:** <200 characters (generic)

If you see analysis <200 chars, it's likely using fallback scoring.









