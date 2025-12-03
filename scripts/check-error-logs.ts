/**
 * Error Log Checker - Identifies and explains common AI analysis errors
 * Run with: npx tsx scripts/check-error-logs.ts
 */

console.log('🔍 AI Analysis Error Log Checker\n');
console.log('==========================================\n');

console.log('📋 COMMON ERROR PATTERNS TO LOOK FOR:\n');

console.log('1️⃣  API KEY ERRORS:\n');
console.log('   Pattern: [NVIDIA] No API key available');
console.log('   Meaning: No API keys configured');
console.log('   Solution: Add API keys in Settings → API Keys or set NVIDIA_API_KEY env var\n');

console.log('   Pattern: [NVIDIA] 🔐 Authentication failed (401/403)');
console.log('   Meaning: Invalid or expired API key');
console.log('   Solution: Check API key validity, ensure it starts with "nvapi-"');
console.log('   Log shows: Current key prefix: nvapi-xxxxx...\n');

console.log('2️⃣  RATE LIMIT ERRORS:\n');
console.log('   Pattern: [NVIDIA] Rate limit hit, retrying (attempt X/3)');
console.log('   Meaning: API rate limit exceeded');
console.log('   Solution: System auto-retries, but add more API keys for better throughput');
console.log('   Pattern: [NVIDIA] Rate limit persists after multiple attempts');
console.log('   Meaning: All retries failed, key marked as rate-limited');
console.log('   Solution: Wait or add more API keys\n');

console.log('3️⃣  API RESPONSE ERRORS:\n');
console.log('   Pattern: [NVIDIA] API returned error in conversation analysis response');
console.log('   Meaning: API returned an error object instead of valid response');
console.log('   Solution: Check API status, may be temporary issue\n');

console.log('   Pattern: [NVIDIA] No choices in response');
console.log('   Meaning: API response missing choices array');
console.log('   Solution: Check API response format, may need to update client\n');

console.log('   Pattern: [NVIDIA] No response content received');
console.log('   Meaning: API response empty or malformed');
console.log('   Solution: Check API response structure\n');

console.log('4️⃣  ANALYSIS FAILURE ERRORS:\n');
console.log('   Pattern: [NVIDIA] ❌ Analysis failed: [error message]');
console.log('   Meaning: General AI analysis failure');
console.log('   Details: Check error message and HTTP status code');
console.log('   Log shows: HTTP Status: XXX, Error details: {...}\n');

console.log('   Pattern: [Pipeline Analysis {jobId}] ❌ AI analysis failed with exception');
console.log('   Meaning: Exception thrown during AI analysis');
console.log('   Details: Check stack trace in logs');
console.log('   Solution: Review error details, may be network or API issue\n');

console.log('5️⃣  TIMEOUT ERRORS:\n');
console.log('   Pattern: [Pipeline Analysis {jobId}] ⚠️ Analysis timed out after 60 seconds');
console.log('   Meaning: AI analysis took too long (>60s)');
console.log('   Solution: System falls back to enhanced analysis automatically');
console.log('   Note: This is expected for very long conversations\n');

console.log('6️⃣  FALLBACK ERRORS:\n');
console.log('   Pattern: [Pipeline Analysis {jobId}] ⚠️ All analysis methods failed, using fallback scoring');
console.log('   Meaning: All AI methods failed (detailed, fast, enhanced)');
console.log('   Solution: Check API keys, network connectivity, API status');
console.log('   Note: Fallback still provides basic scoring\n');

console.log('   Pattern: [Pipeline Analysis {jobId}] ⚠️ AI analysis too short (X chars)');
console.log('   Meaning: AI returned response but it\'s too short (<200 chars)');
console.log('   Solution: System tries fast analysis, then enhanced analysis');
console.log('   Note: May indicate API issues or prompt problems\n');

console.log('7️⃣  DATABASE ERRORS:\n');
console.log('   Pattern: [Pipeline Analysis {jobId}] Batch processing error');
console.log('   Meaning: Database update failed');
console.log('   Common causes: Missing columns, connection issues, transaction errors');
console.log('   Solution: System auto-retries without new fields\n');

console.log('   Pattern: does not exist (P2021)');
console.log('   Meaning: Database column missing');
console.log('   Solution: System auto-retries without problematic fields\n');

console.log('8️⃣  CONVERSATION ERRORS:\n');
console.log('   Pattern: [Pipeline Analysis {jobId}] Conversation not found after X attempts');
console.log('   Meaning: Could not find conversation for contact');
console.log('   Solution: Contact may not have active conversation\n');

console.log('   Pattern: [Pipeline Analysis {jobId}] No messages found for conversation');
console.log('   Meaning: Conversation exists but has no messages');
console.log('   Solution: Contact may have empty conversation\n');

console.log('   Pattern: [Pipeline Analysis {jobId}] No valid messages to analyze');
console.log('   Meaning: All messages filtered out (no text content)');
console.log('   Solution: Contact may only have attachments/media\n');

console.log('==========================================\n');
console.log('🔧 ERROR RESOLUTION GUIDE:\n');

console.log('Step 1: Identify Error Type');
console.log('  - Check console for [NVIDIA] or [Pipeline Analysis] prefixes');
console.log('  - Look for ❌ or ⚠️ emojis indicating errors\n');

console.log('Step 2: Check Error Details');
console.log('  - Look for "Error details:" JSON in logs');
console.log('  - Check HTTP status codes (401, 403, 429, 500, etc.)');
console.log('  - Review stack traces for exceptions\n');

console.log('Step 3: Common Fixes');
console.log('  - API Key Issues: Verify keys in Settings → API Keys');
console.log('  - Rate Limits: Add more API keys or wait');
console.log('  - Timeouts: Normal for long conversations, uses fallback');
console.log('  - Database: System auto-retries, check schema if persistent\n');

console.log('Step 4: Check System Status');
console.log('  - Verify model: Should show "openai/gpt-oss-120b"');
console.log('  - Check API key count: More keys = better throughput');
console.log('  - Review recent successful analyses for comparison\n');

console.log('==========================================\n');
console.log('📊 ERROR SEVERITY LEVELS:\n');

console.log('🔴 CRITICAL (System cannot proceed):');
console.log('  - No API keys available');
console.log('  - All API keys invalid');
console.log('  - Database connection failures\n');

console.log('🟡 WARNING (Degraded functionality):');
console.log('  - Rate limits (auto-retries)');
console.log('  - Timeouts (uses fallback)');
console.log('  - Short AI responses (tries alternatives)\n');

console.log('🟢 INFO (Normal operation):');
console.log('  - Fallback scoring (expected when AI fails)');
console.log('  - Retry attempts (normal recovery)');
console.log('  - Missing conversations (expected for some contacts)\n');

console.log('==========================================\n');
console.log('💡 QUICK DIAGNOSTIC:\n');
console.log('Run this in your dev server console:\n');
console.log('  grep -i "error\\|failed\\|❌" | tail -20\n');
console.log('Or look for these specific patterns:\n');
console.log('  - "[NVIDIA] ❌" - AI API errors');
console.log('  - "[Pipeline Analysis] ❌" - Pipeline errors');
console.log('  - "Authentication failed" - API key issues');
console.log('  - "Rate limit" - Throttling issues');
console.log('  - "timed out" - Timeout issues\n');

console.log('==========================================\n');
console.log('✅ Next Steps:\n');
console.log('1. Check your dev server console for the error patterns above');
console.log('2. Identify the specific error type');
console.log('3. Follow the solution steps for that error type');
console.log('4. If issue persists, check API status and network connectivity\n');









