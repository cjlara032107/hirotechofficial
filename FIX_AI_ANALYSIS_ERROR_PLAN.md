# Fix AI Analysis Error - Chunked Implementation Plan

## 🔍 Root Cause Identified

**Error Location:** `src/lib/facebook/analyze-selected-contacts.ts:442-461`

**Issue:** `analyzeWithFallback()` is throwing an exception instead of returning a result. The function should **never throw** - it should always return a result with fallback scoring.

**Possible Causes:**
1. API key retrieval fails and throws
2. API request throws before retry logic catches it
3. JSON parsing throws unhandled error
4. Edge function throws unhandled error
5. Timeout throws unhandled error

## 📋 Implementation Plan (30 Chunks)

### Phase 1: Enhanced Error Logging (Steps 1-6)

**Step 1:** Add detailed error logging in `analyzeWithFallback`
- Log error type, message, stack trace
- Log retry attempt number
- Log API key status
- Log request parameters

**Step 2:** Add error logging in `analyzeConversationFast`
- Log API key retrieval
- Log request details
- Log response status
- Log JSON parsing errors with content preview

**Step 3:** Add error logging in `analyze-selected-contacts.ts`
- Log before calling `analyzeWithFallback`
- Log error details in catch block
- Log contact ID and message count

**Step 4:** Add API key diagnostic logging
- Log when API key is retrieved
- Log when API key is null
- Log API key manager errors
- Log key rotation attempts

**Step 5:** Add request/response logging
- Log request payload size
- Log response status codes
- Log response content length
- Log timeout occurrences

**Step 6:** Add error context logging
- Log contact ID
- Log message count
- Log pipeline stages
- Log conversation age

### Phase 2: Fix Error Handling in analyzeWithFallback (Steps 7-12)

**Step 7:** Wrap entire function in try-catch
- Ensure no unhandled exceptions
- Always return result
- Use fallback on any error

**Step 8:** Fix API key error handling
- Handle null API key gracefully
- Handle API key manager errors
- Return fallback instead of throwing

**Step 9:** Fix API request error handling
- Wrap all API calls in try-catch
- Handle network errors
- Handle timeout errors
- Handle rate limit errors

**Step 10:** Fix JSON parsing error handling
- Wrap parsing in try-catch
- Better error messages
- Log raw response
- Return fallback on parse error

**Step 11:** Fix edge function error handling
- Wrap edge function call in try-catch
- Handle network errors
- Handle timeout errors
- Return fallback on error

**Step 12:** Ensure fallback always works
- Wrap fallback scoring in try-catch
- Use emergency fallback if needed
- Never throw from fallback

### Phase 3: Fix analyzeConversationFast (Steps 13-18)

**Step 13:** Fix API key retrieval
- Handle null API key
- Handle API key manager errors
- Return null instead of throwing

**Step 14:** Fix API request handling
- Wrap request in try-catch
- Handle all error types
- Return null on error

**Step 15:** Fix timeout handling
- Clear timeout on success
- Handle timeout errors
- Return null on timeout

**Step 16:** Fix JSON parsing
- Multiple parsing strategies
- Better error recovery
- Return null on parse failure

**Step 17:** Fix response validation
- Check response structure
- Validate required fields
- Return null on invalid response

**Step 18:** Add comprehensive error logging
- Log all error types
- Log error details
- Log recovery attempts

### Phase 4: Fix analyze-selected-contacts.ts (Steps 19-24)

**Step 19:** Improve error handling in try-catch
- Log error before fallback
- Include error stack trace
- Log contact context

**Step 20:** Ensure fallback always works
- Wrap fallback in try-catch
- Use emergency fallback
- Never throw from catch block

**Step 21:** Add pre-analysis validation
- Check messages exist
- Check messages not empty
- Validate message structure

**Step 22:** Add analysis result validation
- Check result exists
- Validate result structure
- Handle null results

**Step 23:** Improve error messages
- More descriptive errors
- Include contact ID
- Include error context

**Step 24:** Add retry logic
- Retry on transient errors
- Exponential backoff
- Max retry attempts

### Phase 5: API Key Verification (Steps 25-27)

**Step 25:** Verify API keys in database
- Check active keys exist
- Verify encryption works
- Test key retrieval

**Step 26:** Add API key health check
- Pre-check keys before analysis
- Rotate keys if one fails
- Log key status

**Step 27:** Add API key fallback
- Use environment variable if DB fails
- Clear error if no keys
- Log key source

### Phase 6: Testing & Validation (Steps 28-30)

**Step 28:** Test error scenarios
- Test with null API key
- Test with invalid API key
- Test with API errors
- Test with timeout

**Step 29:** Test fallback scenarios
- Test fallback scoring
- Test emergency fallback
- Test error recovery

**Step 30:** Validate fixes
- Test with failing contact
- Verify error messages
- Confirm fallback works
- Check logs for details

## 🎯 Implementation Order

1. **Steps 1-6:** Add logging (identify exact error)
2. **Steps 7-12:** Fix `analyzeWithFallback` (prevent exceptions)
3. **Steps 13-18:** Fix `analyzeConversationFast` (handle errors)
4. **Steps 19-24:** Fix `analyze-selected-contacts.ts` (improve handling)
5. **Steps 25-27:** Verify API keys (ensure keys work)
6. **Steps 28-30:** Test and validate (confirm fixes)

## 📝 Expected Outcome

After implementation:
- ✅ No unhandled exceptions
- ✅ Clear error messages in logs
- ✅ Proper fallback scoring
- ✅ Detailed error diagnostics
- ✅ API key verification
- ✅ Better error recovery








