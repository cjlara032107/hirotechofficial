# 🔍 AI Analysis Bottlenecks Analysis

## Current Performance Metrics

**Per-Contact Analysis Time:**
- Message Fetching: 500-1000ms
- AI Analysis: 5-10 seconds (NVIDIA API)
- Database Updates: 50-100ms
- **Total: ~6-12 seconds per contact**

**Current Throughput:**
- With 1 API key: ~6-10 contacts/minute
- With 20 API keys: ~50-100 contacts/minute (theoretical)
- Actual: Limited by other bottlenecks

---

## 🚨 Major Bottlenecks Identified

### 1. **AI API Response Time** ⏱️ (CRITICAL)
**Impact:** 5-10 seconds per contact (80-90% of total time)

**Causes:**
- `openai/gpt-oss-120b` model is large (120B parameters) = slow inference
- `max_tokens: 4000` allows long responses = more processing time
- `TIMEOUT_MS: 90000` (90 seconds) - requests can take up to 90s
- Model generates reasoning content before final answer = double processing

**Current Settings:**
```typescript
// src/lib/ai/fast-detailed-analysis.ts
const MODEL = 'openai/gpt-oss-120b'; // 120B model = slow
const TIMEOUT_MS = 90000; // 90 seconds
max_tokens: 4000 // Very high token limit
```

**Optimization Options:**
1. ✅ Use faster model: `meta/llama-3.1-8b-instruct` (8B params, 3-5x faster)
2. ✅ Reduce `max_tokens` to 2000 (still sufficient for analysis)
3. ✅ Reduce timeout to 30-45 seconds (fail faster, retry faster)
4. ✅ Disable reasoning output if not needed

---

### 2. **Concurrency Limits** 🔢 (MODERATE)
**Impact:** Limits parallel processing

**Current Settings:**
```typescript
// src/lib/facebook/analyze-selected-contacts.ts
const analysisLimiter = new ConcurrencyLimiter(100); // 100 concurrent analyses
```

**Issue:**
- With 1 API key: 100 concurrent = rate limit exhaustion
- With 20 API keys: 100 concurrent = underutilized (could be 200+)
- No dynamic scaling based on available API keys

**Optimization:**
- ✅ Use dynamic concurrency based on API key count
- ✅ Formula: `50 + (keyCount * 10)` with max 500
- ✅ With 1 key: 60 concurrent
- ✅ With 20 keys: 250 concurrent

---

### 3. **Retry Delays** ⏳ (MODERATE)
**Impact:** Adds 500ms - 2s per retry

**Current Settings:**
```typescript
// src/lib/ai/enhanced-analysis.ts
const delayMs = Math.min(Math.pow(2, retryCount) * 500, 2000); // 500ms, 1s, 2s
```

**Issue:**
- Exponential backoff: 500ms → 1s → 2s
- With 3 retries: up to 3.5 seconds of delays
- Some retries are for transient errors that resolve quickly

**Optimization:**
- ✅ Reduce base delay to 200ms
- ✅ Max delay: 1s (instead of 2s)
- ✅ Smart retry: Skip delay for certain error types

---

### 4. **Sequential Database Operations** 💾 (MINOR)
**Impact:** 50-100ms per contact (adds up with many contacts)

**Current Flow:**
1. Fetch contact from DB
2. Analyze contact
3. Update contact in DB
4. Log activity in DB

**Issue:**
- Each contact = 2-3 separate DB queries
- No batching for multiple contacts

**Optimization:**
- ✅ Batch database updates (already implemented in pipeline-analyzer)
- ✅ Use transaction for contact + activity log updates
- ✅ Consider write-behind caching

---

### 5. **Message Fetching** 📨 (MINOR)
**Impact:** 500-1000ms per contact

**Current:**
- Fetches last 20 messages per conversation
- Sequential per contact (but high concurrency: 200)

**Optimization:**
- ✅ Already optimized (200 concurrent fetches)
- ✅ Consider caching recent messages
- ✅ Reduce to 15 messages if analysis quality doesn't suffer

---

### 6. **API Key Rotation Overhead** 🔑 (MINOR)
**Impact:** 10-50ms per request

**Current:**
- Database query for each API key retrieval
- Key health checks

**Optimization:**
- ✅ Cache API keys in memory (already implemented)
- ✅ Pre-fetch keys for batch operations

---

### 7. **JSON Parsing** 🔍 (MINOR)
**Impact:** 10-50ms per response

**Current:**
- Complex parsing to extract JSON from reasoning text
- Multiple regex operations

**Optimization:**
- ✅ Already optimized (extracts last valid JSON)
- ✅ Consider streaming JSON parsing

---

## 📊 Bottleneck Priority Ranking

| Rank | Bottleneck | Impact | Fix Difficulty | Priority |
|------|-----------|--------|----------------|----------|
| 1 | AI API Response Time | 🔴 CRITICAL | 🟢 Easy | **HIGH** |
| 2 | Concurrency Limits | 🟡 MODERATE | 🟢 Easy | **HIGH** |
| 3 | Retry Delays | 🟡 MODERATE | 🟢 Easy | **MEDIUM** |
| 4 | Sequential DB Ops | 🟢 MINOR | 🟡 Medium | **LOW** |
| 5 | Message Fetching | 🟢 MINOR | 🟡 Medium | **LOW** |
| 6 | API Key Rotation | 🟢 MINOR | 🟢 Easy | **LOW** |
| 7 | JSON Parsing | 🟢 MINOR | 🟡 Medium | **LOW** |

---

## 🚀 Recommended Optimizations

### Quick Wins (High Impact, Low Effort)

1. **Switch to Faster Model** (5-10x speedup)
   ```typescript
   const MODEL = 'meta/llama-3.1-8b-instruct'; // Instead of gpt-oss-120b
   ```

2. **Reduce Token Limit** (2x speedup)
   ```typescript
   max_tokens: 2000 // Instead of 4000
   ```

3. **Reduce Timeout** (Fail faster, retry faster)
   ```typescript
   const TIMEOUT_MS = 30000; // 30 seconds instead of 90
   ```

4. **Dynamic Concurrency** (2-5x throughput with multiple keys)
   ```typescript
   const concurrency = Math.min(50 + (keyCount * 10), 500);
   ```

5. **Faster Retries** (Save 1-2s per retry)
   ```typescript
   const delayMs = Math.min(Math.pow(2, retryCount) * 200, 1000);
   ```

### Medium-Term Optimizations

6. **Batch Database Updates** (Already implemented in pipeline-analyzer, apply to analyze-selected-contacts)

7. **Message Caching** (Cache recent messages for 5 minutes)

8. **Smart Retry Logic** (Skip delays for certain error types)

---

## 📈 Expected Performance Improvements

### Current Performance
- **1 contact:** ~6-12 seconds
- **10 contacts:** ~60-120 seconds (1-2 minutes)
- **100 contacts:** ~10-20 minutes

### After Quick Wins (Model + Concurrency + Timeout)
- **1 contact:** ~2-4 seconds (3x faster)
- **10 contacts:** ~20-40 seconds (3x faster)
- **100 contacts:** ~3-7 minutes (3x faster)

### After All Optimizations
- **1 contact:** ~1-3 seconds (4-6x faster)
- **10 contacts:** ~10-30 seconds (4-6x faster)
- **100 contacts:** ~2-5 minutes (4-6x faster)

---

## 🎯 Implementation Priority

1. **Phase 1 (Immediate):** Switch model, reduce tokens, reduce timeout
2. **Phase 2 (This Week):** Dynamic concurrency, faster retries
3. **Phase 3 (Next Week):** Batch DB updates, message caching

---

## ⚠️ Trade-offs to Consider

### Model Quality vs Speed
- `gpt-oss-120b`: Best quality, slowest (10s)
- `llama-3.1-8b-instruct`: Good quality, fast (2-3s)
- `llama-3.1-70b-instruct`: Great quality, medium speed (5-6s)

**Recommendation:** Use `llama-3.1-8b-instruct` for speed, `gpt-oss-120b` for quality-critical analyses

### Token Limit vs Completeness
- `max_tokens: 4000`: Full reasoning + analysis (slow)
- `max_tokens: 2000`: Analysis only (faster, still complete)
- `max_tokens: 1000`: Brief analysis (fastest, may miss details)

**Recommendation:** Use 2000 tokens (good balance)

### Concurrency vs Rate Limits
- High concurrency: Faster processing, but hits rate limits faster
- Low concurrency: Slower, but more stable

**Recommendation:** Dynamic concurrency based on API key count

---

## 📝 Next Steps

1. ✅ Create configuration file for model selection
2. ✅ Implement dynamic concurrency
3. ✅ Add model comparison tests
4. ✅ Monitor performance metrics
5. ✅ A/B test different models




