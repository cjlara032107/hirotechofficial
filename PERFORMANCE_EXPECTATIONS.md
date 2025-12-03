# Performance Expectations

This document outlines expected performance characteristics for the Messenger Bulk platform. Use these benchmarks to understand normal behavior and identify when performance issues may need investigation.

## 📊 Overview

The platform handles various operations with different performance characteristics. Performance depends on:
- **Data volume** (number of contacts, conversations, messages)
- **External API dependencies** (Facebook Graph API, AI services)
- **System resources** (database, Redis, network)
- **Concurrent operations** (campaigns, syncs, analysis)

---

## ⚡ Core Operations Performance

### 1. Contact Synchronization

**Instant Sync Mode** (Recommended for initial sync):
- **Time per 100 contacts:** 20-50 seconds
- **Time per 500 contacts:** 2-5 minutes
- **Time per 1000 contacts:** 5-10 minutes
- **AI Analysis:** Queued in background (doesn't block)

**Regular Sync Mode** (Includes AI analysis):
- **Time per 10 contacts:** 1-2 minutes
- **Time per 50 contacts:** 5-10 minutes
- **Time per 100 contacts:** 10-20 minutes
- **Time per 500 contacts:** 1-2 hours

**Performance Breakdown:**
- **Conversation fetching:** 10-30 seconds (for 1000 conversations)
- **Message fetching:** 1-5 seconds per conversation (depends on message count)
- **Database operations:** 0.5-1 second per contact
- **AI analysis:** 5-10 seconds per contact (primary bottleneck)

**Optimization Tips:**
- Use "Instant Sync" for faster initial contact import
- AI analysis runs in background after instant sync
- Subsequent syncs are faster (only processes changed conversations)

---

### 2. Campaign Message Sending

**Fast Parallel Mode** (Default):
- **Batch size:** 10 messages per batch
- **Batch delay:** 500ms-30 seconds (adaptive based on rate limits)
- **Concurrent sends:** All messages in batch sent in parallel
- **Throughput:** 20-100 messages per minute (depends on Facebook rate limits)

**Rate-Limited Mode:**
- **Messages per hour:** Configurable (default: 100/hour)
- **Throughput:** ~1.7 messages per minute
- **Use case:** When Facebook rate limits are strict

**Performance Characteristics:**
- **Small campaigns (10-50 messages):** 1-5 minutes
- **Medium campaigns (100-500 messages):** 5-30 minutes
- **Large campaigns (1000+ messages):** 30 minutes - 2 hours

**Rate Limit Handling:**
- Automatic detection of Facebook rate limits (error codes: 613, 4, 17)
- Adaptive delays: 1-30 seconds between batches
- Extended pause: 5 minutes after 5 consecutive rate-limited batches
- Campaign continues automatically after rate limits reset

---

### 3. AI Contact Analysis

**Single Contact Analysis:**
- **Time:** 5-10 seconds per contact
- **Components:**
  - Network latency: 200-500ms
  - AI processing: 2-5 seconds
  - Retry delays: 500ms-2s (if retries needed)

**Bulk Analysis:**
- **10 contacts:** 50-100 seconds (with 50 concurrent limit)
- **50 contacts:** 5-10 minutes
- **100 contacts:** 10-20 minutes
- **500 contacts:** 1-2 hours

**Concurrency:**
- **Maximum concurrent AI calls:** 50
- **Batch processing:** 50 contacts per batch
- **Parallel batches:** Up to 20 concurrent batches

**Performance Factors:**
- **API key availability:** More keys = better throughput
- **Rate limits:** Each API key has rate limits
- **Network latency:** Geographic distance to AI service
- **Model processing time:** Depends on conversation length

---

### 4. Database Operations

**Query Performance:**
- **Simple queries:** < 100ms
- **Complex queries with joins:** 100-500ms
- **Bulk operations:** 0.5-1 second per 100 records

**Connection Pool:**
- **Default pool size:** 5 connections
- **Recommended for production:** 10-20 connections
- **Pool timeout:** 20 seconds

**Optimization:**
- Queries use indexes on frequently accessed fields
- Bulk operations use batch processing
- Connection pooling prevents exhaustion

---

### 5. Page Load Times

**Dashboard:**
- **Initial load:** 1-3 seconds
- **Subsequent navigation:** < 1 second (cached)

**Contacts List:**
- **100 contacts:** < 1 second
- **500 contacts:** 1-2 seconds
- **1000+ contacts:** 2-5 seconds (with pagination)

**Contact Detail Page:**
- **With messages:** 1-3 seconds
- **Without messages:** < 1 second

**Campaigns Page:**
- **List view:** < 1 second
- **Detail view:** 1-2 seconds

---

## 🚀 Real-Time Features

### WebSocket Updates
- **Latency:** < 100ms for local updates
- **Delivery:** Near-instant for new messages
- **Reliability:** Automatic reconnection on disconnect

### Real-Time Inbox
- **New message appearance:** < 1 second
- **Status updates (delivered/read):** < 2 seconds
- **Typing indicators:** < 500ms

---

## 📈 Scalability Expectations

### Contact Volume

**Recommended Limits:**
- **Small business:** Up to 1,000 contacts
- **Medium business:** 1,000 - 10,000 contacts
- **Large business:** 10,000+ contacts (may require optimization)

**Performance Impact:**
- **< 1,000 contacts:** Optimal performance
- **1,000 - 5,000 contacts:** Good performance, minor slowdowns
- **5,000 - 10,000 contacts:** Acceptable performance, some delays
- **10,000+ contacts:** May require pagination and filtering optimization

### Campaign Volume

**Recommended Limits:**
- **Concurrent campaigns:** 1-3 active campaigns
- **Messages per campaign:** Up to 10,000 messages
- **Daily message volume:** Up to 50,000 messages (depends on Facebook limits)

**Performance Impact:**
- Multiple concurrent campaigns may slow down sending
- Large campaigns (> 5,000 messages) may take hours to complete
- Facebook rate limits are the primary constraint

---

## ⏱️ Timeout Expectations

### API Timeouts

**Facebook Graph API:**
- **Request timeout:** 30 seconds
- **Retry attempts:** 3 attempts with exponential backoff
- **Total max time:** ~90 seconds per request (with retries)

**AI Service API:**
- **Request timeout:** 30 seconds
- **Retry attempts:** 3 attempts
- **Total max time:** ~90 seconds per request (with retries)

**Database Operations:**
- **Query timeout:** 20 seconds
- **Connection timeout:** 10 seconds
- **Pool timeout:** 20 seconds

### Operation Timeouts

**Contact Sync:**
- **Instant sync:** 5 minutes timeout
- **Regular sync:** 30 minutes timeout
- **Background sync:** No timeout (runs until complete)

**Campaign Sending:**
- **Batch timeout:** 60 seconds per batch
- **Campaign timeout:** No timeout (runs until complete or cancelled)

**AI Analysis:**
- **Single contact:** 30 seconds timeout
- **Bulk analysis:** No timeout (runs until complete)

---

## 🔍 Performance Monitoring

### Key Metrics to Monitor

1. **API Response Times:**
   - Facebook API: Should be < 2 seconds
   - AI API: Should be < 10 seconds
   - Database: Should be < 500ms

2. **Operation Completion Times:**
   - Contact sync: Monitor via sync job status
   - Campaign sending: Monitor via campaign progress
   - AI analysis: Monitor via analysis job status

3. **Error Rates:**
   - API errors: Should be < 5%
   - Database errors: Should be < 1%
   - Timeout errors: Should be < 2%

### Performance Degradation Indicators

**Warning Signs:**
- Contact sync taking > 2x expected time
- Campaign sending < 10 messages per minute
- AI analysis taking > 15 seconds per contact
- Database queries taking > 1 second
- Frequent timeout errors

**Action Items:**
1. Check system resources (CPU, memory, database)
2. Review error logs for API issues
3. Verify external service status (Facebook, AI service)
4. Check for rate limiting
5. Review database connection pool usage

---

## 🎯 Performance Optimization Tips

### For Faster Contact Sync

1. **Use Instant Sync:**
   - Contacts appear immediately
   - AI analysis runs in background

2. **Sync During Off-Peak Hours:**
   - Reduces load on Facebook API
   - Better rate limit availability

3. **Limit Message Fetching:**
   - Only fetch last 100-200 messages for analysis
   - Skip unchanged conversations

### For Faster Campaign Sending

1. **Use Fast Parallel Mode:**
   - Sends messages as fast as possible
   - Automatic rate limit handling

2. **Split Large Campaigns:**
   - Break into smaller campaigns (500-1000 messages)
   - Run campaigns sequentially

3. **Monitor Rate Limits:**
   - Check Facebook App rate limit status
   - Adjust sending speed if needed

### For Faster AI Analysis

1. **Add Multiple API Keys:**
   - More keys = better throughput
   - Distributes rate limit load

2. **Use Background Analysis:**
   - Doesn't block contact sync
   - Can be cancelled and resumed

3. **Skip Unchanged Conversations:**
   - Only analyze new or updated conversations
   - Preserves existing analysis

---

## 📊 Expected Performance by Use Case

### Small Business (100-500 contacts)

**Contact Sync:**
- Instant sync: 1-3 minutes
- Regular sync: 10-30 minutes

**Campaign Sending:**
- 100 messages: 2-5 minutes
- 500 messages: 10-30 minutes

**AI Analysis:**
- 100 contacts: 10-20 minutes
- 500 contacts: 1-2 hours

### Medium Business (1,000-5,000 contacts)

**Contact Sync:**
- Instant sync: 5-15 minutes
- Regular sync: 30 minutes - 2 hours

**Campaign Sending:**
- 1,000 messages: 20-60 minutes
- 5,000 messages: 2-5 hours

**AI Analysis:**
- 1,000 contacts: 2-4 hours
- 5,000 contacts: 10-20 hours (background)

### Large Business (10,000+ contacts)

**Contact Sync:**
- Instant sync: 15-60 minutes
- Regular sync: 2-8 hours

**Campaign Sending:**
- 10,000 messages: 3-8 hours
- 50,000 messages: 1-2 days (with rate limits)

**AI Analysis:**
- 10,000 contacts: 1-2 days (background)
- 50,000 contacts: 5-10 days (background)

---

## ⚠️ Performance Limitations

### Hard Limits

1. **Facebook API Rate Limits:**
   - Varies by app and usage
   - Typically 200 calls per hour per user
   - Campaign sending limited by Facebook

2. **AI Service Rate Limits:**
   - Depends on API key tier
   - Typically 100-1000 requests per minute
   - Can be increased with more API keys

3. **Database Connection Pool:**
   - Default: 5 connections
   - Can be increased to 10-20
   - Higher values may cause issues

### Soft Limits

1. **Browser Performance:**
   - Large contact lists (> 5,000) may be slow
   - Use pagination and filtering

2. **Memory Usage:**
   - Large campaigns may use significant memory
   - Background processing recommended

3. **Network Latency:**
   - Geographic distance affects API calls
   - AI service latency: 200-500ms typical

---

## 🔄 Performance vs. Features Trade-offs

### Instant Sync vs. Regular Sync

**Instant Sync:**
- ✅ Fast: Contacts appear in 20-50 seconds
- ✅ Non-blocking: AI analysis in background
- ❌ AI scores not immediately available

**Regular Sync:**
- ✅ Complete: AI analysis included
- ❌ Slow: 10-20 minutes for 100 contacts
- ❌ Blocking: Must wait for completion

### Fast Parallel vs. Rate-Limited Campaigns

**Fast Parallel:**
- ✅ Fast: 20-100 messages per minute
- ✅ Automatic rate limit handling
- ❌ May hit Facebook rate limits

**Rate-Limited:**
- ✅ Safe: Respects Facebook limits
- ✅ Predictable: Consistent sending speed
- ❌ Slow: ~1.7 messages per minute

---

## 📝 Performance Notes

### Development vs. Production

**Development:**
- Slower due to hot reloading
- Additional logging overhead
- Local database may be slower

**Production:**
- Optimized builds
- Better caching
- Production-grade infrastructure

### Network Conditions

**Good Network:**
- Low latency (< 100ms)
- High bandwidth
- Stable connection

**Poor Network:**
- High latency (> 500ms)
- Low bandwidth
- Unstable connection
- May cause timeouts

---

## 🆘 When Performance is Below Expectations

If performance is significantly below these expectations:

1. **Check System Status:**
   ```bash
   npm run diagnose
   ```

2. **Review Error Logs:**
   - Look for API errors
   - Check for rate limiting
   - Verify database connection

3. **Monitor Resources:**
   - CPU usage
   - Memory usage
   - Database connection pool

4. **Verify External Services:**
   - Facebook API status
   - AI service status
   - Database status

5. **Review Configuration:**
   - Environment variables
   - Database connection settings
   - API key configuration

For detailed troubleshooting, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md).









