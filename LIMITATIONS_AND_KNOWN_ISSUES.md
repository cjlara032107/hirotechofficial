# Limitations and Known Issues

This document outlines the current limitations, known issues, and constraints of the Messenger Bulk platform. Understanding these limitations helps set proper expectations and plan workarounds.

---

## 🚫 Platform Limitations

### 1. Facebook & Instagram Integration

#### Message Sending Limitations

**24-Hour Window Restriction:**
- ❌ Cannot send promotional messages outside 24-hour window without message tags
- ✅ Can send messages with appropriate tags (ACCOUNT_UPDATE, CONFIRMED_EVENT_UPDATE, etc.)
- ⚠️ Message tags have strict usage guidelines - misuse can result in restrictions

**Message Tag Restrictions:**
- ❌ Cannot use tags for promotional content
- ❌ Cannot use tags for marketing messages
- ✅ Tags only for specific use cases (account updates, event confirmations, etc.)
- ⚠️ Facebook may restrict or ban accounts for tag misuse

**Rate Limits:**
- ❌ Facebook enforces rate limits (varies by app and usage)
- ❌ Cannot send unlimited messages
- ⚠️ Typical limit: 200 API calls per hour per user
- ✅ System automatically handles rate limits with delays

**Platform Support:**
- ✅ Facebook Messenger: Full support
- ✅ Instagram Direct Messages: Full support
- ❌ WhatsApp Business: Not supported
- ❌ Other messaging platforms: Not supported

#### API Limitations

**Conversation Access:**
- ❌ Cannot access conversations where user blocked the page
- ❌ Cannot access conversations from deleted accounts
- ❌ Cannot access conversations older than Facebook's retention period
- ⚠️ Some conversations may be inaccessible due to privacy settings

**User Profile Data:**
- ❌ Limited profile data for users with strict privacy settings
- ❌ Cannot access email/phone for users who haven't shared it
- ⚠️ Profile data availability depends on user privacy settings

**Webhook Reliability:**
- ⚠️ Webhooks may be delayed during high traffic
- ⚠️ Webhooks may be missed if server is down
- ✅ System attempts to recover missed webhooks via periodic sync

---

### 2. Contact Management

#### Contact Sync Limitations

**Initial Sync Performance:**
- ⚠️ Large pages (5000+ conversations) take 30-90 seconds to fetch
- ⚠️ AI analysis adds 5-10 seconds per contact
- ✅ Use "Instant Sync" to skip AI analysis initially

**Incremental Sync:**
- ⚠️ Currently processes all contacts on each sync
- ⚠️ No automatic detection of unchanged conversations
- ✅ Future: Incremental sync will skip unchanged contacts

**Message History:**
- ⚠️ Fetches up to 5000 messages per conversation
- ⚠️ Very long conversations may timeout
- ✅ System limits message fetching to prevent timeouts

**Contact Data:**
- ❌ Cannot access contacts who haven't messaged the page
- ❌ Cannot access contacts from other pages (unless connected)
- ⚠️ Contact data depends on Facebook permissions

#### Contact Analysis Limitations

**AI Analysis:**
- ⚠️ Requires NVIDIA API keys (or similar AI service)
- ⚠️ Analysis takes 5-10 seconds per contact
- ⚠️ Rate limits apply to AI service
- ❌ Cannot analyze contacts without API keys
- ✅ Fallback scoring available if AI fails

**Analysis Accuracy:**
- ⚠️ AI analysis depends on conversation quality
- ⚠️ Short conversations may have less accurate analysis
- ⚠️ Analysis may vary between AI models
- ✅ Analysis improves with more conversation history

**Bulk Analysis:**
- ⚠️ Large selections (1000+ contacts) may take hours
- ⚠️ Cannot cancel analysis once started (future feature)
- ⚠️ No progress indicator for very large jobs
- ✅ Background processing prevents UI blocking

---

### 3. Campaign Management

#### Campaign Sending Limitations

**Message Volume:**
- ⚠️ Large campaigns (10,000+ messages) may take hours
- ⚠️ Facebook rate limits may slow down sending
- ⚠️ Very large campaigns may timeout
- ✅ System automatically handles rate limits

**Message Personalization:**
- ✅ Supports basic variables: `{firstName}`, `{lastName}`, `{name}`
- ❌ Limited to available contact fields
- ❌ Cannot use custom fields in personalization
- ⚠️ Variables may be empty if contact data unavailable

**Campaign Targeting:**
- ✅ Tag-based targeting
- ✅ Pipeline stage targeting
- ❌ Cannot target by custom criteria (e.g., last message date)
- ❌ Cannot exclude specific contacts from campaigns
- ⚠️ Targeting limited to available filters

**Campaign Status:**
- ⚠️ Cannot edit campaign after creation
- ⚠️ Cannot modify message content after sending starts
- ✅ Can pause/resume campaigns
- ✅ Can cancel campaigns (stops future sends)

#### Campaign Performance

**Sending Speed:**
- ⚠️ Limited by Facebook rate limits
- ⚠️ Network latency affects sending speed
- ⚠️ Database operations may slow down large campaigns
- ✅ Fast parallel mode maximizes speed within limits

**Error Handling:**
- ✅ Individual message failures don't stop campaign
- ✅ Failed messages can be retried
- ⚠️ Some errors may require manual intervention
- ⚠️ Rate limit errors may pause campaign temporarily

---

### 4. Database & Infrastructure

#### Database Limitations

**Connection Pool:**
- ⚠️ Default pool size: 5 connections
- ⚠️ High concurrency may exhaust pool
- ✅ Can be increased to 10-20 connections
- ⚠️ Very high values may cause issues

**Query Performance:**
- ⚠️ Large datasets may slow down queries
- ⚠️ Complex queries may take > 1 second
- ✅ Indexes optimize common queries
- ⚠️ Some queries may need optimization for large datasets

**Data Retention:**
- ⚠️ No automatic data cleanup
- ⚠️ Old data accumulates over time
- ✅ Manual cleanup available
- ⚠️ Large databases may slow down operations

#### Infrastructure Limitations

**Serverless Constraints (Vercel):**
- ⚠️ 10-second timeout for API routes (Hobby plan)
- ⚠️ 60-second timeout for Pro plan
- ⚠️ Background jobs may not complete on serverless
- ✅ Worker processes handle long-running tasks

**Redis Requirements:**
- ⚠️ Required for campaign sending
- ⚠️ Required for background jobs
- ❌ Campaigns won't work without Redis
- ✅ Can use Upstash or Railway for production

**File Storage:**
- ❌ No file upload support
- ❌ No image attachment support in messages
- ⚠️ Limited to text messages only

---

### 5. AI & Automation Features

#### AI Analysis Limitations

**API Key Requirements:**
- ❌ Requires NVIDIA API keys (or similar)
- ❌ Cannot use without API keys
- ⚠️ Rate limits apply per API key
- ✅ Multiple keys can be added for better throughput

**Analysis Quality:**
- ⚠️ Depends on AI model quality
- ⚠️ May vary between different AI services
- ⚠️ Short conversations may have less accurate analysis
- ✅ Fallback scoring available

**Cost Considerations:**
- ⚠️ AI analysis incurs API costs
- ⚠️ Large-scale analysis can be expensive
- ⚠️ Rate limits may require multiple API keys
- ✅ Can skip AI analysis for faster syncs

#### Automation Limitations

**AI Automations:**
- ⚠️ Requires AI analysis to be enabled
- ⚠️ Limited to available trigger conditions
- ⚠️ Cannot create complex multi-step workflows
- ✅ Basic automation rules supported

**Auto-Pipeline Assignment:**
- ✅ Automatic assignment based on AI analysis
- ⚠️ Requires AI analysis to be enabled
- ⚠️ Assignment rules are fixed (cannot customize)
- ✅ Manual assignment always available

---

### 6. User Interface & Experience

#### UI Limitations

**Large Datasets:**
- ⚠️ Contact lists with 5000+ contacts may be slow
- ⚠️ Pagination required for very large lists
- ⚠️ Filtering/searching may be slow on large datasets
- ✅ Virtual scrolling optimizes rendering

**Real-Time Updates:**
- ⚠️ Updates may be delayed during high load
- ⚠️ WebSocket connections may drop
- ✅ Automatic reconnection handles disconnects
- ⚠️ Some updates may require page refresh

**Mobile Experience:**
- ⚠️ Optimized for desktop
- ⚠️ Some features may be limited on mobile
- ✅ Responsive design for basic usage
- ⚠️ Complex operations may be difficult on mobile

#### Feature Limitations

**Bulk Operations:**
- ⚠️ Limited bulk actions available
- ⚠️ Cannot bulk edit contact fields
- ✅ Can bulk tag/untag contacts
- ✅ Can bulk move contacts between stages

**Export/Import:**
- ❌ No CSV export functionality
- ❌ No CSV import functionality
- ⚠️ Manual data entry required
- ✅ Future: Export/import features planned

**Reporting:**
- ⚠️ Limited analytics available
- ⚠️ No custom report generation
- ✅ Basic campaign statistics
- ✅ Contact activity timeline

---

## 🐛 Known Issues

### 1. Prisma Client Lock (Windows)

**Issue:**
- Prisma client files get locked by Node.js processes
- Causes 500 errors on all pages
- Most common on Windows

**Status:** Known issue, workaround available

**Workaround:**
```bash
.\quick-fix.bat
# or manually:
taskkill /F /IM node.exe /T
npm run clean-prisma
npx prisma generate
```

**Prevention:**
- Always use Ctrl+C to stop servers
- Don't force-close terminals
- Run `npm run clean-prisma` weekly

---

### 2. Campaign Stuck in "SENDING" Status

**Issue:**
- Campaigns may get stuck in "SENDING" status
- Messages not actually sending
- Worker process may have crashed

**Status:** Known issue, fix available

**Workaround:**
```bash
npm run fix:campaigns
```

**Prevention:**
- Ensure BullMQ worker is running
- Check Redis connection
- Monitor worker logs

---

### 3. Contact Sync Shows 0 Contacts

**Issue:**
- Sync completes but shows 0 contacts synced
- Contacts may actually be synced
- UI may not update correctly

**Status:** Known issue, intermittent

**Workaround:**
- Refresh page after sync
- Check contacts list directly
- Re-run sync if needed

**Root Cause:**
- Race condition in sync status updates
- UI may not reflect actual sync results

---

### 4. AI Analysis Jobs Stuck at 0%

**Issue:**
- Analysis jobs created but not executing
- Progress shows 0% indefinitely
- Background processing may not start

**Status:** Known issue, fix in progress

**Workaround:**
- Cancel and restart analysis job
- Use instant sync instead
- Check API keys are configured

**Root Cause:**
- Background async functions may not execute in serverless
- Database connection may not be established
- Promise chain may not be kept alive

---

### 5. JSON Parse Errors in Browser Console

**Issue:**
- Console shows: `Unexpected token '<', "<!DOCTYPE "... is not valid JSON`
- API calls fail silently
- Usually indicates server error

**Status:** Mostly fixed, may still occur

**Workaround:**
- Check server logs for actual error
- Run `npm run diagnose`
- Fix underlying issue (usually Prisma lock)

**Prevention:**
- All API routes now return JSON with proper Content-Type
- Error handling improved
- Still may occur if server crashes

---

### 6. Database Connection Pool Exhausted

**Issue:**
- Intermittent 500 errors during high load
- "Connection pool timeout" errors
- P2024 Prisma errors

**Status:** Known issue, mitigation available

**Workaround:**
- Increase connection pool size in DATABASE_URL
- Reduce concurrent operations
- Wait and retry

**Prevention:**
- Increase pool size: `?connection_limit=10&pool_timeout=20`
- Reduce batch sizes in campaigns
- Process operations sequentially when possible

---

### 7. Facebook Token Expiration Not Detected

**Issue:**
- Expired tokens may not be detected immediately
- Operations fail with generic errors
- User may not know token expired

**Status:** Known issue, improvement in progress

**Workaround:**
- Reconnect Facebook page in Settings
- Check token expiration date
- Monitor error logs for token errors

**Improvement:**
- Automatic token expiration detection
- User notifications for expired tokens
- Automatic reconnection prompts

---

### 8. Rate Limit Errors Not User-Friendly

**Issue:**
- Rate limit errors show technical error codes
- Users may not understand what to do
- No clear indication of when to retry

**Status:** Known issue, improvement in progress

**Workaround:**
- Wait 5-10 minutes and retry
- Reduce campaign sending speed
- Check Facebook App rate limit status

**Improvement:**
- User-friendly error messages
- Automatic retry with delays
- Rate limit status indicators

---

### 9. Large Campaign Performance

**Issue:**
- Very large campaigns (10,000+ messages) may be slow
- Progress updates may lag
- UI may become unresponsive

**Status:** Known issue, optimization in progress

**Workaround:**
- Split large campaigns into smaller ones
- Use background processing
- Monitor campaign progress via API

**Improvement:**
- Better progress tracking
- Optimized batch processing
- Background job improvements

---

### 10. Webhook Missed Events

**Issue:**
- Webhook events may be missed if server is down
- Events may be delayed during high traffic
- Some events may not be processed

**Status:** Known issue, mitigation available

**Workaround:**
- Periodic sync recovers missed events
- Check webhook configuration
- Monitor webhook delivery status

**Improvement:**
- Webhook event queue
- Retry mechanism for failed events
- Event delivery confirmation

---

## ⚠️ Workarounds & Best Practices

### For Contact Sync Issues

1. **Use Instant Sync:**
   - Faster initial sync
   - AI analysis in background
   - Contacts appear immediately

2. **Sync During Off-Peak:**
   - Better API availability
   - Fewer rate limits
   - Faster processing

3. **Limit Message Fetching:**
   - Only fetch recent messages
   - Skip unchanged conversations
   - Reduce API calls

### For Campaign Issues

1. **Split Large Campaigns:**
   - Break into 500-1000 message campaigns
   - Run sequentially
   - Better error handling

2. **Monitor Rate Limits:**
   - Check Facebook App status
   - Adjust sending speed
   - Use rate-limited mode if needed

3. **Use Background Processing:**
   - Don't block UI
   - Monitor via dashboard
   - Can cancel if needed

### For AI Analysis Issues

1. **Add Multiple API Keys:**
   - Better throughput
   - Distribute rate limits
   - Redundancy

2. **Use Background Analysis:**
   - Non-blocking
   - Can be cancelled
   - Better user experience

3. **Skip Unchanged Conversations:**
   - Only analyze new/updated
   - Preserve existing analysis
   - Faster processing

---

## 🔮 Planned Improvements

### Short-Term (Next Release)

- ✅ Incremental contact sync
- ✅ Better error messages
- ✅ Token expiration detection
- ✅ Campaign progress improvements

### Medium-Term (Next Quarter)

- 🔄 CSV export/import
- 🔄 Custom report generation
- 🔄 Advanced filtering
- 🔄 Webhook event queue

### Long-Term (Future)

- 🔄 WhatsApp Business support
- 🔄 Multi-language support
- 🔄 Advanced automation workflows
- 🔄 Custom field support

---

## 📝 Reporting Issues

If you encounter issues not listed here:

1. **Check Existing Documentation:**
   - [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
   - [PERFORMANCE_EXPECTATIONS.md](./PERFORMANCE_EXPECTATIONS.md)

2. **Run Diagnostics:**
   ```bash
   npm run diagnose
   ```

3. **Gather Information:**
   - Error messages
   - Steps to reproduce
   - System logs
   - Browser console errors

4. **Report Issue:**
   - Include all gathered information
   - Describe expected vs. actual behavior
   - Note any workarounds found

---

## 🔗 Related Documentation

- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Troubleshooting guide
- [PERFORMANCE_EXPECTATIONS.md](./PERFORMANCE_EXPECTATIONS.md) - Performance benchmarks
- [README.md](./README.md) - General documentation









