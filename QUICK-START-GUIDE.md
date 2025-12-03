# Campaign System - Quick Start Guide

## ✅ What Has Been Implemented

All campaign system components are now **multi-DB safe** with comprehensive logging and error handling:

### 1. **Multi-DB Routing Throughout**
- All campaign APIs use `getPrismaForOrg(organizationId)` 
- Automatic database routing based on organization hash
- Detailed logging shows which DB (index/host) each operation uses
- Org-scoped data access prevents cross-org leakage

### 2. **Scheduling & Automation**
- Cron job picks up scheduled campaigns automatically
- Worker safely processes campaigns across multiple databases
- Auto-fetch recipients feature for dynamic lists
- Tag-based filtering (include/exclude)

### 3. **Flexible Targeting**
- Send to specific contacts (validated)
- Send to all contacts for a page/platform
- Tag-based targeting
- Pipeline stage targeting
- Contact group targeting

### 4. **Media Support**
- Image and video attachments
- URL validation and conversion
- Automatic cleanup after campaign completion

### 5. **AI Personalization**
- Per-contact message generation
- Conversation history context
- Custom instructions support
- Background generation (non-blocking)
- Fallback to templates on failure

### 6. **Status Tracking**
- Real-time campaign status API
- Per-message status tracking
- Progress percentage calculation
- Estimated time remaining
- Recent errors display
- Comprehensive metrics (sent, delivered, read, failed, replied)

### 7. **Retry & Error Handling**
- Rate limit detection and backoff
- Batch processing with pause/cancel support
- Connection pool management
- Detailed error logging with DB context

## 🚀 How to Use

### Create a Campaign (Immediate Send)

```bash
curl -X POST http://localhost:3000/api/campaigns \
  -H "Content-Type: application/json" \
  -H "Cookie: your-auth-cookie" \
  -d '{
    "name": "Product Launch",
    "platform": "MESSENGER",
    "facebookPageId": "your-page-id",
    "targetingType": "SPECIFIC_CONTACTS",
    "targetContactIds": ["contact1", "contact2", "contact3"],
    "templateId": "your-template-id",
    "mediaUrl": "https://yourdomain.com/image.jpg",
    "mediaType": "image",
    "useAiPersonalization": true,
    "aiCustomInstructions": "Be friendly and mention our sale"
  }'
```

### Create a Scheduled Campaign

```bash
curl -X POST http://localhost:3000/api/campaigns \
  -H "Content-Type: application/json" \
  -H "Cookie: your-auth-cookie" \
  -d '{
    "name": "Holiday Greetings",
    "platform": "MESSENGER",
    "facebookPageId": "your-page-id",
    "targetingType": "ALL_CONTACTS",
    "sendToAll": true,
    "templateId": "your-template-id",
    "scheduledAt": "2025-12-25T09:00:00Z",
    "autoFetchEnabled": true,
    "includeTags": ["customer"],
    "excludeTags": ["unsubscribed"]
  }'
```

### Send Campaign

```bash
curl -X POST http://localhost:3000/api/campaigns/CAMPAIGN_ID/send \
  -H "Cookie: your-auth-cookie"
```

### Check Campaign Status

```bash
curl http://localhost:3000/api/campaigns/CAMPAIGN_ID/status \
  -H "Cookie: your-auth-cookie"
```

Response:
```json
{
  "campaign": {
    "id": "clx123",
    "name": "Product Launch",
    "status": "SENDING",
    "platform": "MESSENGER"
  },
  "metrics": {
    "totalRecipients": 100,
    "sent": 75,
    "delivered": 60,
    "read": 20,
    "failed": 5,
    "pending": 20
  },
  "progress": {
    "percentage": 75,
    "isActive": true,
    "estimatedTimeRemaining": 30
  },
  "recentErrors": []
}
```

## 🔧 Configuration

### Environment Variables

```bash
# Multi-DB Configuration
ENABLE_MULTI_DB=true
DB_ROUTING_STRATEGY=hash  # or 'round-robin' or 'load-aware'

# Database URLs
DATABASE_URL_0=postgresql://user:pass@host1:5432/db1
DATABASE_URL_1=postgresql://user:pass@host2:5432/db2
DATABASE_URL_2=postgresql://user:pass@host3:5432/db3

# Cron Secret
CRON_SECRET=your-cron-secret

# AI Configuration
GOOGLE_AI_API_KEY=your-google-ai-key
```

### Verify Configuration

```bash
# Check database connectivity
npx ts-node scripts/verify-supabase-projects.ts

# Verify campaign multi-DB setup
npx ts-node scripts/verify-campaign-multi-db.ts
```

## 📊 Monitoring Logs

All campaign operations log:
- Organization ID
- Multi-DB status
- Routing strategy
- Database index (0, 1, 2, etc.)
- Database host
- Database health status
- Targeting details (sendToAll, contactIds count, etc.)
- Media/AI flags
- Errors with full context

**Example logs:**
```
[Campaign API POST] Start {
  orgId: 'clo123xyz',
  name: 'Holiday Campaign',
  platform: 'MESSENGER',
  sendToAll: false,
  contactIdsCount: 150,
  scheduledAt: 'immediate',
  useAiPersonalization: true,
  hasMedia: true,
  multiDb: true,
  strategy: 'hash'
}

[Campaign API POST] Routed DB {
  organizationId: 'clo123xyz',
  dbIndex: 1,
  dbUrlHost: 'aws-0-us-west-1.pooler.supabase.com',
  dbHealth: 'healthy'
}

[Campaign API POST] Created campaign {
  campaignId: 'clx123',
  status: 'PENDING',
  orgId: 'clo123xyz',
  scheduledAt: 'none',
  totalRecipients: 150,
  hasMedia: true,
  useAiPersonalization: true
}
```

## 🧪 Testing

### Test 1: Immediate Send
1. Create campaign with specific contacts
2. Send immediately
3. Poll status API
4. Verify all messages sent successfully
5. Check logs for DB routing

### Test 2: Scheduled Send
1. Create campaign scheduled for future
2. Wait for cron job to pick it up
3. Verify campaign sends at scheduled time
4. Check status transitions

### Test 3: Media Delivery
1. Create campaign with media URL
2. Send to contacts
3. Verify media delivered in Facebook
4. Check media cleanup after completion

### Test 4: AI Personalization
1. Create campaign with AI enabled
2. Provide custom instructions
3. Verify unique messages per contact
4. Check aiMessagesMap in database

### Test 5: Multi-DB Verification
1. Enable multi-DB mode
2. Create campaigns for different orgs
3. Verify each org's campaigns in correct DB
4. Run `verify-campaign-multi-db.ts` script

## 📁 Key Files Modified

### API Routes
- `src/app/api/campaigns/route.ts` - List/Create campaigns
- `src/app/api/campaigns/[id]/route.ts` - Get/Delete campaign
- `src/app/api/campaigns/[id]/send/route.ts` - Send campaign
- `src/app/api/campaigns/[id]/status/route.ts` - **NEW** Status API
- `src/app/api/campaigns/create-with-messages/route.ts` - Create with AI

### Services
- `src/lib/campaigns/send.ts` - Core sending logic
- `src/lib/db/get-prisma-for-org.ts` - Multi-DB helper (unchanged)
- `src/lib/db/multi-db-router.ts` - DB router (unchanged)

### Workers
- `src/app/api/cron/send-scheduled/route.ts` - Scheduled campaign worker

### Verification Scripts
- `scripts/verify-campaign-multi-db.ts` - **NEW** Multi-DB verification
- `scripts/verify-supabase-projects.ts` - DB connectivity check

### Documentation
- `CAMPAIGN-IMPLEMENTATION-SUMMARY.md` - Complete implementation details
- `UI-IMPLEMENTATION-NOTES.md` - UI enhancement guide
- `QUICK-START-GUIDE.md` - This file

## 🐛 Troubleshooting

### Campaign not found in routed DB
**Problem:** 404 error with "not found in routed database"

**Solution:**
1. Check database connectivity: `npx ts-node scripts/verify-supabase-projects.ts`
2. Verify routing: Check logs for DB index/host
3. Run verification: `npx ts-node scripts/verify-campaign-multi-db.ts`

### Messages not sending
**Problem:** Campaign stuck in SENDING status

**Solution:**
1. Check for rate limit warnings in logs
2. Verify contacts have valid PSIDs/SIDs
3. Check Facebook page token expiration
4. Review batch processing logs

### AI generation slow
**Problem:** AI message generation takes too long

**Solution:**
- It's background processing - doesn't block campaign creation
- Check `aiMessagesMap` field for progress
- Increase API key count for higher concurrency
- Messages use template as fallback if AI fails

## ✨ Features Summary

| Feature | Status | Multi-DB Safe | API Endpoint |
|---------|--------|---------------|--------------|
| Create Campaign | ✅ | ✅ | POST /api/campaigns |
| List Campaigns | ✅ | ✅ | GET /api/campaigns |
| Get Campaign | ✅ | ✅ | GET /api/campaigns/[id] |
| Send Campaign | ✅ | ✅ | POST /api/campaigns/[id]/send |
| Delete Campaign | ✅ | ✅ | DELETE /api/campaigns/[id] |
| Campaign Status | ✅ | ✅ | GET /api/campaigns/[id]/status |
| Scheduled Sending | ✅ | ✅ | Cron job |
| Scoped Sending | ✅ | ✅ | Via targetingType |
| Media Support | ✅ | ✅ | Via mediaUrl/mediaType |
| AI Messages | ✅ | ✅ | Via useAiPersonalization |
| Status Tracking | ✅ | ✅ | Per message & campaign |
| Retry Logic | ✅ | ✅ | Built into sender |

## 🎯 Next Steps (Optional)

1. **UI Enhancements** (see UI-IMPLEMENTATION-NOTES.md)
   - Real-time status polling in UI
   - Campaign creation wizard
   - Analytics dashboard

2. **Advanced Features**
   - Retry failed messages endpoint
   - A/B testing variants
   - Recurring campaigns
   - Time zone-aware scheduling

3. **Performance**
   - Increase batch sizes for faster sending
   - Add Redis caching for status queries
   - Implement message queuing system

## 📞 Support

For issues or questions:
1. Check logs for detailed error messages
2. Run verification scripts
3. Review CAMPAIGN-IMPLEMENTATION-SUMMARY.md
4. Check UI-IMPLEMENTATION-NOTES.md for frontend guidance

## 🎉 Success!

Your campaign system is now production-ready with:
- ✅ Full multi-DB support with automatic routing
- ✅ Comprehensive logging for debugging
- ✅ Scheduling and automation
- ✅ Flexible targeting options
- ✅ Media and AI support
- ✅ Real-time status tracking
- ✅ Robust error handling
- ✅ Org-level data isolation

**All campaign APIs and workers are multi-DB safe and ready for deployment!**

