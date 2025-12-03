# Campaign System - Multi-DB Implementation Summary

## Overview

This document summarizes the comprehensive multi-DB safe campaign system implementation for HIRO V1.2. All campaign APIs, workers, and services now support multi-database routing with detailed logging, org-aware data access, and robust error handling.

## Implementation Status

### ✅ Completed Features

#### 1. Multi-DB Routing with Detailed Logging

**Files Updated:**
- `src/app/api/campaigns/route.ts` (GET, POST)
- `src/app/api/campaigns/[id]/route.ts` (GET, DELETE)
- `src/app/api/campaigns/[id]/send/route.ts` (POST)
- `src/app/api/campaigns/create-with-messages/route.ts` (POST)
- `src/lib/campaigns/send.ts` (all functions)
- `src/app/api/cron/send-scheduled/route.ts` (cron worker)

**Implementation Details:**
- All APIs use `getPrismaForOrg(organizationId)` for automatic DB routing
- Logs include:
  - Organization ID
  - Multi-DB enabled status
  - Routing strategy (hash/round-robin/load-aware)
  - Database index (DB0, DB1, DB2, etc.)
  - Database host (extracted from URL)
  - Database health status
- Errors include DB context for debugging

**Example Log Output:**
```
[Campaign API POST] Start {
  orgId: 'clo123xyz',
  name: 'Holiday Campaign',
  platform: 'MESSENGER',
  sendToAll: false,
  contactIdsCount: 150,
  scheduledAt: 'immediate',
  useAiPersonalization: true,
  hasMedia: false,
  multiDb: true,
  strategy: 'hash'
}

[Campaign API POST] Routed DB {
  organizationId: 'clo123xyz',
  dbIndex: 1,
  dbUrlHost: 'aws-0-us-west-1.pooler.supabase.com',
  dbHealth: 'healthy'
}
```

#### 2. Scheduling Flow with Cron Support

**Components:**
- Cron job: `src/app/api/cron/send-scheduled/route.ts`
- Runs every minute (configurable in `vercel.json` or cron config)
- Picks campaigns with `status=SCHEDULED` and `scheduledAt <= NOW()`
- Processes up to 10 campaigns per run to avoid timeouts
- Multi-DB safe: routes each campaign to its organization's database

**Features:**
- Auto-fetch recipients (optional): Fetches fresh contacts from Facebook before sending
- Tag filtering: Include/exclude tags for dynamic recipient lists
- AI message generation: Generates personalized messages during scheduled send
- Status transitions: `SCHEDULED` → `SENDING` → `COMPLETED` or `CANCELLED`
- Retry logic with exponential backoff
- Database lock to prevent simultaneous execution across instances

**Testing:**
```bash
# Test cron endpoint
curl -H "Authorization: Bearer YOUR_CRON_SECRET" \
  http://localhost:3000/api/cron/send-scheduled
```

#### 3. Scoped Sending (Selected vs Send-to-All)

**Targeting Types Supported:**
1. `SPECIFIC_CONTACTS`: Send to specific contact IDs
2. `ALL_CONTACTS`: Send to all contacts for a page/platform
3. `CONTACT_GROUPS`: Send to contacts in specific groups
4. `TAGS`: Send to contacts with specific tags
5. `PIPELINE_STAGES`: Send to contacts in specific pipeline stages

**Validation:**
- `sendToAll` and `targetContactIds` are mutually exclusive
- All specific contacts must belong to same org and page
- Facebook page must exist and belong to organization
- Contacts are validated before campaign creation
- Empty contact lists are rejected with clear errors

**API Usage:**
```json
// Send to specific contacts
POST /api/campaigns
{
  "name": "VIP Campaign",
  "targetingType": "SPECIFIC_CONTACTS",
  "targetContactIds": ["contact1", "contact2", "contact3"],
  "facebookPageId": "page123"
}

// Send to all contacts
POST /api/campaigns
{
  "name": "Announcement",
  "targetingType": "ALL_CONTACTS",
  "sendToAll": true,
  "facebookPageId": "page123"
}
```

#### 4. Media Support

**Supported Media Types:**
- `image` (JPEG, PNG, GIF, WebP)
- `video` (MP4)

**Features:**
- Media URL validation (must be publicly accessible)
- Relative URL conversion to full URLs
- Localhost warning (Facebook can't access localhost)
- Media metadata stored with campaign
- Media included in message delivery
- Auto-cleanup after campaign completion

**API Usage:**
```json
POST /api/campaigns
{
  "name": "Product Launch",
  "mediaUrl": "https://yourdomain.com/media/product.jpg",
  "mediaType": "image",
  "targetContactIds": ["contact1", "contact2"]
}
```

**Media Sending Flow:**
```typescript
// In send.ts
if (mediaUrl && mediaType) {
  result = await client.sendMediaMessage({
    recipientId,
    message: content || undefined,
    mediaUrl: fullMediaUrl,
    mediaType,
    messageTag,
  });
}
```

#### 5. AI-Generated Messages

**Features:**
- Personalized message generation per contact
- Uses conversation history (last 10 messages)
- Custom instructions support
- Concurrency control (20-50 parallel generations)
- Fallback to template on AI failure
- Background generation to avoid blocking
- Messages cached in `aiMessagesMap` (JSON field)

**Implementation:**
- Service: `GoogleAIService`
- Concurrency: Dynamic based on available API keys
- Context includes:
  - Contact name
  - Conversation history
  - Template message
  - Custom instructions (optional)

**API Usage:**
```json
POST /api/campaigns/create-with-messages
{
  "name": "Personalized Outreach",
  "useAiPersonalization": true,
  "aiCustomInstructions": "Be friendly and mention their previous purchase",
  "templateContent": "Hi {firstName}! I wanted to reach out...",
  "targetContactIds": ["contact1", "contact2"]
}
```

**AI Generation Flow:**
1. Campaign created with `useAiPersonalization=true`
2. Background job starts generating messages
3. For each contact:
   - Fetch conversation history
   - Generate personalized message
   - Store in `aiMessagesMap`
4. Campaign updated with all generated messages
5. Sending uses AI messages instead of template

#### 6. Comprehensive Status Tracking

**Campaign Status Values:**
- `DRAFT`: Campaign being created
- `PENDING`: Ready to send immediately
- `SCHEDULED`: Scheduled for future send
- `SENDING`: Currently sending messages
- `COMPLETED`: All messages sent
- `CANCELLED`: Campaign cancelled

**Message Status Values:**
- `PENDING`: Message queued
- `SENT`: Message sent to Facebook
- `DELIVERED`: Message delivered to recipient
- `READ`: Message read by recipient
- `FAILED`: Message failed to send

**Per-Campaign Metrics:**
- `totalRecipients`: Total contacts targeted
- `sentCount`: Messages successfully sent
- `deliveredCount`: Messages delivered
- `readCount`: Messages read
- `failedCount`: Messages failed
- `repliedCount`: Messages with replies

**Per-Contact/Message Tracking:**
- Status and timestamps stored per message
- Error messages captured and sanitized
- Retry count tracked (for future retry logic)
- Activity log created for each sent message

**Retry Logic (in sendMessagesInBackground):**
- Rate limit detection (Facebook error codes 613, 4, 17)
- Exponential backoff (1s per rate-limited message, max 30s)
- Consecutive rate limit tracking (5 batches → 5min delay)
- Campaign pause/cancel check before each batch
- Batch timeout protection (60s per batch)
- Database connection pool management (batch size 10)

#### 7. Status API for UI Polling

**Endpoint:** `GET /api/campaigns/[id]/status`

**Features:**
- Real-time metrics calculation
- Message status distribution
- Progress percentage
- Estimated time remaining
- Recent errors (last 10)
- Multi-DB safe

**Response:**
```json
{
  "campaign": {
    "id": "campaign123",
    "name": "Holiday Campaign",
    "status": "SENDING",
    "platform": "MESSENGER",
    "organizationId": "org123",
    "createdAt": "2025-01-01T10:00:00Z",
    "startedAt": "2025-01-01T10:05:00Z",
    "scheduledAt": null,
    "useAiPersonalization": true,
    "hasMedia": false,
    "mediaType": null
  },
  "metrics": {
    "totalRecipients": 1000,
    "sent": 750,
    "delivered": 600,
    "read": 200,
    "failed": 50,
    "replied": 10,
    "pending": 200
  },
  "statusDistribution": {
    "SENT": 750,
    "DELIVERED": 600,
    "READ": 200,
    "FAILED": 50
  },
  "progress": {
    "percentage": 75,
    "isActive": true,
    "estimatedTimeRemaining": 120
  },
  "recentErrors": [
    {
      "id": "msg123",
      "message": "Recipient unavailable",
      "failedAt": "2025-01-01T10:10:00Z",
      "contactName": "John Doe"
    }
  ],
  "timestamp": "2025-01-01T10:15:00Z"
}
```

**UI Polling Example:**
```typescript
// Poll every 2 seconds while campaign is active
const pollCampaignStatus = async (campaignId: string) => {
  const response = await fetch(`/api/campaigns/${campaignId}/status`);
  const data = await response.json();
  
  if (data.progress.isActive) {
    setTimeout(() => pollCampaignStatus(campaignId), 2000);
  }
  
  return data;
};
```

#### 8. Org Integrity & Safety Checks

**Implemented Safeguards:**

1. **Campaign Creation:**
   - All campaigns must have valid `organizationId`
   - Campaigns can only be created by authenticated users
   - Facebook page must belong to organization
   - Contact IDs validated against organization

2. **Campaign Access:**
   - All GET/DELETE/SEND operations verify `organizationId` matches session
   - 403 Forbidden if org mismatch
   - 404 Not Found if campaign doesn't exist in routed DB

3. **Database Routing:**
   - Uses `getPrismaForOrg(organizationId)` for all operations
   - Consistent routing (same org → same DB)
   - Fallback to default DB if multi-DB disabled

4. **Error Messages:**
   - Clear distinction between:
     - "Not found" (doesn't exist)
     - "Not found in routed DB" (multi-DB issue)
     - "Access denied" (wrong org)
   - Includes DB index and host in logs for debugging

5. **Data Validation:**
   - sendToAll and targetContactIds mutually exclusive
   - All contacts must belong to same page
   - Empty contact lists rejected
   - Scheduled time must be in future

## Testing Plan

### Manual Testing

#### Test 1: Immediate Send to Selected Contacts (No Media)
```bash
# 1. Create campaign
curl -X POST http://localhost:3000/api/campaigns \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "name": "Test Campaign 1",
    "platform": "MESSENGER",
    "facebookPageId": "YOUR_PAGE_ID",
    "targetingType": "SPECIFIC_CONTACTS",
    "targetContactIds": ["contact1", "contact2", "contact3"],
    "templateId": "YOUR_TEMPLATE_ID"
  }'

# 2. Send campaign
curl -X POST http://localhost:3000/api/campaigns/CAMPAIGN_ID/send \
  -H "Cookie: your-session-cookie"

# 3. Poll status
curl http://localhost:3000/api/campaigns/CAMPAIGN_ID/status \
  -H "Cookie: your-session-cookie"
```

**Expected Results:**
- Campaign created with status `PENDING`
- Logs show org ID and routed DB index/host
- Campaign transitions to `SENDING`
- Messages sent in parallel batches (batch size 10)
- Status API shows progress percentage
- Campaign completes with `COMPLETED` status
- Sent count matches contact count

#### Test 2: Send-to-All with Media
```bash
curl -X POST http://localhost:3000/api/campaigns \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "name": "Product Announcement",
    "platform": "MESSENGER",
    "facebookPageId": "YOUR_PAGE_ID",
    "targetingType": "ALL_CONTACTS",
    "sendToAll": true,
    "templateId": "YOUR_TEMPLATE_ID",
    "mediaUrl": "https://yourdomain.com/product.jpg",
    "mediaType": "image"
  }'
```

**Expected Results:**
- All contacts for page/platform fetched
- Media URL validated
- Media included in each message
- Media delivered successfully
- Media file cleaned up after completion

#### Test 3: Scheduled Send (Future)
```bash
curl -X POST http://localhost:3000/api/campaigns \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "name": "Scheduled Campaign",
    "platform": "MESSENGER",
    "facebookPageId": "YOUR_PAGE_ID",
    "targetingType": "SPECIFIC_CONTACTS",
    "targetContactIds": ["contact1", "contact2"],
    "templateId": "YOUR_TEMPLATE_ID",
    "scheduledAt": "2025-12-31T10:00:00Z"
  }'
```

**Expected Results:**
- Campaign created with status `SCHEDULED`
- Campaign does not send immediately
- Cron job picks it up at scheduled time
- Campaign transitions to `SENDING` at scheduled time
- Messages sent successfully

#### Test 4: AI-Generated Messages
```bash
curl -X POST http://localhost:3000/api/campaigns/create-with-messages \
  -H "Content-Type: application/json" \
  -H "Cookie: your-session-cookie" \
  -d '{
    "name": "Personalized Outreach",
    "platform": "MESSENGER",
    "facebookPageId": "YOUR_PAGE_ID",
    "targetingType": "SPECIFIC_CONTACTS",
    "targetContactIds": ["contact1", "contact2"],
    "useAiPersonalization": true,
    "aiCustomInstructions": "Be friendly and professional",
    "templateContent": "Hi {firstName}!"
  }'
```

**Expected Results:**
- Campaign created immediately
- Background job starts AI generation
- Each contact gets personalized message
- Messages stored in `aiMessagesMap`
- Campaign ready to send with AI messages

#### Test 5: Multi-DB Sanity Check
```bash
# Ensure ENABLE_MULTI_DB=true and DB1/DB2 configured

# 1. Check logs for DB routing
tail -f .next/server.log | grep "Routed DB"

# 2. Create campaign and verify:
# - Logs show dbIndex (0, 1, or 2)
# - Logs show dbUrlHost
# - Campaign and contacts exist in routed DB
# - No "Not found in routed DB" errors
```

**Expected Results:**
- Logs show correct DB index based on org hash
- Same org always routes to same DB
- Data accessible from routed DB
- No cross-DB data leakage

### Verification Checklist

- [ ] Campaigns created in correct DB based on org ID
- [ ] All campaign APIs use multi-DB routing
- [ ] Logs include org ID, DB index, and DB host
- [ ] Scheduled campaigns sent at correct time
- [ ] Send-to-all fetches all contacts for page
- [ ] Selected contacts validated against org/page
- [ ] Media URLs validated and converted to full URLs
- [ ] AI messages generated and cached
- [ ] Status API provides real-time metrics
- [ ] Errors logged with DB context
- [ ] Rate limiting handled with backoff
- [ ] Campaigns complete successfully
- [ ] Media cleaned up after completion

## Database Schema (Relevant Fields)

### Campaign Table
```prisma
model Campaign {
  id               String         @id @default(cuid())
  name             String
  description      String?
  status           CampaignStatus @default(DRAFT)
  platform         Platform
  messageTag       MessageTag?
  facebookPageId   String
  scheduledAt      DateTime?
  startedAt        DateTime?
  completedAt      DateTime?
  organizationId   String        // For multi-DB routing
  createdById      String
  templateId       String?
  targetingType    TargetingType
  targetContactIds String[]
  targetTags       String[]
  targetStageIds   String[]
  rateLimit        Int            @default(3600)
  totalRecipients  Int            @default(0)
  sentCount        Int            @default(0)
  deliveredCount   Int            @default(0)
  readCount        Int            @default(0)
  failedCount      Int            @default(0)
  repliedCount     Int            @default(0)
  
  // Scheduling
  autoFetchEnabled Boolean   @default(false)
  includeTags      String[]
  excludeTags      String[]
  lastFetchAt      DateTime?
  fetchCount       Int       @default(0)
  
  // AI Personalization
  useAiPersonalization Boolean @default(false)
  aiCustomInstructions String?
  aiMessagesMap        Json?
  
  // Media
  mediaUrl   String?
  mediaType  String?
}
```

### Message Table
```prisma
model Message {
  id                String        @id @default(cuid())
  content           String
  platform          Platform
  status            MessageStatus @default(PENDING)
  messageTag        MessageTag?
  facebookMessageId String?
  contactId         String
  conversationId    String?
  campaignId        String?      // Links to campaign
  isFromBusiness    Boolean      @default(true)
  sentAt            DateTime?
  deliveredAt       DateTime?
  readAt            DateTime?
  failedAt          DateTime?
  errorMessage      String?
  attachments       Json?        // Media attachments
  createdAt         DateTime     @default(now())
}
```

## Next Steps (Optional Enhancements)

1. **Retry Failed Messages:**
   - Add `/api/campaigns/[id]/retry-failed` endpoint
   - Resend messages with `status=FAILED`
   - Track retry count per message

2. **Campaign Analytics Dashboard:**
   - Delivery rate over time
   - Read rate by contact
   - Response rate tracking
   - Best send times

3. **A/B Testing:**
   - Split campaigns with variant messages
   - Track performance by variant
   - Auto-select winner

4. **Advanced Scheduling:**
   - Recurring campaigns
   - Time zone-aware sending
   - Optimal send time prediction

5. **Enhanced AI Features:**
   - Sentiment-aware personalization
   - Product recommendation integration
   - Dynamic content generation

## Configuration

### Environment Variables
```bash
# Multi-DB Configuration
ENABLE_MULTI_DB=true
DB_ROUTING_STRATEGY=hash  # or 'round-robin' or 'load-aware'

# Database URLs (configure 1-10)
DATABASE_URL_0=postgresql://...
DATABASE_URL_1=postgresql://...
DATABASE_URL_2=postgresql://...

# Direct URLs (optional, for migrations)
DIRECT_URL_0=postgresql://...
DIRECT_URL_1=postgresql://...

# Cron Secret (for scheduled campaigns)
CRON_SECRET=your-secret-here

# AI Configuration
GOOGLE_AI_API_KEY=your-key-here
```

### Vercel Cron Configuration (`vercel.json`)
```json
{
  "crons": [
    {
      "path": "/api/cron/send-scheduled",
      "schedule": "* * * * *"
    }
  ]
}
```

## Troubleshooting

### Campaign Not Found in Routed DB
**Symptom:** 404 error with "not found in routed database"

**Causes:**
- DB1/DB2 connectivity issues
- Data not replicated to correct DB
- Org ID routing to wrong DB

**Fix:**
1. Check DB connectivity: Run `scripts/verify-supabase-projects.ts`
2. Verify routing: Check logs for DB index/host
3. Verify data: Query both DBs to find where data exists
4. Check replication: Ensure data synced across DBs

### Messages Not Sending
**Symptom:** Campaign stuck in `SENDING` status

**Causes:**
- Rate limiting by Facebook
- Invalid PSIDs/SIDs
- Token expiration
- Database connection pool exhaustion

**Fix:**
1. Check logs for rate limit warnings
2. Verify contacts have valid PSIDs
3. Check Facebook page token
4. Increase batch delay or reduce batch size

### AI Generation Slow
**Symptom:** AI message generation takes too long

**Causes:**
- Limited API keys
- High concurrency
- Large contact list

**Fix:**
1. Add more Google AI API keys
2. Reduce concurrency limit
3. Use background generation (already implemented)
4. Pre-generate messages before scheduling

## Conclusion

The campaign system is now fully multi-DB safe with comprehensive logging, robust error handling, and production-ready features including scheduling, media support, AI generation, and real-time status tracking.

All APIs enforce org-level data access controls and route to the correct database automatically. The system handles edge cases gracefully and provides clear, actionable error messages for debugging.

