# 👥 Contacts System - Visual Summary

**Quick Reference Guide** | November 12, 2025

---

## 🎯 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   CONTACTS SYSTEM ARCHITECTURE                   │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Facebook   │◄────────┤   Webhook    │────────►│   Database   │
│   Graph API  │         │   Handler    │         │  (Contacts)  │
└──────┬───────┘         └──────────────┘         └──────┬───────┘
       │                                                   │
       │ Sync                                             │ Query
       ↓                                                   ↓
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ Background   │────────►│  Google AI   │         │     API      │
│ Sync Worker  │ Analyze │   (Gemini)   │         │   Endpoints  │
└──────────────┘         └──────────────┘         └──────┬───────┘
                                                          │
                                                          ↓
                                                   ┌──────────────┐
                                                   │  Next.js UI  │
                                                   │  Components  │
                                                   └──────────────┘
```

---

## 📊 Contact Data Model

```
Contact
├── 🆔 Identifiers
│   ├── id (CUID)
│   ├── messengerPSID (Facebook Page-Scoped ID)
│   └── instagramSID (Instagram-Scoped ID)
│
├── 👤 Profile Information
│   ├── firstName
│   ├── lastName
│   ├── profilePicUrl
│   ├── locale
│   └── timezone
│
├── 📱 Platform Flags
│   ├── hasMessenger (boolean)
│   └── hasInstagram (boolean)
│
├── 🏢 Organization
│   ├── organizationId
│   └── facebookPageId
│
├── 📈 CRM Tracking
│   ├── pipelineId (nullable)
│   ├── stageId (nullable)
│   ├── stageEnteredAt
│   ├── leadScore (0-100)
│   └── leadStatus (NEW, CONTACTED, QUALIFIED, etc.)
│
├── 🏷️ Metadata
│   ├── tags (string array)
│   ├── notes (text)
│   ├── aiContext (text)
│   ├── aiContextUpdatedAt
│   └── lastInteraction
│
└── 🔗 Relations
    ├── groups (ContactGroup[])
    ├── messages (Message[])
    ├── conversations (Conversation[])
    └── activities (ContactActivity[])
```

---

## 🔄 Contact Sync Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      SYNC PROCESS                                │
└─────────────────────────────────────────────────────────────────┘

Step 1: Trigger Sync
   │
   ├─→ Manual: User clicks "Sync" button
   └─→ Automatic: Scheduled background job (hourly)

Step 2: Fetch Conversations
   │
   ├─→ Messenger: GET /{pageId}/conversations
   └─→ Instagram: GET /{igAccountId}/conversations

Step 3: Extract Participants
   │
   └─→ PSIDs and SIDs from conversation participants

Step 4: Analyze with AI (for each contact)
   │
   ├─→ Extract messages from conversation
   ├─→ Send to Google Gemini 2.0 Flash Exp
   ├─→ Generate 2-3 sentence context summary
   └─→ Rotate through 9 API keys

Step 5: Upsert Contact
   │
   ├─→ If exists: Update profile + aiContext
   └─→ If new: Create with all data

Step 6: Update Statistics
   │
   └─→ Set page.lastSyncedAt = now()

┌────────────────────────────────────────────────────────────────┐
│ ⏱️ Timing: ~2 seconds per contact (1s AI + 1s delay)          │
│ 📊 Scale: 50 contacts = ~2 minutes                            │
└────────────────────────────────────────────────────────────────┘
```

---

## 🖥️ UI Components Map

```
┌─────────────────────────────────────────────────────────────────┐
│                        /contacts PAGE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Header Section                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Contacts                            [AI Analyze All]        │ │
│  │ Manage your messenger and           [Create Campaign]      │ │
│  │ Instagram contacts                                          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Filters Bar                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [Search...] [Date Range] [Page ▼] [Platform ▼]            │ │
│  │ [Score ▼] [Stage ▼] [Tags ▼]                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Bulk Actions Toolbar (when items selected)                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ✓ 15 contacts selected          [Add Tags ▼]              │ │
│  │ [Clear selection]                [Move to Stage ▼]         │ │
│  │                                  [Delete]                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Data Table                                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [☑] Contact    Page  Platforms  Score  Stage  Tags  Added │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ [☑] John Doe   FB    M,I        75     Lead   vip   Nov 1 │ │
│  │ [☐] Jane Smith FB    M          50     Contact-   Nov 2    │ │
│  │ [☐] Bob Wilson IG    I          25     New    -     Nov 3 │ │
│  │ ...                                                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Pagination                                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Page 1 of 10          [◄ Previous] [Next ►]      245 total│ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Filter Types

```
┌─────────────────────────────────────────────────────────────────┐
│                       FILTER OPTIONS                             │
└─────────────────────────────────────────────────────────────────┘

1. 🔍 Search
   └─→ firstName OR lastName (case-insensitive, partial match)

2. 📅 Date Range
   └─→ createdAt BETWEEN startDate AND endDate

3. 📄 Page
   └─→ facebookPageId = selected

4. 📱 Platform
   ├─→ All: No filter
   ├─→ Messenger: hasMessenger = true
   ├─→ Instagram: hasInstagram = true
   └─→ Both: hasMessenger AND hasInstagram

5. ⭐ Score Range
   ├─→ 0-25 (Cold)
   ├─→ 26-50 (Warm)
   ├─→ 51-75 (Hot)
   └─→ 76-100 (Very Hot)

6. 📊 Pipeline Stage
   └─→ stageId = selected (grouped by pipeline)

7. 🏷️ Tags
   └─→ ALL selected tags must match (AND logic)

8. 🔄 Sort
   ├─→ By Name (A-Z / Z-A)
   ├─→ By Score (High-Low / Low-High)
   └─→ By Date (Newest / Oldest)

┌────────────────────────────────────────────────────────────────┐
│ 💡 TIP: All filters work together (AND logic)                 │
│ Example: Search "John" + Tags "vip,customer" + Score 50-100   │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔧 API Endpoints

```
┌─────────────────────────────────────────────────────────────────┐
│                      API ROUTES SUMMARY                          │
└─────────────────────────────────────────────────────────────────┘

📋 Contact List & Search
GET    /api/contacts                    List with filters
GET    /api/contacts/ids                Get all IDs (for bulk ops)
GET    /api/contacts/total-count        Count all contacts

👤 Individual Contact
GET    /api/contacts/[id]               Get details
PATCH  /api/contacts/[id]               Update contact
DELETE /api/contacts/[id]               Delete contact

🏷️ Tags Management
POST   /api/contacts/[id]/tags          Add/remove tags
       { action: 'add|remove', tags: [] }

📊 Pipeline Management
POST   /api/contacts/[id]/move          Move to stage
       { stageId: string, notes?: string }

🔄 Bulk Operations
POST   /api/contacts/bulk               Bulk actions
       { action: string, contactIds: [], data: {} }
       
       Actions:
       - addTags
       - removeTags
       - moveToStage
       - updateLeadScore
       - delete

🤖 AI Analysis
POST   /api/contacts/analyze-all        Bulk AI analysis
       { limit: 100, skipIfHasContext: true }
```

---

## 📦 Bulk Operations

```
┌─────────────────────────────────────────────────────────────────┐
│                    BULK OPERATIONS FLOW                          │
└─────────────────────────────────────────────────────────────────┘

Step 1: Select Contacts
   │
   ├─→ Option A: Select on current page
   │   └─→ Checkbox in table header
   │
   └─→ Option B: Select all across pages
       ├─→ Check all on page
       ├─→ Click "Select all contacts across all pages"
       └─→ Fetches all matching IDs (respects filters)

Step 2: Choose Action
   │
   ├─→ Add Tags
   │   └─→ Dropdown of available tags
   │
   ├─→ Remove Tags
   │   └─→ Dropdown of tags on selected contacts
   │
   ├─→ Move to Stage
   │   └─→ Grouped dropdown (by pipeline)
   │
   └─→ Delete
       └─→ Confirmation dialog

Step 3: Execute
   │
   ├─→ POST /api/contacts/bulk
   ├─→ Verify authorization
   ├─→ Update all contacts (parallel)
   ├─→ Log activities
   └─→ Return success

Step 4: UI Update
   │
   ├─→ Show success toast
   ├─→ Clear selection
   └─→ Refresh page

┌────────────────────────────────────────────────────────────────┐
│ 🚀 Performance: Parallel updates with Promise.all()           │
│ 🔒 Security: Verifies all contacts belong to organization     │
└────────────────────────────────────────────────────────────────┘
```

---

## 🤖 AI Context Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI ANALYSIS SYSTEM                            │
└─────────────────────────────────────────────────────────────────┘

Model: Google Gemini 2.0 Flash Exp
Keys: 9-key rotation system for rate limiting
Trigger: Automatic (sync) or Manual (Analyze All button)

┌────────────────────────────────────────────────────────────────┐
│ Input: Conversation Messages                                   │
├────────────────────────────────────────────────────────────────┤
│ User: Hi, I'm interested in your enterprise plan              │
│ Page: Great! Can I ask what size team you have?               │
│ User: About 50 people. Need it by Q1 2025                     │
│ Page: Perfect, let me send you a quote...                     │
└────────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────────┐
│ Google AI Processing                                           │
│ Prompt: "Analyze this conversation and provide a concise      │
│ 2-3 sentence summary focusing on needs, interests, and        │
│ specific requests..."                                          │
└────────────────────────────────────────────────────────────────┘
                          ↓
┌────────────────────────────────────────────────────────────────┐
│ Output: AI Context                                             │
├────────────────────────────────────────────────────────────────┤
│ "Customer inquired about enterprise plan for 50-person team.  │
│ Interested in Q1 2025 implementation timeline. Quote          │
│ requested and will be sent."                                   │
└────────────────────────────────────────────────────────────────┘
                          ↓
                  Saved to contact.aiContext

┌────────────────────────────────────────────────────────────────┐
│ ⏱️ Rate Limiting: 1 second delay between API calls            │
│ 🔑 Key Rotation: Cycles through 9 keys automatically          │
│ 🛡️ Graceful Fail: Sync continues if AI fails                 │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔗 Pipeline Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                  CONTACT-PIPELINE RELATIONSHIP                   │
└─────────────────────────────────────────────────────────────────┘

Contact ──[optional]──► Pipeline ──[has many]──► Stages
   │
   └─────[optional]──► Stage

Assignment Methods:
├─→ 1. Manual (Individual)
│   └─→ From contact detail page → Move to Stage
│
├─→ 2. Manual (Bulk)
│   └─→ Select multiple → Bulk action → Move to Stage
│
└─→ 3. Automatic (Facebook Page Setting)
    ├─→ autoPipelineId: Target pipeline
    ├─→ autoPipelineMode:
    │   ├─→ SKIP_EXISTING: Only new contacts
    │   └─→ UPDATE_EXISTING: Re-evaluate all
    └─→ Applied during sync

Pipeline Views:
├─→ Contacts List with Stage Filter
│   └─→ Filter: Stage = "New Lead" → Shows all in that stage
│
└─→ Pipeline Kanban Board
    └─→ /pipelines/[id] → Horizontal columns per stage

Activity Tracking:
└─→ Every stage move creates ContactActivity
    ├─→ type: STAGE_CHANGED
    ├─→ fromStageId
    ├─→ toStageId
    └─→ userId
```

---

## 🎯 Campaign Targeting

```
┌─────────────────────────────────────────────────────────────────┐
│                  CAMPAIGN TARGETING OPTIONS                      │
└─────────────────────────────────────────────────────────────────┘

Target Type: PIPELINE_STAGES
├─→ Config: targetStageIds: ['stage1', 'stage2']
└─→ Query: WHERE stageId IN (targetStageIds)

Target Type: TAGS
├─→ Config: targetTags: ['vip', 'engaged']
└─→ Query: WHERE tags HAS 'vip' AND tags HAS 'engaged'

Target Type: CONTACT_GROUPS
├─→ Config: groups: [group1, group2]
└─→ Query: WHERE id IN (group.contactIds)

Target Type: SPECIFIC_CONTACTS
├─→ Config: targetContactIds: ['id1', 'id2']
└─→ Query: WHERE id IN (targetContactIds)

Target Type: ADVANCED_FILTERS
├─→ Config: targetFilters: { leadScore: 50-100, platform: 'messenger' }
└─→ Query: Complex where clause

Target Type: ALL_CONTACTS
└─→ Query: WHERE organizationId = orgId

┌────────────────────────────────────────────────────────────────┐
│ 💡 All targeting respects platform selection                  │
│    (hasMessenger for Messenger, hasInstagram for Instagram)   │
└────────────────────────────────────────────────────────────────┘
```

---

## 📈 Performance Metrics

```
┌─────────────────────────────────────────────────────────────────┐
│                     PERFORMANCE PROFILE                          │
└─────────────────────────────────────────────────────────────────┘

Database Queries
├─→ List contacts (20/page):     ~50-100ms  ✅ Fast (indexed)
├─→ Count total:                 ~20-50ms   ✅ Fast
├─→ Get single contact:          ~10-20ms   ✅ Instant
├─→ Update contact:              ~20-30ms   ✅ Fast
└─→ Bulk update (100 contacts):  ~500ms-1s  ✅ Acceptable

Sync Performance
├─→ Fetch conversations:         ~500ms-2s per page
├─→ AI analysis:                 ~1s per contact
├─→ Database upsert:             ~50ms per contact
└─→ Total: ~2s per contact (AI + delay)

Scaling
├─→ 50 contacts:    ~2 minutes
├─→ 100 contacts:   ~4 minutes
├─→ 500 contacts:   ~17 minutes
└─→ 1000 contacts:  ~35 minutes

Optimization Strategies
├─→ ✅ Database indexes on all query fields
├─→ ✅ Parallel bulk updates with Promise.all
├─→ ✅ Select only needed fields (exclude TEXT)
├─→ ✅ AI key rotation prevents rate limits
└─→ ✅ Background jobs for long-running syncs
```

---

## 🔒 Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     SECURITY ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────┘

Authentication Layer
├─→ NextAuth session check on every API route
└─→ Unauthorized → 401 response

Authorization Layer (Multi-Tenant)
├─→ All queries scoped by organizationId
├─→ session.user.organizationId enforced
└─→ Cross-org access → 404 (not revealed as unauthorized)

Data Isolation
├─→ Prisma where clauses always include organizationId
├─→ Bulk operations verify all IDs belong to organization
└─→ Foreign key constraints enforce relationships

API Security
├─→ CSRF protection via NextAuth
├─→ Rate limiting on AI endpoints
├─→ Input validation on all POST/PATCH
└─→ SQL injection prevention (Prisma ORM)

Future Enhancements
├─→ Field-level encryption for notes/aiContext
├─→ Role-based access control (RBAC)
├─→ Audit logging for deletions
└─→ Data retention policies
```

---

## 📚 Key Statistics

```
┌─────────────────────────────────────────────────────────────────┐
│                      SYSTEM STATISTICS                           │
└─────────────────────────────────────────────────────────────────┘

📊 Data Model
├─→ Contact Fields:           22 columns
├─→ Indexed Fields:           5 indexes
├─→ Unique Constraints:       1 (PSID + pageId)
└─→ Relations:                4 (groups, messages, convos, activities)

🔌 API Endpoints
├─→ Total Contact Routes:     9 endpoints
├─→ Query Parameters:         10 filter types
└─→ Bulk Actions:             5 action types

🖥️ UI Components
├─→ Filter Components:        7 components
├─→ Table Components:         3 components
└─→ Detail Components:        4 components

🤖 AI Integration
├─→ API Keys:                 9 (rotation)
├─→ Model:                    Gemini 2.0 Flash Exp
├─→ Analysis Time:            ~1s per contact
└─→ Triggers:                 2 (sync + manual)

📈 Features
├─→ Filter Types:             8 types
├─→ Sort Options:             3 fields × 2 directions
├─→ Bulk Operations:          5 actions
└─→ Campaign Targets:         6 strategies
```

---

## 🎨 Status Legend

```
✅ IMPLEMENTED    - Fully functional in production
⚠️ PARTIAL       - Schema exists, UI pending
❌ NOT STARTED   - Planned for future
🚀 IN PROGRESS   - Currently being developed
📊 ANALYTICS     - Data collected, dashboard pending
🔒 SECURITY      - Security-related feature
🤖 AI-POWERED    - Uses artificial intelligence
```

---

## 🚀 Quick Actions

```
┌─────────────────────────────────────────────────────────────────┐
│                      COMMON WORKFLOWS                            │
└─────────────────────────────────────────────────────────────────┘

Sync New Contacts
└─→ Settings → Integrations → [Sync] → Wait for completion

Find VIP Customers
└─→ Contacts → Tags filter: "vip" → Results

Bulk Tag Contacts
└─→ Contacts → Select all → Add Tags → Choose tag

Move to Pipeline Stage
└─→ Contacts → Select contacts → Move to Stage → Choose stage

Export Contact List
└─→ Contacts → Apply filters → [Export CSV] → Download

Create Campaign from Segment
└─→ Contacts → Apply filters → [Create Campaign] → Configure

Analyze All Contacts
└─→ Contacts → [AI Analyze All] → Wait for completion

View Contact Journey
└─→ Contacts → Click contact → Activity Timeline
```

---

**Last Updated:** November 12, 2025  
**Version:** 1.0  
**Status:** ✅ Complete & Production Ready

