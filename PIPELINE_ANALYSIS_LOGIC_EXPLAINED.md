# Pipeline Analysis Feature - Detailed Logic Explanation

## Overview

The Pipeline Analysis feature is an AI-powered system that:
1. Analyzes Facebook Messenger and Instagram conversations
2. Calculates lead scores using AI
3. Automatically assigns contacts to appropriate pipeline stages
4. Processes contacts in batches with real-time progress tracking

## High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER INITIATES ANALYSIS                     │
│  (Click "Analyze Pipeline" button in UI)                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-002: Pipeline Analysis API Endpoint                      │
│  - Validates authentication & authorization                     │
│  - Validates request body (facebookPageId, forceUpdateExisting)│
│  - Verifies user owns the Facebook page                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-004: Start Pipeline Analysis Service                      │
│  - Checks for existing active jobs (prevents duplicates)        │
│  - Creates SyncJob record with status PENDING                   │
│  - Starts async execution (non-blocking)                       │
│  - Returns jobId immediately                                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-010: Batch Processing Coordinator                     │
│  - Updates job status to IN_PROGRESS                            │
│  - Fetches FacebookPage with pipeline configuration            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-006: Contact Filtering and Selection                      │
│  - Queries contacts based on:                                   │
│    • facebookPageId                                             │
│    • forceUpdateExisting flag                                    │
│    • Pipeline existence (skip existing vs update all)          │
│    • Must have messengerPSID OR instagramSID                     │
│  - Returns filtered contact array                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-007: Conversation Fetching Service                        │
│  - Separates participant IDs into Messenger PSIDs & Instagram  │
│  - Fetches Messenger conversations from Facebook Graph API     │
│  - Fetches Instagram conversations (if any Instagram SIDs)    │
│  - Handles API errors gracefully (returns partial results)     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-008: Conversation Mapping Utility                         │
│  - Creates Map<participantId, Conversation> for O(1) lookup    │
│  - Maps Messenger conversations by PSID                         │
│  - Maps Instagram conversations by SID                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-015: Contact Processing Loop (Parallel Processing)        │
│  For each contact (with dynamic concurrency):                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 1. Check cancellation (TASK-005)                          │  │
│  │ 2. Find conversation from map (TASK-008 result)          │  │
│  │ 3. Fetch messages from conversation (TASK-019)            │  │
│  │ 4. Run AI analysis (TASK-009)                             │  │
│  │ 5. Build update data object                               │  │
│  │ 6. Return update data or null if failed                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-009: AI Analysis Orchestrator (Per Contact)              │
│  - Tries fast-detailed-analysis first (with timeout)           │
│  - Falls back to enhanced-analysis-v2 if fast fails            │
│  - Returns analysis result with metadata (usedFallback flag)   │
│  - Returns null if all methods fail (doesn't throw)           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-011: Contact Update Batch Processor                       │
│  - Processes batch of analyzed contacts                         │
│  - For each contact:                                           │
│    • Determines pipeline stage (TASK-012)                       │
│    • Checks downgrade prevention                                │
│    • Builds update data                                         │
│  - Executes batch update in database transaction                │
│  - Creates activity log entries (TASK-016)                     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-012: Stage Assignment Logic                               │
│  - Uses leadScore from AI analysis (0-100)                      │
│  - Matches score to pipeline stage score ranges                 │
│  - Returns appropriate PipelineStage or null                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-013: Job Progress Tracking (Periodic Updates)             │
│  - Updates SyncJob with:                                         │
│    • analyzedCount (increments)                                 │
│    • failedCount (increments)                                   │
│    • errors array (appends)                                      │
│    • lastProgressAt timestamp                                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-021: Error Aggregation                                    │
│  - Collects errors from failed contacts                         │
│  - Formats errors consistently                                 │
│  - Limits array size (max 100 errors)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-010: Final Job Status Update                              │
│  - Aggregates all errors (TASK-021)                             │
│  - Updates job status to COMPLETED or FAILED                   │
│  - Includes final progress counts and errors                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  TASK-003: Job Status Polling (Frontend)                       │
│  - Frontend polls this endpoint every 2 seconds               │
│  - Returns current job status, progress, errors                 │
│  - Stops polling when job completes/fails                      │
└─────────────────────────────────────────────────────────────────┘
```

## Detailed Step-by-Step Logic

### Phase 1: Job Initiation

#### Step 1.1: User Action
- User clicks "Analyze Pipeline" button (TASK-014)
- Button component calls API endpoint (TASK-002)

#### Step 1.2: API Validation (TASK-002)
```typescript
// Request validation using Zod schema (TASK-018)
{
  facebookPageId: string (UUID),
  forceUpdateExisting: boolean (optional, default: false)
}

// Validation checks:
1. User authenticated? → 401 if not
2. Request body valid? → 400 if invalid
3. User owns Facebook page? → 404 if not
4. All checks pass → Proceed
```

#### Step 1.3: Job Creation (TASK-004)
```typescript
// Logic:
1. Check for existing active job (status: PENDING or IN_PROGRESS)
   - If exists → Return existing jobId
   - If not → Continue
2. Create new SyncJob record:
   {
     status: 'PENDING',
     facebookPageId: string,
     forceUpdateExisting: boolean,
     analyzedCount: 0,
     failedCount: 0,
     errors: []
   }
3. Start async execution (don't await):
   executePipelineAnalysis(jobId, facebookPageId, forceUpdateExisting)
4. Return PipelineAnalysisResult:
   {
     success: true,
     jobId: string,
     message: "Analysis started"
   }
```

### Phase 2: Contact Selection

#### Step 2.1: Contact Filtering (TASK-006)
```typescript
// Query logic:
1. Fetch FacebookPage with autoPipeline relation
2. Determine update mode:
   - If forceUpdateExisting = true → UPDATE_ALL
   - If pipeline exists → SKIP_EXISTING (only unassigned contacts)
   - If no pipeline → UPDATE_ALL (all contacts)
3. Query contacts with filters:
   WHERE facebookPageId = ?
   AND (messengerPSID IS NOT NULL OR instagramSID IS NOT NULL)
   AND (if SKIP_EXISTING: pipelineId IS NULL)
4. Return contacts with fields:
   {
     id, messengerPSID, instagramSID, 
     pipelineId, stageId, lastInteraction
   }
```

### Phase 3: Conversation Fetching

#### Step 3.1: Fetch Conversations (TASK-007)
```typescript
// Process:
1. Initialize FacebookClient with pageAccessToken
2. Separate participant IDs:
   - Messenger PSIDs: contacts with messengerPSID
   - Instagram SIDs: contacts with instagramSID
3. Fetch Messenger conversations:
   - For each PSID, query Facebook Graph API
   - Handle rate limiting
   - Continue on errors (log, don't fail)
4. Fetch Instagram conversations:
   - For each SID, query Instagram Graph API
   - Handle rate limiting
   - Continue on errors (log, don't fail)
5. Return:
   {
     messengerConversations: Conversation[],
     instagramConversations: Conversation[]
   }
```

#### Step 3.2: Map Conversations (TASK-008)
```typescript
// Create lookup maps:
1. Create Map<string, Conversation> for Messenger
   - Key: messengerPSID
   - Value: Conversation object
2. Create Map<string, Conversation> for Instagram
   - Key: instagramSID
   - Value: Conversation object
3. Handle edge cases:
   - Invalid participant structure → Skip, log warning
   - Duplicate participants → Use first occurrence
   - Missing participants array → Skip
4. Return both maps for O(1) lookup
```

### Phase 4: Contact Processing (Parallel)

#### Step 4.1: Process Each Contact (TASK-015)
```typescript
// Parallel processing with dynamic concurrency:
For each contact (in batches):

  1. Check Cancellation (TASK-005):
     - Query SyncJob status
     - If CANCELLED → Stop processing, return null
     - If not → Continue

  2. Find Conversation:
     - Try messengerPSID in Messenger map
     - Try instagramSID in Instagram map
     - If not found → Mark as failed, continue to next

  3. Fetch Messages (TASK-019):
     - Extract messages from conversation object
     - Handle platform-specific formats (Messenger vs Instagram)
     - Filter out system messages
     - Return Message[] array

  4. AI Analysis (TASK-009):
     - Try fast-detailed-analysis first (with timeout)
     - If fails → Try enhanced-analysis-v2
     - If both fail → Return null (mark as failed)
     - Return analysis result with metadata

  5. Build Update Data:
     {
       contactId: string,
       aiAnalysis: AIAnalysisResult | null,
       aiContext: string,
       leadScore: number | null,
       leadStatus: LeadStatus,
       // ... other fields
     }

  6. Return update data or null if processing failed
```

#### Step 4.2: AI Analysis Orchestration (TASK-009)
```typescript
// Fallback strategy:
1. Try fast-detailed-analysis:
   - Call analyzeConversationFast(messages, pipelineStages)
   - Timeout: 30 seconds
   - If success → Return result with usedFallback: false
   - If fails → Log error, continue to step 2

2. Try enhanced-analysis-v2:
   - Call analyzeConversationEnhanced(messages, pipelineStages)
   - Timeout: 60 seconds
   - If success → Return result with usedFallback: true
   - If fails → Log error, continue to step 3

3. All methods failed:
   - Return null (doesn't throw)
   - Contact will be marked as failed in batch processor

// Return structure:
{
  analysis: AIAnalysisResult | null,
  usedFallback: boolean,
  retryCount: number
}
```

### Phase 5: Batch Updates

#### Step 5.1: Process Batch (TASK-011)
```typescript
// Batch update logic:
1. Handle auto-create mode:
   - If pipelineId === 'TEMP' → Store analysis only, no stage assignment
   - Skip to step 5

2. Fetch pipeline and stages:
   - Query Pipeline with stages
   - Validate pipeline exists

3. Fetch contacts in batch:
   - Query all contacts by IDs
   - Load current stage information

4. Filter contacts by update mode:
   - SKIP_EXISTING: Only update contacts without pipelineId
   - UPDATE_ALL: Update all contacts

5. For each contact in batch:
   a. Determine stage (TASK-012):
      - Use leadScore from AI analysis
      - Match to stage score ranges
      - Return PipelineStage or null
   
   b. Check downgrade prevention:
      - If shouldPreventDowngrade(currentStage, newStage) → Skip
      - Otherwise → Proceed
   
   c. Build update data:
      {
        aiAnalysis: AIAnalysisResult,
        aiContext: string,
        leadScore: number,
        leadStatus: LeadStatus,
        pipelineId: string,
        stageId: string | null,
        // ... other fields
      }

6. Execute batch update in transaction:
   - Update all contacts atomically
   - If any fails → Rollback entire batch

7. Create activity log entries (TASK-016):
   - For each contact with stage change
   - Log: contactId, newStageId, previousStageId, reason
```

#### Step 5.2: Stage Assignment (TASK-012)
```typescript
// Stage matching logic:
1. Input:
   - leadScore: number (0-100) or null
   - leadStatus: LeadStatus enum
   - stages: PipelineStage[] (sorted by order)
   - currentStage: PipelineStage | null

2. Handle null leadScore:
   - Return null (no stage assignment)
   - Or return first stage (based on business logic)

3. Find matching stage:
   - Use findBestMatchingStage(leadScore, stages)
   - Match score to stage.leadScoreMin and leadScoreMax ranges
   - Return first matching stage

4. Handle edge cases:
   - Score outside 0-100 → Clamp or return null
   - Score on boundary → Include in range
   - No matching stage → Return null

5. Return PipelineStage | null
```

### Phase 6: Progress Tracking

#### Step 6.1: Update Progress (TASK-013)
```typescript
// Periodic progress updates:
1. Called after each batch or periodically
2. Update SyncJob:
   {
     analyzedCount: increment by batch size,
     failedCount: increment by failed contacts,
     errors: append new errors (don't overwrite),
     lastProgressAt: new Date()
   }
3. Use withRetry for resilience:
   - Retry on database connection errors
   - Log errors but don't throw (non-critical)
4. Atomic updates to prevent race conditions
```

#### Step 6.2: Error Aggregation (TASK-021)
```typescript
// Error formatting:
1. Collect errors from failed contacts:
   - Platform (messenger/instagram)
   - Contact ID
   - Error message
   - Error code (if available)

2. Format consistently:
   {
     platform: string,
     id: string,
     error: string,
     code?: number
   }

3. Limit array size:
   - Max 100 errors
   - Add truncation indicator if exceeded

4. Return formatted error array
```

### Phase 7: Job Completion

#### Step 7.1: Final Status Update (TASK-010)
```typescript
// Final job update:
1. Aggregate all errors (TASK-021)
2. Calculate final metrics:
   - Total analyzed: analyzedCount
   - Total failed: failedCount
   - Total contacts: analyzedCount + failedCount
   - Success rate: (analyzedCount / total) * 100

3. Update job status:
   - If any critical errors → FAILED
   - If all contacts processed → COMPLETED
   - If cancelled → CANCELLED

4. Final SyncJob update:
   {
     status: 'COMPLETED' | 'FAILED' | 'CANCELLED',
     analyzedCount: number,
     failedCount: number,
     errors: Error[],
     completedAt: new Date()
   }
```

### Phase 8: Frontend Updates

#### Step 8.1: Progress Display (TASK-017)
```typescript
// Frontend polling:
1. Component receives jobId from button click
2. Poll status endpoint (TASK-003) every 2 seconds:
   - GET /api/facebook/analyze-pipeline/status/[jobId]
   - Returns current job status and progress

3. Display progress:
   - Progress bar with percentage
   - Analyzed count / Total count
   - Failed count
   - Job status badge (PENDING, IN_PROGRESS, COMPLETED, FAILED)

4. Stop polling when:
   - Job status is COMPLETED
   - Job status is FAILED
   - Job status is CANCELLED
   - Component unmounts

5. Call callbacks:
   - onComplete() when job completes
   - onError() when job fails
```

## Key Design Patterns

### 1. **Non-Blocking Job Execution**
- Job creation returns immediately with jobId
- Actual processing happens asynchronously
- Frontend polls for status updates

### 2. **Graceful Error Handling**
- Individual contact failures don't stop entire job
- Errors are collected and aggregated
- Partial results are returned when possible

### 3. **Dynamic Concurrency**
- Uses cached concurrency limits
- Adjusts based on system resources
- Prevents resource exhaustion

### 4. **Fallback Strategy**
- Primary AI method (fast-detailed-analysis)
- Fallback AI method (enhanced-analysis-v2)
- Graceful degradation if all methods fail

### 5. **Batch Processing**
- Processes contacts in batches
- Database transactions for atomicity
- Efficient bulk updates

### 6. **Cancellation Support**
- Periodic cancellation checks
- Graceful stop on cancellation
- Status update to CANCELLED

## Data Flow Summary

```
User Input
  ↓
API Validation (Zod)
  ↓
Job Creation (SyncJob record)
  ↓
Contact Selection (filtered query)
  ↓
Conversation Fetching (Facebook API)
  ↓
Conversation Mapping (Map structures)
  ↓
Parallel Contact Processing
  ├─→ Message Fetching
  ├─→ AI Analysis (with fallback)
  └─→ Update Data Building
  ↓
Batch Updates (database transaction)
  ├─→ Stage Assignment
  ├─→ Downgrade Prevention
  └─→ Activity Logging
  ↓
Progress Tracking (periodic updates)
  ↓
Error Aggregation
  ↓
Final Status Update
  ↓
Frontend Polling (real-time display)
```

## Performance Optimizations

1. **O(1) Conversation Lookup**: Map structures instead of array searches
2. **Batch Database Updates**: Single transaction for multiple contacts
3. **Parallel Processing**: Dynamic concurrency for contact analysis
4. **Early Stopping**: Stop fetching when all participants found
5. **Incremental Progress**: Update progress periodically, not after each contact
6. **Error Batching**: Collect errors and update in batches

## Error Scenarios & Handling

1. **Contact without conversation**: Mark as failed, continue processing
2. **AI analysis failure**: Try fallback method, mark as failed if all fail
3. **Database errors**: Retry with exponential backoff
4. **API rate limiting**: Implement retry logic with backoff
5. **Job cancellation**: Check periodically, stop gracefully
6. **Network timeouts**: Handle with timeouts, retry if appropriate

## Testing Strategy

1. **Unit Tests**: Each task independently testable
2. **Integration Tests**: Test task interactions
3. **End-to-End Tests**: Full flow from button click to completion
4. **Error Scenarios**: Test all error paths
5. **Performance Tests**: Test with large contact lists
6. **Cancellation Tests**: Test cancellation at various points

---

This detailed logic explanation covers the complete pipeline analysis workflow from user initiation to final completion, including all error handling, optimizations, and design patterns used throughout the system.

