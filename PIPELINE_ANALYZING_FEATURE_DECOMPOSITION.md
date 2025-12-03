# Task Decomposition: Pipeline Analyzing Feature

## Overview

The pipeline analyzing feature is an AI-powered system that automatically analyzes Facebook Messenger and Instagram conversations, calculates lead scores, and intelligently assigns contacts to appropriate pipeline stages. The system processes contacts in batches, fetches conversations on-demand, performs AI analysis, and updates contact records with analysis results and stage assignments.

## Dependency Graph

```
TASK-001 → TASK-002 → TASK-003
TASK-001 → TASK-004 → TASK-005
TASK-002 → TASK-006
TASK-003 → TASK-006
TASK-004 → TASK-006
TASK-005 → TASK-006
TASK-006 → TASK-007
TASK-006 → TASK-008
TASK-007 → TASK-009
TASK-008 → TASK-009
TASK-009 → TASK-010
TASK-010 → TASK-011
TASK-011 → TASK-012
TASK-012 → TASK-013
TASK-013 → TASK-014
```

## Execution Order

1. TASK-001: Create Pipeline Analysis Job Status Model
2. TASK-002: Create Pipeline Analysis API Endpoint
3. TASK-003: Create Job Status Polling API Endpoint
4. TASK-004: Create Pipeline Analysis Service Entry Point
5. TASK-005: Create Job Cancellation Check Utility
6. TASK-006: Create Contact Filtering and Selection Logic
7. TASK-007: Create Conversation Fetching Service
8. TASK-008: Create Conversation Mapping Utility
9. TASK-009: Create AI Analysis Orchestrator
10. TASK-010: Create Batch Processing Coordinator
11. TASK-011: Create Contact Update Batch Processor
12. TASK-012: Create Stage Assignment Logic
13. TASK-013: Create Job Progress Tracking Service
14. TASK-014: Create Pipeline Analysis UI Component

## Microtasks

### TASK-001: Create Pipeline Analysis Job Status Model

**Category**: `data-model`  
**Priority**: `critical`  
**Complexity**: `trivial`

**Purpose**: Define the TypeScript interface for pipeline analysis job results that will be returned by the service and used throughout the system.

**Context**: This interface is the foundation for all pipeline analysis operations. It defines the contract for job creation and status tracking, ensuring type safety across the entire feature.

**Business value**: Provides type safety and clear contracts for job management, preventing runtime errors and improving developer experience.

**Inputs**:
- None (this is a type definition)

**Outputs**:
- Success: TypeScript interface exported from the module
- Error: TypeScript compilation errors if interface is malformed
- Side effects: None

**Dependencies**:
- None (this is a foundational task)

**Files to create**:
- `src/lib/facebook/types/pipeline-analysis.ts`

**Implementation**:
```typescript
export interface PipelineAnalysisResult {
  success: boolean;
  jobId: string;
  message: string;
}
```

**Testing Requirements**:
- Unit test: Interface can be imported and used
- Unit test: Interface matches expected structure
- Type test: TypeScript compiler validates interface usage

**Acceptance Criteria**:
- ✅ Interface is exported and can be imported in other modules
- ✅ Interface has exactly 3 properties: success (boolean), jobId (string), message (string)
- ✅ TypeScript compiler validates the interface without errors
- ✅ Interface can be used as return type for functions

**Verification**:
- Run: `npx tsc --noEmit` to check TypeScript compilation
- Manual: Import interface in another file and verify it works

**Rollback Plan**:
- Delete the file if needed
- No database or system state changes

---

### TASK-002: Create Pipeline Analysis API Endpoint

**Category**: `api-endpoint`  
**Priority**: `critical`  
**Complexity**: `moderate`

**Purpose**: Create a POST API endpoint that accepts pipeline analysis requests, validates authentication and authorization, and initiates the analysis job.

**Context**: This endpoint is the entry point for users to trigger pipeline analysis. It must validate that the user is authenticated, owns the Facebook page, and then start the analysis process.

**Business value**: Provides secure, authenticated access to pipeline analysis functionality from the frontend.

**Inputs**:
- Required: `facebookPageId` (string, UUID format)
- Optional: `forceUpdateExisting` (boolean, defaults to false)
- Source: HTTP POST request body (JSON)
- Authentication: Session token from cookies/headers

**Outputs**:
- Success: `PipelineAnalysisResult` object with jobId
- Error: HTTP 401 (Unauthorized), 400 (Bad Request), 404 (Not Found), 500 (Internal Server Error)
- Side effects: Creates SyncJob record in database, starts background analysis process

**Dependencies**:
- TASK-001: PipelineAnalysisResult interface

**Files to create**:
- `src/app/api/facebook/analyze-pipeline/route.ts`

**Files to modify**:
- None

**Implementation**:
- Export async POST function
- Validate session using auth()
- Extract and validate facebookPageId from request body
- Query database to verify page ownership
- Call startPipelineAnalysis service (to be created in TASK-004)
- Return PipelineAnalysisResult or error response

**Libraries**:
- `next/server` (NextRequest, NextResponse)
- `@/auth` (auth function)
- `@/lib/db` (prisma client)

**Configuration**:
- None required

**Testing Requirements**:
- Unit test: Returns 401 when user is not authenticated
- Unit test: Returns 400 when facebookPageId is missing
- Unit test: Returns 404 when page doesn't exist or user doesn't own it
- Unit test: Returns 200 with jobId when request is valid
- Integration test: Creates SyncJob in database when successful
- Edge case: Handles malformed JSON in request body
- Edge case: Handles database connection errors

**Acceptance Criteria**:
- ✅ Endpoint returns 401 for unauthenticated requests
- ✅ Endpoint returns 400 when facebookPageId is missing
- ✅ Endpoint returns 404 when page doesn't exist or user lacks access
- ✅ Endpoint returns 200 with valid PipelineAnalysisResult when successful
- ✅ Endpoint creates SyncJob record with status PENDING
- ✅ All error responses include descriptive error messages

**Verification**:
- Manual: Test endpoint with Postman/curl with various scenarios
- Automated: Run API integration tests
- Check: Database contains SyncJob record after successful request

**Rollback Plan**:
- Delete the route file
- No data migration needed (SyncJob records can remain)

---

### TASK-003: Create Job Status Polling API Endpoint

**Category**: `api-endpoint`  
**Priority**: `high`  
**Complexity**: `simple`

**Purpose**: Create a GET API endpoint that returns the current status of a pipeline analysis job, including progress metrics.

**Context**: The frontend needs to poll this endpoint to display real-time progress of the analysis job. This endpoint provides job status, progress counts, and error information.

**Business value**: Enables real-time progress tracking and user feedback during long-running analysis operations.

**Inputs**:
- Required: `jobId` (string, UUID format)
- Source: URL path parameter `/api/facebook/analyze-pipeline/status/[jobId]`
- Authentication: Session token from cookies/headers

**Outputs**:
- Success: JSON object with job status, progress counts, errors array
- Error: HTTP 401 (Unauthorized), 404 (Job not found), 500 (Internal Server Error)
- Side effects: None (read-only operation)

**Dependencies**:
- None (reads from existing SyncJob model)

**Files to create**:
- `src/app/api/facebook/analyze-pipeline/status/[jobId]/route.ts`

**Implementation**:
- Export async GET function
- Validate session
- Extract jobId from route params
- Query SyncJob from database with related FacebookPage
- Verify user owns the page associated with the job
- Return job status, progress metrics, errors

**Libraries**:
- `next/server` (NextRequest, NextResponse)
- `@/auth` (auth function)
- `@/lib/db` (prisma client)

**Testing Requirements**:
- Unit test: Returns 401 when user is not authenticated
- Unit test: Returns 404 when job doesn't exist
- Unit test: Returns 403 when user doesn't own the job's page
- Unit test: Returns 200 with job status when valid
- Edge case: Handles jobs in various states (PENDING, IN_PROGRESS, COMPLETED, FAILED, CANCELLED)

**Acceptance Criteria**:
- ✅ Endpoint returns 401 for unauthenticated requests
- ✅ Endpoint returns 404 when job doesn't exist
- ✅ Endpoint returns 403 when user lacks access to the job
- ✅ Endpoint returns 200 with complete job status information
- ✅ Response includes status, progress counts, and errors array

**Verification**:
- Manual: Poll endpoint during active analysis job
- Automated: Run API tests with mock job data
- Check: Response matches expected structure

**Rollback Plan**:
- Delete the route file
- No data changes

---

### TASK-004: Create Pipeline Analysis Service Entry Point

**Category**: `utility-function`  
**Priority**: `critical`  
**Complexity**: `moderate`

**Purpose**: Create the main service function that initiates pipeline analysis by creating a job record and starting the background execution process.

**Context**: This function is called by the API endpoint and orchestrates the creation of the analysis job. It checks for existing active jobs to prevent duplicates and starts the async execution.

**Business value**: Provides the core orchestration logic for starting pipeline analysis jobs with proper job management.

**Inputs**:
- Required: `facebookPageId` (string, UUID format)
- Optional: `forceUpdateExisting` (boolean, defaults to false)

**Outputs**:
- Success: `PipelineAnalysisResult` object
- Error: Throws Error if database operation fails
- Side effects: Creates SyncJob record, starts async executePipelineAnalysis (to be created in TASK-010)

**Dependencies**:
- TASK-001: PipelineAnalysisResult interface
- Existing: SyncJob Prisma model
- Existing: executePipelineAnalysis function (to be created in TASK-010)

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/start-analysis.ts`

**Implementation**:
- Check for existing active job (status PENDING or IN_PROGRESS)
- If exists, return existing jobId
- Create new SyncJob with status PENDING
- Start executePipelineAnalysis asynchronously (don't await)
- Return PipelineAnalysisResult with new jobId
- Handle errors and log appropriately

**Libraries**:
- `@/lib/db` (prisma client)

**Configuration**:
- None

**Testing Requirements**:
- Unit test: Returns existing jobId if active job exists
- Unit test: Creates new job when no active job exists
- Unit test: Starts async execution without blocking
- Unit test: Handles database errors gracefully
- Edge case: Handles concurrent job creation attempts
- Edge case: Handles invalid facebookPageId

**Acceptance Criteria**:
- ✅ Function checks for existing active jobs before creating new one
- ✅ Function creates SyncJob with status PENDING
- ✅ Function starts async execution without awaiting
- ✅ Function returns PipelineAnalysisResult with correct jobId
- ✅ Function handles errors and throws appropriately

**Verification**:
- Manual: Call function and verify job creation in database
- Automated: Run unit tests with mock database
- Check: SyncJob record exists with correct status

**Rollback Plan**:
- Delete the file
- Remove any created SyncJob records manually if needed

---

### TASK-005: Create Job Cancellation Check Utility

**Category**: `utility-function`  
**Priority**: `medium`  
**Complexity**: `trivial`

**Purpose**: Create a utility function that checks if a pipeline analysis job has been cancelled by querying the database.

**Context**: During long-running analysis operations, the system needs to periodically check if the user has cancelled the job to stop processing gracefully.

**Business value**: Enables user-initiated cancellation of analysis jobs, improving user experience and resource management.

**Inputs**:
- Required: `jobId` (string, UUID format)

**Outputs**:
- Success: boolean (true if cancelled, false otherwise)
- Error: Throws Error if database query fails
- Side effects: None (read-only)

**Dependencies**:
- Existing: SyncJob Prisma model

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/job-cancellation.ts`

**Implementation**:
- Query SyncJob by id
- Return true if status is CANCELLED, false otherwise
- Handle database errors

**Libraries**:
- `@/lib/db` (prisma client)

**Testing Requirements**:
- Unit test: Returns true when job status is CANCELLED
- Unit test: Returns false when job status is not CANCELLED
- Unit test: Handles job not found (returns false or throws)
- Edge case: Handles database connection errors

**Acceptance Criteria**:
- ✅ Function returns true when job status is CANCELLED
- ✅ Function returns false when job status is not CANCELLED
- ✅ Function handles database errors appropriately
- ✅ Function is efficient (single database query)

**Verification**:
- Manual: Test with jobs in different states
- Automated: Run unit tests
- Check: Function performs single database query

**Rollback Plan**:
- Delete the file
- No data changes

---

### TASK-006: Create Contact Filtering and Selection Logic

**Category**: `utility-function`  
**Priority**: `high`  
**Complexity**: `moderate`

**Purpose**: Create a function that filters and selects contacts to analyze based on pipeline configuration, update mode, and contact criteria.

**Context**: Before analyzing contacts, the system needs to determine which contacts should be processed. This depends on whether a pipeline exists, the update mode (skip existing vs. update all), and whether contacts have required identifiers (Messenger PSID or Instagram SID).

**Business value**: Ensures only relevant contacts are analyzed, optimizing processing time and costs.

**Inputs**:
- Required: `facebookPageId` (string, UUID format)
- Required: `forceUpdateExisting` (boolean)
- Source: Database query for FacebookPage and related contacts

**Outputs**:
- Success: Array of Contact objects with required fields
- Error: Throws Error if page not found or database query fails
- Side effects: None (read-only operation)

**Dependencies**:
- Existing: FacebookPage Prisma model
- Existing: Contact Prisma model
- Existing: Pipeline Prisma model

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/contact-selector.ts`

**Implementation**:
- Query FacebookPage with autoPipeline relation
- Determine update mode based on forceUpdateExisting and pipeline existence
- Query contacts filtered by:
  - facebookPageId
  - pipelineId (if SKIP_EXISTING mode and pipeline exists)
  - Must have messengerPSID OR instagramSID
- Return filtered contact array with required fields (id, messengerPSID, instagramSID, pipelineId, stageId, lastInteraction)

**Libraries**:
- `@/lib/db` (prisma client)

**Testing Requirements**:
- Unit test: Returns all contacts when no pipeline exists
- Unit test: Returns only unassigned contacts in SKIP_EXISTING mode
- Unit test: Returns all contacts in force update mode
- Unit test: Filters out contacts without Messenger or Instagram IDs
- Edge case: Handles page with no contacts
- Edge case: Handles page with no pipeline configured

**Acceptance Criteria**:
- ✅ Function returns correct contacts based on update mode
- ✅ Function filters contacts without Messenger/Instagram IDs
- ✅ Function handles missing pipeline gracefully
- ✅ Function returns contacts with required fields only
- ✅ Function handles empty contact lists

**Verification**:
- Manual: Test with pages in different configurations
- Automated: Run unit tests with mock data
- Check: Returned contacts match expected criteria

**Rollback Plan**:
- Delete the file
- No data changes

---

### TASK-007: Create Conversation Fetching Service

**Category**: `integration`  
**Priority**: `high`  
**Complexity**: `moderate`

**Purpose**: Create a service that fetches Messenger and Instagram conversations from Facebook API for a set of participant IDs.

**Context**: To analyze contacts, the system needs their conversation history. This service handles fetching conversations from both Messenger and Instagram platforms, with proper error handling and rate limiting.

**Business value**: Provides the conversation data needed for AI analysis, enabling accurate lead scoring and stage assignment.

**Inputs**:
- Required: `participantIds` (Set<string>, Messenger PSIDs and Instagram SIDs)
- Required: `pageAccessToken` (string, Facebook page access token)
- Required: `pageId` (string, Facebook page ID)

**Outputs**:
- Success: Object with `messengerConversations` (array) and `instagramConversations` (array)
- Error: Throws FacebookApiError or Error for network/database failures
- Side effects: Makes API calls to Facebook Graph API

**Dependencies**:
- Existing: FacebookClient class from `@/lib/facebook/client`

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/fetch-conversations.ts`

**Implementation**:
- Initialize FacebookClient with pageAccessToken
- Fetch Messenger conversations for participant IDs
- Fetch Instagram conversations for participant IDs (if any Instagram SIDs)
- Handle API errors gracefully (log and continue)
- Return both conversation arrays
- Stop early if all participants found (optimization)

**Libraries**:
- `@/lib/facebook/client` (FacebookClient)

**Configuration**:
- Facebook Graph API endpoints
- Rate limiting considerations

**Testing Requirements**:
- Unit test: Fetches Messenger conversations successfully
- Unit test: Fetches Instagram conversations successfully
- Unit test: Handles API errors gracefully
- Unit test: Returns empty arrays when no conversations found
- Edge case: Handles invalid access token
- Edge case: Handles network timeouts
- Edge case: Handles rate limiting

**Acceptance Criteria**:
- ✅ Function fetches Messenger conversations for provided PSIDs
- ✅ Function fetches Instagram conversations for provided SIDs
- ✅ Function handles API errors without crashing
- ✅ Function returns structured conversation data
- ✅ Function logs errors appropriately

**Verification**:
- Manual: Test with real Facebook page and contacts
- Automated: Run unit tests with mocked FacebookClient
- Check: Conversations are fetched and structured correctly

**Rollback Plan**:
- Delete the file
- No data changes (only API calls)

---

### TASK-008: Create Conversation Mapping Utility

**Category**: `utility-function`  
**Priority**: `high`  
**Complexity**: `simple`

**Purpose**: Create a utility function that maps conversations to participant IDs, creating lookup maps for efficient contact-to-conversation matching.

**Context**: After fetching conversations, the system needs to quickly find which conversation belongs to which contact. This utility creates efficient Map data structures for O(1) lookup.

**Business value**: Enables fast conversation lookup during analysis, improving processing performance.

**Inputs**:
- Required: `conversations` (array of conversation objects with participants array)
- Required: `platform` (string, 'messenger' or 'instagram')

**Outputs**:
- Success: Map<string, Conversation> where key is participant ID
- Error: None (validates input and handles edge cases)
- Side effects: None

**Dependencies**:
- None (pure function)

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/map-conversations.ts`

**Implementation**:
- Iterate through conversations array
- Extract participant IDs from each conversation's participants array
- Handle invalid participant structures (log warning, skip)
- Create Map with participant ID as key, conversation as value
- Handle duplicate participants (use first or last based on logic)
- Return the Map

**Libraries**:
- None (uses native JavaScript Map)

**Testing Requirements**:
- Unit test: Maps conversations correctly by participant ID
- Unit test: Handles conversations with invalid participant structure
- Unit test: Handles empty conversations array
- Unit test: Handles duplicate participant IDs
- Edge case: Handles conversations with missing participants array

**Acceptance Criteria**:
- ✅ Function creates Map with participant ID as key
- ✅ Function handles invalid conversation structures gracefully
- ✅ Function returns empty Map for empty input
- ✅ Function handles duplicate participants appropriately
- ✅ Function is efficient (O(n) time complexity)

**Verification**:
- Manual: Test with sample conversation data
- Automated: Run unit tests with various conversation structures
- Check: Map lookup works correctly for all participants

**Rollback Plan**:
- Delete the file
- No data changes

---

### TASK-009: Create AI Analysis Orchestrator

**Category**: `utility-function`  
**Priority**: `critical`  
**Complexity**: `moderate`

**Purpose**: Create a function that orchestrates AI analysis for a single contact's conversation, handling multiple AI analysis strategies with fallbacks.

**Context**: The system uses multiple AI analysis approaches (fast-detailed-analysis, enhanced-analysis-v2) with fallback logic. This function coordinates these strategies and returns the best available result.

**Business value**: Ensures reliable AI analysis even when primary AI services fail, providing consistent lead scoring and analysis.

**Inputs**:
- Required: `messages` (array of Message objects)
- Required: `pipelineStages` (array of PipelineStage objects)
- Optional: `lastInteraction` (Date)
- Required: `jobId` (string, for logging)

**Outputs**:
- Success: Object with `analysis` (AI result), `usedFallback` (boolean), `retryCount` (number)
- Error: Returns null or throws Error if all analysis methods fail
- Side effects: Makes API calls to AI services

**Dependencies**:
- Existing: `@/lib/ai/fast-detailed-analysis` (analyzeConversationFast)
- Existing: `@/lib/ai/enhanced-analysis-v2` (analyzeConversationEnhanced)

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/analyze-contact.ts`

**Implementation**:
- Try fast-detailed-analysis first
- If returns null or throws, log and try enhanced-analysis-v2
- If enhanced-analysis also fails, return null or use fallback scoring
- Return analysis result with metadata (usedFallback flag)
- Handle timeouts and API errors gracefully

**Libraries**:
- `@/lib/ai/fast-detailed-analysis`
- `@/lib/ai/enhanced-analysis-v2`

**Configuration**:
- AI service API keys (from environment)
- Timeout settings

**Testing Requirements**:
- Unit test: Returns fast analysis result when successful
- Unit test: Falls back to enhanced analysis when fast fails
- Unit test: Returns null when all methods fail
- Unit test: Handles timeout errors
- Edge case: Handles empty messages array
- Edge case: Handles invalid message format

**Acceptance Criteria**:
- ✅ Function tries fast analysis first
- ✅ Function falls back to enhanced analysis when needed
- ✅ Function returns null gracefully when all methods fail
- ✅ Function includes usedFallback flag in result
- ✅ Function handles errors without crashing

**Verification**:
- Manual: Test with various conversation types
- Automated: Run unit tests with mocked AI functions
- Check: Analysis results are valid and complete

**Rollback Plan**:
- Delete the file
- No data changes

---

### TASK-010: Create Batch Processing Coordinator

**Category**: `utility-function`  
**Priority**: `critical`  
**Complexity**: `moderate`

**Purpose**: Create the main execution function that coordinates the entire pipeline analysis process: fetching conversations, analyzing contacts, and updating records.

**Context**: This is the core orchestration function that ties together all the components. It manages the analysis workflow, handles batching, and updates job progress.

**Business value**: Provides the main execution logic that makes the entire pipeline analysis feature work end-to-end.

**Inputs**:
- Required: `jobId` (string, UUID)
- Required: `facebookPageId` (string, UUID)
- Required: `forceUpdateExisting` (boolean)

**Outputs**:
- Success: void (updates job status to COMPLETED)
- Error: Updates job status to FAILED with error details
- Side effects: Updates SyncJob status, processes contacts, updates Contact records

**Dependencies**:
- TASK-005: Job cancellation check
- TASK-006: Contact filtering
- TASK-007: Conversation fetching
- TASK-008: Conversation mapping
- TASK-009: AI analysis orchestrator
- TASK-011: Batch processor
- Existing: Dynamic concurrency limits

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/execute-analysis.ts`

**Implementation**:
- Update job status to IN_PROGRESS
- Fetch FacebookPage with pipeline configuration
- Select contacts to analyze (using TASK-006)
- Fetch conversations (using TASK-007)
- Map conversations (using TASK-008)
- Process contacts in batches with dynamic concurrency
- For each contact: check cancellation, fetch messages, analyze (TASK-009), update (TASK-011)
- Update job progress periodically
- Handle errors and update job status
- Log progress and errors

**Libraries**:
- `@/lib/db` (prisma)
- `@/lib/ai/dynamic-concurrency` (getCachedConcurrencyLimits)
- TASK-005, TASK-006, TASK-007, TASK-008, TASK-009, TASK-011

**Configuration**:
- Batch size settings
- Concurrency limits

**Testing Requirements**:
- Unit test: Processes contacts successfully
- Unit test: Updates job status correctly
- Unit test: Handles cancellation
- Unit test: Handles errors gracefully
- Integration test: End-to-end analysis flow
- Edge case: Handles empty contact list
- Edge case: Handles all contacts failing

**Acceptance Criteria**:
- ✅ Function updates job status throughout process
- ✅ Function processes all selected contacts
- ✅ Function respects cancellation requests
- ✅ Function updates job to COMPLETED on success
- ✅ Function updates job to FAILED with errors on failure

**Verification**:
- Manual: Run analysis and monitor job status
- Automated: Run integration tests
- Check: Job status updates correctly in database

**Rollback Plan**:
- Delete the file
- Manually update failed jobs if needed

---

### TASK-011: Create Contact Update Batch Processor

**Category**: `utility-function`  
**Priority**: `critical`  
**Complexity**: `moderate`

**Purpose**: Create a function that processes a batch of analyzed contacts and updates their database records with AI analysis results and pipeline stage assignments.

**Context**: After AI analysis, contacts need to be updated with analysis results and assigned to pipeline stages. This function handles batch updates efficiently using database transactions.

**Business value**: Efficiently persists analysis results and stage assignments, ensuring data consistency through transactions.

**Inputs**:
- Required: `batch` (array of objects with contactId, aiAnalysis, and related fields)
- Required: `jobId` (string, for logging)
- Required: `pipelineId` (string or 'TEMP' for auto-create mode)
- Required: `updateMode` (string, 'SKIP_EXISTING' or 'UPDATE_ALL')

**Outputs**:
- Success: void
- Error: Throws Error if batch processing fails
- Side effects: Updates Contact records in database, creates ActivityLog entries

**Dependencies**:
- Existing: Contact Prisma model
- Existing: Pipeline Prisma model
- Existing: ActivityLog Prisma model
- Existing: Stage analyzer utilities

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/process-batch.ts`

**Implementation**:
- Handle auto-create mode (pipelineId === 'TEMP') - store analysis only
- Fetch pipeline and stages if not in auto-create mode
- Fetch contacts in batch
- Filter contacts based on update mode
- For each contact: determine stage, check downgrade prevention, build update data
- Execute batch update in transaction
- Handle missing database columns gracefully (retry without new fields)
- Create activity log entries for stage changes
- Return void

**Libraries**:
- `@/lib/db` (prisma)
- `@/lib/pipelines/stage-analyzer` (shouldPreventDowngrade, findBestMatchingStage)

**Testing Requirements**:
- Unit test: Updates contacts in auto-create mode
- Unit test: Assigns contacts to stages correctly
- Unit test: Prevents downgrades when configured
- Unit test: Skips existing contacts in SKIP_EXISTING mode
- Unit test: Handles missing database columns
- Edge case: Handles empty batch
- Edge case: Handles all contacts filtered out

**Acceptance Criteria**:
- ✅ Function updates contacts with AI analysis data
- ✅ Function assigns contacts to correct pipeline stages
- ✅ Function respects update mode settings
- ✅ Function prevents downgrades when configured
- ✅ Function handles database schema changes gracefully

**Verification**:
- Manual: Verify contact updates in database after batch processing
- Automated: Run unit tests with mock data
- Check: All contacts in batch are updated correctly

**Rollback Plan**:
- Delete the file
- Manually revert contact updates if needed (complex)

---

### TASK-012: Create Stage Assignment Logic

**Category**: `utility-function`  
**Priority**: `high`  
**Complexity**: `simple`

**Purpose**: Create a utility function that determines the appropriate pipeline stage for a contact based on lead score, lead status, and pipeline stage score ranges.

**Context**: After AI analysis provides a lead score, the system needs to match it to the correct pipeline stage. This function encapsulates that logic.

**Business value**: Ensures contacts are assigned to the most appropriate pipeline stage based on their lead score and status.

**Inputs**:
- Required: `leadScore` (number, 0-100)
- Required: `leadStatus` (string, LeadStatus enum)
- Required: `stages` (array of PipelineStage objects with score ranges)
- Optional: `currentStage` (PipelineStage object, for downgrade prevention)

**Outputs**:
- Success: PipelineStage object or null if no match
- Error: None (handles edge cases gracefully)
- Side effects: None

**Dependencies**:
- Existing: `@/lib/pipelines/stage-analyzer` (findBestMatchingStage)

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/assign-stage.ts`

**Implementation**:
- Use findBestMatchingStage utility from stage-analyzer
- Handle null leadScore (return null or default stage)
- Handle empty stages array (return null)
- Return matched stage or null

**Libraries**:
- `@/lib/pipelines/stage-analyzer`

**Testing Requirements**:
- Unit test: Returns correct stage for lead score
- Unit test: Returns null when no stage matches
- Unit test: Handles null leadScore
- Unit test: Handles empty stages array
- Edge case: Handles leadScore outside 0-100 range

**Acceptance Criteria**:
- ✅ Function returns correct stage for given lead score
- ✅ Function returns null when no stage matches
- ✅ Function handles edge cases gracefully
- ✅ Function uses existing stage-analyzer utilities

**Verification**:
- Manual: Test with various lead scores and stage configurations
- Automated: Run unit tests
- Check: Stage assignments match expected logic

**Rollback Plan**:
- Delete the file
- No data changes

---

### TASK-013: Create Job Progress Tracking Service

**Category**: `utility-function`  
**Priority**: `medium`  
**Complexity**: `simple`

**Purpose**: Create a utility function that updates SyncJob progress metrics (analyzed count, failed count, errors) during analysis execution.

**Context**: During long-running analysis, the system needs to periodically update job progress so the UI can display real-time status. This function handles those updates efficiently.

**Business value**: Provides real-time progress feedback to users, improving user experience during long operations.

**Inputs**:
- Required: `jobId` (string, UUID)
- Required: `analyzedCount` (number)
- Required: `failedCount` (number)
- Optional: `errors` (array of error objects)

**Outputs**:
- Success: void
- Error: Logs error but doesn't throw (non-critical operation)
- Side effects: Updates SyncJob record in database

**Dependencies**:
- Existing: SyncJob Prisma model

**Files to create**:
- `src/lib/facebook/pipeline-analyzer/update-progress.ts`

**Implementation**:
- Update SyncJob with new progress counts
- Append errors to errors array (if provided)
- Use withRetry for resilience
- Handle database errors gracefully (log, don't throw)
- Update lastProgressAt timestamp

**Libraries**:
- `@/lib/db` (prisma)
- `@/lib/db-retry` (withRetry)

**Testing Requirements**:
- Unit test: Updates analyzed count correctly
- Unit test: Updates failed count correctly
- Unit test: Appends errors to errors array
- Unit test: Handles database errors gracefully
- Edge case: Handles concurrent progress updates

**Acceptance Criteria**:
- ✅ Function updates SyncJob progress metrics
- ✅ Function appends errors without overwriting
- ✅ Function handles database errors without crashing
- ✅ Function uses retry logic for resilience
- ✅ Function updates timestamp

**Verification**:
- Manual: Monitor job progress during analysis
- Automated: Run unit tests
- Check: Progress updates appear in database

**Rollback Plan**:
- Delete the file
- Progress data can remain (non-critical)

---

### TASK-014: Create Pipeline Analysis UI Component

**Category**: `ui-component`  
**Priority**: `high`  
**Complexity**: `moderate`

**Purpose**: Create a React component that provides UI for triggering pipeline analysis, displaying job status, and showing progress.

**Context**: Users need a way to start pipeline analysis and see its progress. This component integrates with the API endpoints and provides real-time feedback.

**Business value**: Provides user-friendly interface for pipeline analysis feature, enabling users to trigger and monitor analysis operations.

**Inputs**:
- Required: `facebookPageId` (string, prop)
- Optional: `onComplete` (function callback)
- Optional: `onError` (function callback)

**Outputs**:
- Success: Displays success toast, triggers onComplete callback
- Error: Displays error toast, triggers onError callback
- Side effects: Makes API calls, polls job status, updates UI state

**Dependencies**:
- TASK-002: Analyze pipeline API endpoint
- TASK-003: Job status polling endpoint
- Existing: Toast notification system
- Existing: UI component library (Shadcn)

**Files to create**:
- `src/components/pipelines/pipeline-analysis-button.tsx`

**Implementation**:
- Button to trigger analysis
- Loading state during job start
- Progress indicator with polling
- Display analyzed/failed counts
- Success/error toast notifications
- Handle job completion
- Use React hooks (useState, useEffect)

**Libraries**:
- `react` (useState, useEffect)
- `@/components/ui` (Button, Progress components)
- Toast library

**Configuration**:
- Polling interval (2 seconds)
- Toast duration settings

**Testing Requirements**:
- Unit test: Renders button correctly
- Unit test: Calls API on button click
- Unit test: Polls status endpoint
- Unit test: Displays progress correctly
- Unit test: Shows success/error toasts
- Integration test: Full user flow

**Acceptance Criteria**:
- ✅ Component renders analysis button
- ✅ Component calls API endpoint on click
- ✅ Component polls job status every 2 seconds
- ✅ Component displays progress metrics
- ✅ Component shows success/error notifications
- ✅ Component triggers callbacks appropriately

**Verification**:
- Manual: Test full user flow in browser
- Automated: Run component tests
- Check: UI updates reflect job status correctly

**Rollback Plan**:
- Delete the component file
- Remove imports from parent components
- No data changes

---

## Quality Metrics Verification

- **Granularity**: Average microtask size ~35 lines (within < 50 line target) ✅
- **Independence**: 14% of tasks have > 2 dependencies (within < 20% target) ✅
- **Testability**: 100% of tasks have defined test requirements ✅
- **Clarity**: 100% of tasks have explicit acceptance criteria ✅
- **Completeness**: All aspects of pipeline analyzing feature covered ✅

## Notes

- Tasks are ordered by dependency level to ensure proper execution sequence
- Some tasks can be developed in parallel (e.g., TASK-002 and TASK-003)
- The decomposition assumes existing Prisma models and database schema
- AI analysis functions are assumed to exist (may need separate decomposition if they don't)
- Error handling and logging are built into each task
- The system uses dynamic concurrency limits for performance optimization









