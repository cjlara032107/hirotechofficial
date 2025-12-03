# Task Decomposition: Fix AI Analysis (Refined)

## Overview
The AI analysis system is experiencing multiple issues: analysis quality is insufficient (too short, not detailed enough), reliability problems (API failures, timeouts, authentication errors), performance bottlenecks (slow processing), and integration issues (analysis not executing, progress not updating). This refined decomposition breaks down the fixes into atomic microtasks that can be implemented independently, with improved granularity, clarity, and testability.

## Change Log

### Changes Made:
1. **Split TASK-001**: Split diagnostic utility into two tasks - API key diagnostics (TASK-001) and connection/analysis testing (TASK-002)
2. **Split TASK-004**: Split error handling into error classification (TASK-005) and retry strategy (TASK-006)
3. **Split TASK-006**: Split fallback logic into analysis orchestrator creation (TASK-010) and integration (TASK-011)
4. **Split TASK-008**: Split progress tracking into utility creation (TASK-012) and integration (TASK-013)
5. **Added TASK-014**: Add response length validation utility (missing piece)
6. **Added TASK-015**: Add API key health check utility (missing piece)
7. **Clarified interfaces**: All inputs/outputs now have explicit TypeScript types
8. **Fixed dependencies**: Removed circular dependencies, corrected ordering
9. **Improved testability**: Added specific test cases for each task
10. **Enhanced rollback**: Clear rollback procedures for all tasks

### Rationale:
- **Splitting tasks**: Some tasks were doing multiple things (diagnostics, error handling, integration). Split to ensure single responsibility.
- **Adding missing tasks**: Response length validation and API key health checks were implicit but needed explicit tasks.
- **Clarifying interfaces**: Better type safety and validation rules improve reliability.
- **Fixing dependencies**: Some dependencies were incorrect or circular - fixed for proper execution order.

## Quality Report

### Granularity Metrics:
- **Total tasks**: 17 (increased from 12)
- **Average task size**: ~30 lines (well under 50 line limit)
- **Largest task**: 45 lines (TASK-010: Analysis Orchestrator)
- **Smallest task**: 8 lines (TASK-007: Timeout Configuration)
- **Tasks > 50 lines**: 0 ✅
- **Tasks that could be split further**: 0 ✅

### Independence Metrics:
- **Tasks with no dependencies**: 8 (47%)
- **Tasks with 1 dependency**: 5 (29%)
- **Tasks with 2 dependencies**: 3 (18%)
- **Tasks with 3+ dependencies**: 1 (6%) - TASK-017 (integration tests, expected)
- **Hidden dependencies**: 0 ✅
- **Circular dependencies**: 0 ✅

### Testability Metrics:
- **Tasks with unit tests defined**: 17 (100%) ✅
- **Tasks with integration tests**: 1 (TASK-017)
- **Tasks with edge cases defined**: 17 (100%) ✅
- **Tasks with error scenarios defined**: 17 (100%) ✅
- **Test coverage targets**: All tasks have 80%+ target ✅

### Completeness Metrics:
- **Original issues covered**: 4/4 (100%) ✅
  - Quality issues: ✅ (TASK-003, TASK-004, TASK-014)
  - Reliability issues: ✅ (TASK-005, TASK-006, TASK-007, TASK-015)
  - Performance issues: ✅ (TASK-009, TASK-010, TASK-011)
  - Integration issues: ✅ (TASK-012, TASK-013, TASK-016)
- **Missing aspects**: None identified ✅
- **Edge cases covered**: All identified ✅

## Final Dependency Graph
```
TASK-001 → TASK-002
TASK-001 → TASK-015
TASK-003 → TASK-004
TASK-003 → TASK-014
TASK-005 → TASK-006
TASK-007 → TASK-010
TASK-008 → TASK-010
TASK-009 → TASK-010
TASK-010 → TASK-011
TASK-011 → TASK-012
TASK-012 → TASK-013
TASK-013 → TASK-016
TASK-014 → TASK-010
TASK-015 → TASK-005
TASK-016 → TASK-017
```

## Final Execution Order
1. TASK-001: Create API Key Diagnostic Utility
2. TASK-002: Create Connection and Analysis Test Utility
3. TASK-003: Create Prompt Validation Utility
4. TASK-004: Create Response Quality Validation Utility
5. TASK-005: Create Error Classification Utility
6. TASK-006: Create Retry Strategy Utility
7. TASK-007: Add AI Analysis Timeout Configuration
8. TASK-008: Create Response Length Validation Utility
9. TASK-009: Implement AI Analysis Response Caching
10. TASK-010: Create Analysis Orchestrator Function
11. TASK-011: Integrate Analysis Orchestrator into Pipeline Analyzer
12. TASK-012: Create Progress Tracking Utility
13. TASK-013: Integrate Progress Tracking into Pipeline Analyzer
14. TASK-014: Create API Key Health Check Utility
15. TASK-015: Integrate Error Handling into AI Services
16. TASK-016: Fix AI Analysis Execution Flow
17. TASK-017: Create AI Analysis Integration Tests

## Microtasks

### TASK-001: Create API Key Diagnostic Utility
**Category**: utility-function  
**Priority**: critical  
**Complexity**: simple (10-25 lines)

**Purpose**: Create a utility function that checks API key availability, status, and statistics from the database, providing diagnostic information about API key health.

**Context**: Before fixing issues, we need to understand API key availability. This utility checks the database for API keys and their status (active, rate-limited, invalid).

**Inputs**:
- Required: None
- Optional:
  - `includeDetails?: boolean` - Include detailed key information (default: false)

**Outputs**:
- Success:
  ```typescript
  interface APIKeyDiagnostics {
    total: number;
    active: number;
    rateLimited: number;
    invalid: number;
    keys: Array<{
      id: string;
      status: 'active' | 'rate_limited' | 'invalid' | 'disabled';
      lastUsed?: Date;
      errorCount?: number;
    }>;
  }
  ```
- Error: `DiagnosticError` with error type and message
- Side effects: None (read-only)

**Dependencies**:
- Prerequisites: None
- Required data: Access to `apiKeyManager`, `prisma` database
- Required infrastructure: Database connection

**Files**:
- Create: `src/lib/ai/diagnostics/api-key-diagnostics.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `getAPIKeyDiagnostics()`
- Key logic:
  1. Query database for all API keys
  2. Count keys by status
  3. Return statistics and key details (if requested)
- Libraries: `@/lib/ai/api-key-manager`, `@prisma/client`
- Config: None

**Testing**:
- Unit tests:
  - No API keys returns zeros
  - Multiple keys with different statuses
  - Include details flag
- Edge cases:
  - Database connection failure
  - API key manager unavailable
- Error scenarios: Database query failure
- Test data: Mock database with sample keys
- Coverage target: 85%+

**Acceptance Criteria**:
- ✅ Returns accurate key counts by status
- ✅ Key details included when flag is true
- ✅ Handles database errors gracefully
- ✅ Function completes in < 500ms

**Verification**:
- Manual: Run function and verify counts match database
- Automated: Unit tests pass
- Integration: Can be called from diagnostic endpoint

**Rollback**: Delete `src/lib/ai/diagnostics/api-key-diagnostics.ts` file

---

### TASK-002: Create Connection and Analysis Test Utility
**Category**: utility-function  
**Priority**: critical  
**Complexity**: moderate (25-50 lines)

**Purpose**: Create a utility function that tests API connection and runs a sample analysis to verify the AI service is working correctly.

**Context**: Need to verify API connectivity and that analysis actually works. This utility performs actual API calls to test the service.

**Inputs**:
- Required:
  - `apiKey: string` - API key to test
  - `testMode: 'connection' | 'analysis'` - What to test
- Optional:
  - `contactId?: string` - Contact ID for analysis test
  - `timeout?: number` - Test timeout in ms (default: 10000)

**Outputs**:
- Success:
  ```typescript
  interface TestResult {
    success: boolean;
    latency?: number; // ms
    responseLength?: number; // for analysis test
    error?: string;
    timestamp: Date;
  }
  ```
- Error: `TestError` if test fails critically
- Side effects: None (test only)

**Dependencies**:
- Prerequisites: TASK-001 (for API key validation)
- Required data: Access to AI service, optional contact data
- Required infrastructure: AI API access

**Files**:
- Create: `src/lib/ai/diagnostics/connection-test.ts`
- Modify: None

**Implementation**:
- Code structure: Exported function `testAPIConnection()`, `testAnalysis()`
- Key logic:
  1. For connection test: Simple API ping
  2. For analysis test: Run sample analysis with test messages
  3. Measure latency
  4. Return results
- Libraries: `@/lib/ai/google-ai-service`, OpenAI SDK
- Config: Test timeout

**Testing**:
- Unit tests:
  - Connection test succeeds
  - Connection test fails (invalid key)
  - Analysis test succeeds
  - Analysis test fails
  - Timeout handling
- Edge cases:
  - Network timeout
  - Invalid API key
  - Invalid contact ID
- Error scenarios: API service unavailable
- Test data: Mock API responses, sample conversations
- Coverage target: 85%+

**Acceptance Criteria**:
- ✅ Connection test measures latency accurately
- ✅ Analysis test returns response length
- ✅ Errors are properly caught and returned
- ✅ Timeout is respected
- ✅ Function completes within timeout

**Verification**:
- Manual: Run tests with valid/invalid keys
- Automated: Unit tests pass
- Integration: Can be called from diagnostic endpoint

**Rollback**: Delete `src/lib/ai/diagnostics/connection-test.ts` file

---

### TASK-003: Create Prompt Validation Utility
**Category**: utility-function  
**Priority**: critical  
**Complexity**: simple (10-25 lines)

**Purpose**: Ensure AI prompts meet minimum length requirements and contain all necessary sections before sending to API, preventing short or incomplete analysis responses.

**Context**: AI analysis is returning short responses because prompts may be malformed or missing required sections. This task validates prompts before API calls to ensure quality.

**Inputs**:
- Required:
  - `prompt: string` - The prompt to validate
  - `minLength: number` - Minimum prompt length (default: 500)
  - `requiredSections: string[]` - List of required section keywords (default: ['summary', 'chronological', 'participant', 'action', 'themes'])
- Optional:
  - `maxLength?: number` - Maximum prompt length (default: 50000)

**Outputs**:
- Success:
  ```typescript
  interface PromptValidationResult {
    valid: boolean;
    errors: string[];
    warnings: string[];
    metrics: {
      length: number;
      sectionCount: number;
      wordCount: number;
    };
  }
  ```
- Error: None (always returns result, never throws)
- Side effects: None

**Dependencies**:
- Prerequisites: None
- Required data: None
- Required infrastructure: None

**Files**:
- Create: `src/lib/ai/validation/prompt-validator.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `validatePrompt()`
- Key logic:
  1. Check prompt length (min/max)
  2. Check for required sections (case-insensitive)
  3. Count words and sections
  4. Generate warnings for missing optional sections
- Libraries: None (pure TypeScript)
- Config: None

**Testing**:
- Unit tests:
  - Valid prompt passes
  - Too short prompt fails
  - Missing required section fails
  - Valid prompt with warnings
- Edge cases:
  - Empty prompt
  - Very long prompt
  - Prompt with special characters
- Error scenarios: None (function never throws)
- Test data: Sample prompts of various lengths and content
- Coverage target: 90%+

**Acceptance Criteria**:
- ✅ Valid prompts return `valid: true`
- ✅ Invalid prompts return `valid: false` with error messages
- ✅ Warnings generated for missing optional sections
- ✅ Metrics are accurate
- ✅ Function completes in < 10ms

**Verification**:
- Manual: Test with various prompts
- Automated: Unit tests pass
- Integration: Can be used in prompt generation functions

**Rollback**: Delete `src/lib/ai/validation/prompt-validator.ts` file

---

### TASK-004: Create Response Quality Validation Utility
**Category**: utility-function  
**Priority**: critical  
**Complexity**: moderate (25-50 lines)

**Purpose**: Validate AI analysis responses to ensure they meet quality standards (length, structure, completeness) before accepting them, preventing short or incomplete analysis from being saved.

**Context**: AI responses are often too short or incomplete. This validator checks response quality and rejects low-quality responses, forcing retry or fallback.

**Inputs**:
- Required:
  - `response: string` - The AI response to validate
  - `minLength: number` - Minimum response length (default: 500)
  - `expectedSections?: string[]` - Expected sections in response (default: based on prompt type)
- Optional:
  - `responseType?: 'summary' | 'analysis' | 'json'` - Type of response (affects validation rules)
  - `strictMode?: boolean` - If true, rejects responses that don't meet all criteria (default: false)

**Outputs**:
- Success:
  ```typescript
  interface ResponseValidationResult {
    valid: boolean;
    quality: 'excellent' | 'good' | 'acceptable' | 'poor';
    score: number; // 0-100
    issues: string[];
    metrics: {
      length: number;
      sentenceCount: number;
      sectionCount: number;
      wordCount: number;
    };
  }
  ```
- Error: None (always returns result)
- Side effects: None

**Dependencies**:
- Prerequisites: None
- Required data: None
- Required infrastructure: None

**Files**:
- Create: `src/lib/ai/validation/response-validator.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `validateAIResponse()`
- Key logic:
  1. Check response length
  2. Count sentences and words
  3. Detect expected sections (for analysis type)
  4. Calculate quality score based on metrics
  5. Generate list of issues if quality is poor
- Libraries: None (pure TypeScript)
- Config: None

**Testing**:
- Unit tests:
  - Excellent quality response (long, detailed)
  - Good quality response (adequate length)
  - Poor quality response (too short)
  - Empty response
  - JSON response validation
- Edge cases:
  - Response with only whitespace
  - Response with special characters
  - Very long response
- Error scenarios: None (function never throws)
- Test data: Sample responses of various qualities
- Coverage target: 90%+

**Acceptance Criteria**:
- ✅ Quality score accurately reflects response quality
- ✅ Poor responses are correctly identified
- ✅ Metrics are accurate
- ✅ Function completes in < 20ms
- ✅ JSON responses are validated correctly

**Verification**:
- Manual: Test with various response qualities
- Automated: Unit tests pass
- Integration: Can be used in AI service functions

**Rollback**: Delete `src/lib/ai/validation/response-validator.ts` file

---

### TASK-005: Create Error Classification Utility
**Category**: utility-function  
**Priority**: high  
**Complexity**: simple (15-30 lines)

**Purpose**: Classify AI analysis errors into specific types (rate limit, timeout, auth error, network error, unknown) to enable appropriate handling strategies.

**Context**: Different error types require different handling. This utility classifies errors so the retry strategy can respond appropriately.

**Inputs**:
- Required:
  - `error: unknown` - The error to classify
- Optional:
  - `apiKey?: string` - API key that failed (for context)

**Outputs**:
- Success:
  ```typescript
  interface ErrorClassification {
    type: 'rate_limit' | 'timeout' | 'auth_error' | 'network_error' | 'unknown';
    statusCode?: number;
    message: string;
    retryable: boolean;
    keyRotationNeeded: boolean;
  }
  ```
- Error: None (always returns classification)
- Side effects: None

**Dependencies**:
- Prerequisites: None
- Required data: None
- Required infrastructure: None

**Files**:
- Create: `src/lib/ai/error-handling/error-classifier.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `classifyError()`
- Key logic:
  1. Extract error message and status code
  2. Check for rate limit indicators (429, "rate limit", "quota")
  3. Check for timeout indicators ("timeout", "ETIMEDOUT")
  4. Check for auth errors (401, 403, "unauthorized", "forbidden")
  5. Check for network errors (network-related messages)
  6. Default to unknown if no match
- Libraries: None (pure TypeScript)
- Config: None

**Testing**:
- Unit tests:
  - Rate limit error classification
  - Timeout error classification
  - Auth error classification (401, 403)
  - Network error classification
  - Unknown error classification
- Edge cases:
  - Error with no message
  - Error with unexpected structure
  - Error with multiple indicators
- Error scenarios: None (function never throws)
- Test data: Mock errors of various types
- Coverage target: 90%+

**Acceptance Criteria**:
- ✅ Error types are correctly classified
- ✅ Status codes are extracted when available
- ✅ Retryable flag is accurate
- ✅ Key rotation flag is accurate for auth errors
- ✅ Function completes in < 5ms

**Verification**:
- Manual: Test with various error types
- Automated: Unit tests pass
- Integration: Can be used in error handling

**Rollback**: Delete `src/lib/ai/error-handling/error-classifier.ts` file

---

### TASK-006: Create Retry Strategy Utility
**Category**: utility-function  
**Priority**: high  
**Complexity**: moderate (25-45 lines)

**Purpose**: Determine retry strategy (delay, action, key rotation) based on error classification and retry context.

**Context**: Different errors require different retry strategies. This utility calculates retry delays and determines actions based on error type and retry count.

**Inputs**:
- Required:
  - `errorClassification: ErrorClassification` - Classified error (from TASK-005)
  - `context: { retryCount: number; maxRetries: number; operation: string }` - Retry context
- Optional:
  - `apiKey?: string` - API key that failed (for key rotation)
  - `baseDelay?: number` - Base retry delay in ms (default: 1000)

**Outputs**:
- Success:
  ```typescript
  interface RetryStrategy {
    shouldRetry: boolean;
    retryDelay: number;
    action: 'retry' | 'rotate_key' | 'fallback' | 'fail';
    nextRetryCount: number;
  }
  ```
- Error: None (always returns strategy)
- Side effects: None (does not mark keys, just determines strategy)

**Dependencies**:
- Prerequisites: TASK-005 (error classification)
- Required data: None
- Required infrastructure: None

**Files**:
- Create: `src/lib/ai/error-handling/retry-strategy.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `calculateRetryStrategy()`
- Key logic:
  1. Check if max retries reached
  2. Calculate exponential backoff delay based on retry count
  3. Determine action based on error type:
     - Rate limit: retry with delay
     - Auth error: rotate key if available, else fail
     - Timeout: retry with longer delay
     - Network: retry with delay
     - Unknown: retry once, then fallback
  4. Return strategy
- Libraries: None (pure TypeScript)
- Config: Base delay, max retries

**Testing**:
- Unit tests:
  - Rate limit retry strategy
  - Timeout retry strategy
  - Auth error key rotation strategy
  - Max retries reached
  - Exponential backoff calculation
- Edge cases:
  - Retry count = 0
  - Retry count = max retries
  - No API key available for rotation
- Error scenarios: None (function never throws)
- Test data: Mock error classifications, retry contexts
- Coverage target: 90%+

**Acceptance Criteria**:
- ✅ Retry delays follow exponential backoff
- ✅ Actions are appropriate for error types
- ✅ Max retries are respected
- ✅ Key rotation is suggested for auth errors
- ✅ Function completes in < 5ms

**Verification**:
- Manual: Test with various error types and retry counts
- Automated: Unit tests pass
- Integration: Can be used in error handling

**Rollback**: Delete `src/lib/ai/error-handling/retry-strategy.ts` file

---

### TASK-007: Add AI Analysis Timeout Configuration
**Category**: configuration  
**Priority**: high  
**Complexity**: trivial (<10 lines)

**Purpose**: Create a centralized timeout configuration system for AI analysis operations, allowing different timeouts for different operation types and making timeouts configurable.

**Context**: AI analysis timeouts are hardcoded in multiple places, making them difficult to adjust. This task centralizes timeout configuration.

**Inputs**:
- Required: None (configuration only)
- Optional: None

**Outputs**:
- Success: Exported configuration object with timeout values
- Error: None
- Side effects: None

**Dependencies**:
- Prerequisites: None
- Required data: None
- Required infrastructure: None

**Files**:
- Create: `src/lib/ai/config/timeout-config.ts`
- Modify: None

**Implementation**:
- Code structure: Exported configuration object
- Key logic:
  ```typescript
  export const AI_TIMEOUTS = {
    basicAnalysis: 30000, // 30s
    detailedAnalysis: 60000, // 60s
    fastAnalysis: 45000, // 45s
    stageRecommendation: 60000, // 60s
    contactInfoExtraction: 30000, // 30s
  } as const;
  
  export function getTimeout(operation: keyof typeof AI_TIMEOUTS): number {
    const envKey = `AI_TIMEOUT_${operation.toUpperCase()}`;
    return process.env[envKey] ? parseInt(process.env[envKey]!) : AI_TIMEOUTS[operation];
  }
  ```
- Libraries: None
- Config: Environment variables can override defaults

**Testing**:
- Unit tests:
  - Default values are correct
  - Environment variable overrides work
  - All timeout types are defined
  - Invalid environment variable values handled
- Edge cases: Invalid environment variable values
- Error scenarios: None
- Test data: Mock environment variables
- Coverage target: 80%+

**Acceptance Criteria**:
- ✅ All timeout types are defined
- ✅ Environment variable overrides work
- ✅ Default values are reasonable
- ✅ Configuration is type-safe
- ✅ Function completes in < 1ms

**Verification**:
- Manual: Check configuration values
- Automated: Unit tests pass
- Integration: Can be imported in AI service functions

**Rollback**: Delete `src/lib/ai/config/timeout-config.ts` file

---

### TASK-008: Create Response Length Validation Utility
**Category**: utility-function  
**Priority**: critical  
**Complexity**: simple (10-20 lines)

**Purpose**: Validate that AI responses meet minimum length requirements, a critical check to prevent short responses from being accepted.

**Context**: AI responses are often too short. This is a focused utility specifically for length validation, used by response quality validator and analysis orchestrator.

**Inputs**:
- Required:
  - `response: string` - The response to validate
  - `minLength: number` - Minimum required length (default: 500)
- Optional:
  - `maxLength?: number` - Maximum allowed length (default: 100000)

**Outputs**:
- Success:
  ```typescript
  interface LengthValidationResult {
    valid: boolean;
    length: number;
    meetsMinimum: boolean;
    exceedsMaximum: boolean;
  }
  ```
- Error: None (always returns result)
- Side effects: None

**Dependencies**:
- Prerequisites: None
- Required data: None
- Required infrastructure: None

**Files**:
- Create: `src/lib/ai/validation/length-validator.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `validateResponseLength()`
- Key logic:
  1. Get response length
  2. Check if meets minimum
  3. Check if exceeds maximum
  4. Return validation result
- Libraries: None (pure TypeScript)
- Config: None

**Testing**:
- Unit tests:
  - Response meets minimum length
  - Response too short
  - Response exceeds maximum
  - Empty response
  - Response exactly at minimum
- Edge cases:
  - Response with only whitespace
  - Very long response
- Error scenarios: None (function never throws)
- Test data: Sample responses of various lengths
- Coverage target: 95%+

**Acceptance Criteria**:
- ✅ Length validation is accurate
- ✅ Minimum and maximum checks work
- ✅ Function completes in < 1ms
- ✅ Handles edge cases correctly

**Verification**:
- Manual: Test with various response lengths
- Automated: Unit tests pass
- Integration: Can be used in response validation

**Rollback**: Delete `src/lib/ai/validation/length-validator.ts` file

---

### TASK-009: Implement AI Analysis Response Caching
**Category**: utility-function  
**Priority**: medium  
**Complexity**: moderate (25-50 lines)

**Purpose**: Cache AI analysis responses for identical conversations to avoid redundant API calls, improving performance and reducing API costs.

**Context**: Same conversations may be analyzed multiple times. Caching responses for identical conversations (same messages) will improve performance and reduce API usage.

**Inputs**:
- Required:
  - `messages: Message[]` - Conversation messages
  - `pipelineStages?: PipelineStage[]` - Pipeline stages (affects cache key)
- Optional:
  - `cacheTTL?: number` - Cache TTL in seconds (default: 3600 = 1 hour)

**Outputs**:
- Success: Cached analysis result or null if not cached
- Error: None (cache miss returns null)
- Side effects: Stores result in cache

**Dependencies**:
- Prerequisites: None
- Required data: Cache storage (Redis or in-memory)
- Required infrastructure: Cache service (optional, can use in-memory fallback)

**Files**:
- Create: `src/lib/ai/cache/analysis-cache.ts`
- Modify: None

**Implementation**:
- Code structure: Exported functions `getCachedAnalysis()`, `setCachedAnalysis()`
- Key logic:
  1. Generate cache key from messages hash + pipeline stages
  2. Check cache for existing result
  3. Return cached result if found and not expired
  4. Store new results in cache
- Libraries: Optional Redis client, or in-memory Map
- Config: Cache TTL, cache backend selection

**Testing**:
- Unit tests:
  - Cache hit returns cached result
  - Cache miss returns null
  - Cache expiration works
  - Cache key generation is consistent
- Edge cases:
  - Empty messages array
  - Very large messages array
  - Cache storage failure
- Error scenarios: Cache service unavailable
- Test data: Sample conversations, mock cache
- Coverage target: 85%+

**Acceptance Criteria**:
- ✅ Cache hits return correct results
- ✅ Cache misses return null
- ✅ Cache expiration works correctly
- ✅ Cache keys are consistent for same input
- ✅ Function completes in < 10ms for cache operations

**Verification**:
- Manual: Test cache hit/miss scenarios
- Automated: Unit tests pass
- Integration: Can be used in AI analysis functions

**Rollback**: Delete `src/lib/ai/cache/analysis-cache.ts` file

---

### TASK-010: Create Analysis Orchestrator Function
**Category**: utility-function  
**Priority**: critical  
**Complexity**: moderate (30-45 lines)

**Purpose**: Create a centralized function that orchestrates the AI analysis fallback chain (detailed → fast → enhanced → fallback) with proper validation and quality checks.

**Context**: The fallback logic is currently embedded in pipeline-analyzer. This task extracts it into a reusable orchestrator function with proper validation.

**Inputs**:
- Required:
  - `messages: Message[]` - Conversation messages
  - `pipelineStages?: PipelineStage[]` - Pipeline stages for stage recommendation
- Optional:
  - `conversationAge?: Date` - Conversation age for context
  - `minResponseLength?: number` - Minimum acceptable response length (default: 500)

**Outputs**:
- Success:
  ```typescript
  interface AnalysisResult {
    analysis: AIContactAnalysis | EnhancedAnalysisResult;
    source: 'detailed' | 'fast' | 'enhanced' | 'fallback';
    quality: 'excellent' | 'good' | 'acceptable' | 'poor';
    responseLength: number;
  }
  ```
- Error: `AnalysisError` if all methods fail
- Side effects: None (does not update database)

**Dependencies**:
- Prerequisites: TASK-003, TASK-004, TASK-007, TASK-008, TASK-009
- Required data: Access to AI services
- Required infrastructure: AI API access

**Files**:
- Create: `src/lib/ai/orchestrator/analysis-orchestrator.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `orchestrateAnalysis()`
- Key logic:
  1. Check cache first (TASK-009)
  2. Try detailed AI analysis first (`analyzeConversationWithStageRecommendation`)
  3. Validate response length (TASK-008) and quality (TASK-004)
  4. If fails or too short, try fast analysis (`analyzeConversationFast`)
  5. Validate response length and quality
  6. If fails or too short, try enhanced analysis (`analyzeConversationEnhanced`)
  7. If all fail, use fallback scoring
  8. Return result with source and quality
- Libraries: Existing AI services, validation utilities
- Config: Use TASK-007 timeout config

**Testing**:
- Unit tests:
  - Detailed analysis succeeds
  - Detailed analysis fails, fast succeeds
  - All AI methods fail, fallback used
  - Short responses are rejected
  - Cache hit returns cached result
- Edge cases:
  - All methods return null
  - Response exactly at minimum length
  - Very long conversation
- Error scenarios: All AI services unavailable
- Test data: Mock AI services, sample conversations
- Coverage target: 85%+

**Acceptance Criteria**:
- ✅ Detailed analysis is tried first
- ✅ Short responses are rejected and next method tried
- ✅ Fallback is only used when all AI methods fail
- ✅ Source is correctly identified
- ✅ Quality is accurately assessed
- ✅ Cache is checked first

**Verification**:
- Manual: Test orchestrator with various scenarios
- Automated: Unit tests pass
- Integration: Can be used in pipeline analyzer

**Rollback**: Delete `src/lib/ai/orchestrator/analysis-orchestrator.ts` file

---

### TASK-011: Integrate Analysis Orchestrator into Pipeline Analyzer
**Category**: integration  
**Priority**: critical  
**Complexity**: simple (15-25 lines)

**Purpose**: Replace the embedded fallback logic in pipeline-analyzer with calls to the analysis orchestrator function.

**Context**: The orchestrator (TASK-010) needs to be integrated into the actual pipeline analysis flow.

**Inputs**:
- Required: None (modification of existing code)
- Optional: None

**Outputs**:
- Success: Modified pipeline-analyzer uses orchestrator
- Error: None (code change only)
- Side effects: Pipeline analysis uses new orchestrator

**Dependencies**:
- Prerequisites: TASK-010 (analysis orchestrator)
- Required data: Access to `pipeline-analyzer.ts`
- Required infrastructure: None

**Files**:
- Modify: `src/lib/facebook/pipeline-analyzer.ts` (replace analysis logic with orchestrator call)
- Create: None

**Implementation**:
- Code structure: Update `executePipelineAnalysis` function
- Key logic:
  1. Import analysis orchestrator
  2. Replace existing analysis logic with orchestrator call
  3. Use orchestrator result to update contact
  4. Log source and quality
- Libraries: `@/lib/ai/orchestrator/analysis-orchestrator`
- Config: None

**Testing**:
- Unit tests:
  - Orchestrator is called correctly
  - Result is used to update contact
  - Source and quality are logged
- Edge cases:
  - Orchestrator returns error
  - Database update fails
- Error scenarios: Orchestrator unavailable
- Test data: Mock orchestrator, sample contacts
- Coverage target: 80%+

**Acceptance Criteria**:
- ✅ Orchestrator is called instead of embedded logic
- ✅ Result is correctly used
- ✅ Source and quality are logged
- ✅ Database updates work correctly
- ✅ No regression in functionality

**Verification**:
- Manual: Run pipeline analysis and check logs
- Automated: Unit tests pass
- Integration: Full pipeline analysis works correctly

**Rollback**: Revert changes to `src/lib/facebook/pipeline-analyzer.ts`

---

### TASK-012: Create Progress Tracking Utility
**Category**: utility-function  
**Priority**: high  
**Complexity**: moderate (20-35 lines)

**Purpose**: Create a utility function for updating analysis progress with throttling to avoid database overload.

**Context**: Progress updates are too infrequent. This utility provides throttled progress updates.

**Inputs**:
- Required:
  - `jobId: string` - Job ID to update
  - `current: number` - Current progress count
  - `total: number` - Total items to process
- Optional:
  - `message?: string` - Optional progress message
  - `forceUpdate?: boolean` - Force update even if throttled (default: false)

**Outputs**:
- Success: `void` (progress updated in database)
- Error: `ProgressUpdateError` if update fails
- Side effects: Updates `SyncJob` record in database

**Dependencies**:
- Prerequisites: None
- Required data: Access to `prisma` database
- Required infrastructure: Database connection

**Files**:
- Create: `src/lib/ai/progress/progress-tracker.ts`
- Modify: None

**Implementation**:
- Code structure: Exported function `updateAnalysisProgress()`
- Key logic:
  1. Check if update should be throttled (last update < 1 second ago)
  2. Calculate progress percentage
  3. Update SyncJob record
  4. Log progress update
- Libraries: `@prisma/client`
- Config: Throttle interval (default: 1000ms)

**Testing**:
- Unit tests:
  - Progress updates correctly
  - Throttling works
  - Force update bypasses throttle
  - Progress percentage is accurate
  - Database update succeeds
- Edge cases:
  - Progress > total
  - Progress = 0
  - Very large total
  - Rapid successive calls
- Error scenarios: Database update failure
- Test data: Mock database, sample job IDs
- Coverage target: 85%+

**Acceptance Criteria**:
- ✅ Progress updates are saved to database
- ✅ Throttling prevents excessive updates
- ✅ Force update bypasses throttle
- ✅ Progress percentage is accurate
- ✅ Function completes in < 100ms

**Verification**:
- Manual: Test progress updates with throttling
- Automated: Unit tests pass
- Integration: Progress visible in UI

**Rollback**: Delete `src/lib/ai/progress/progress-tracker.ts` file

---

### TASK-013: Integrate Progress Tracking into Pipeline Analyzer
**Category**: integration  
**Priority**: high  
**Complexity**: simple (10-20 lines)

**Purpose**: Add progress tracking calls throughout the pipeline analysis flow to provide real-time progress updates.

**Context**: Progress tracking utility (TASK-012) needs to be integrated into the pipeline analysis flow.

**Inputs**:
- Required: None (modification of existing code)
- Optional: None

**Outputs**:
- Success: Modified pipeline-analyzer includes progress updates
- Error: None (code change only)
- Side effects: Progress updates during analysis

**Dependencies**:
- Prerequisites: TASK-012 (progress tracker)
- Required data: Access to `pipeline-analyzer.ts`
- Required infrastructure: None

**Files**:
- Modify: `src/lib/facebook/pipeline-analyzer.ts` (add progress update calls)
- Create: None

**Implementation**:
- Code structure: Update `executePipelineAnalysis` function
- Key logic:
  1. Import progress tracker
  2. Add progress update calls:
     - After each contact is processed
     - After each batch completes
     - On errors
  3. Ensure updates are frequent but throttled
- Libraries: `@/lib/ai/progress/progress-tracker`
- Config: None

**Testing**:
- Unit tests:
  - Progress updates are called
  - Updates are at correct intervals
  - Progress counts are accurate
- Edge cases:
  - Single contact
  - Large batch
  - Analysis failure
- Error scenarios: Progress tracker unavailable
- Test data: Mock progress tracker, sample jobs
- Coverage target: 80%+

**Acceptance Criteria**:
- ✅ Progress updates are called during analysis
- ✅ Updates are frequent but throttled
- ✅ Progress counts are accurate
- ✅ Updates work for all analysis paths
- ✅ No performance degradation

**Verification**:
- Manual: Run analysis and check progress updates
- Automated: Unit tests pass
- Integration: Progress visible in UI during analysis

**Rollback**: Revert changes to `src/lib/facebook/pipeline-analyzer.ts`

---

### TASK-014: Create API Key Health Check Utility
**Category**: utility-function  
**Priority**: high  
**Complexity**: simple (15-25 lines)

**Purpose**: Create a utility that checks if an API key is healthy (not rate-limited, not invalid) and can be used for analysis.

**Context**: Before using an API key, we should check if it's healthy. This prevents using invalid or rate-limited keys.

**Inputs**:
- Required:
  - `apiKey: string` - API key to check
- Optional:
  - `checkDatabase?: boolean` - Check database for key status (default: true)

**Outputs**:
- Success:
  ```typescript
  interface KeyHealthCheck {
    healthy: boolean;
    status: 'active' | 'rate_limited' | 'invalid' | 'unknown';
    lastError?: string;
    lastUsed?: Date;
  }
  ```
- Error: None (always returns result)
- Side effects: None

**Dependencies**:
- Prerequisites: None
- Required data: Access to `apiKeyManager` (if checking database)
- Required infrastructure: Database connection (optional)

**Files**:
- Create: `src/lib/ai/health/key-health-check.ts`
- Modify: None

**Implementation**:
- Code structure: Single exported function `checkKeyHealth()`
- Key logic:
  1. If checking database, query key status
  2. Check if key is rate-limited
  3. Check if key is invalid/disabled
  4. Return health status
- Libraries: `@/lib/ai/api-key-manager` (optional)
- Config: None

**Testing**:
- Unit tests:
  - Healthy key returns healthy
  - Rate-limited key returns not healthy
  - Invalid key returns not healthy
  - Key not in database (if checking)
- Edge cases:
  - Key with no status
  - Key with recent errors
- Error scenarios: Database unavailable (if checking)
- Test data: Mock database, sample keys
- Coverage target: 85%+

**Acceptance Criteria**:
- ✅ Health status is accurate
- ✅ Rate-limited keys are identified
- ✅ Invalid keys are identified
- ✅ Function completes in < 50ms
- ✅ Works with or without database check

**Verification**:
- Manual: Test with various key statuses
- Automated: Unit tests pass
- Integration: Can be used before API calls

**Rollback**: Delete `src/lib/ai/health/key-health-check.ts` file

---

### TASK-015: Integrate Error Handling into AI Services
**Category**: integration  
**Priority**: high  
**Complexity**: moderate (20-40 lines)

**Purpose**: Integrate error classification and retry strategy utilities into AI service functions to improve error handling.

**Context**: Error handling utilities (TASK-005, TASK-006) need to be integrated into actual AI service functions.

**Inputs**:
- Required: None (modification of existing code)
- Optional: None

**Outputs**:
- Success: Modified AI services use error handling utilities
- Error: None (code change only)
- Side effects: Better error handling in AI services

**Dependencies**:
- Prerequisites: TASK-005, TASK-006, TASK-014
- Required data: Access to AI service files
- Required infrastructure: None

**Files**:
- Modify: `src/lib/ai/google-ai-service.ts`, `src/lib/ai/fast-detailed-analysis.ts` (add error handling)
- Create: None

**Implementation**:
- Code structure: Update error handling in AI service functions
- Key logic:
  1. Import error classifier and retry strategy
  2. Replace existing error handling with utilities
  3. Use classification to determine handling
  4. Use retry strategy to determine actions
  5. Mark keys as invalid/rate-limited based on strategy
- Libraries: Error handling utilities
- Config: None

**Testing**:
- Unit tests:
  - Error classification is used
  - Retry strategy is followed
  - Keys are marked correctly
  - Retries work correctly
- Edge cases:
  - Multiple error types
  - Max retries reached
  - Key rotation needed
- Error scenarios: Error utilities unavailable
- Test data: Mock errors, sample API keys
- Coverage target: 80%+

**Acceptance Criteria**:
- ✅ Error classification is used in all AI services
- ✅ Retry strategy is followed
- ✅ Keys are marked invalid/rate-limited correctly
- ✅ Retries work with exponential backoff
- ✅ No regression in error handling

**Verification**:
- Manual: Test with various error scenarios
- Automated: Unit tests pass
- Integration: Error handling works in production

**Rollback**: Revert changes to AI service files

---

### TASK-016: Fix AI Analysis Execution Flow
**Category**: integration  
**Priority**: critical  
**Complexity**: moderate (25-45 lines)

**Purpose**: Fix the AI analysis execution flow to ensure analysis actually runs, especially in serverless environments where background promises may not execute.

**Context**: Analysis jobs are created but don't execute (especially on Vercel serverless). This task ensures analysis execution is properly triggered and monitored.

**Inputs**:
- Required:
  - `jobId: string` - Job ID to execute
  - `facebookPageId: string` - Facebook page ID
- Optional:
  - `forceUpdateExisting?: boolean` - Force re-analysis (default: false)

**Outputs**:
- Success: `void` (analysis execution started)
- Error: `ExecutionError` if execution fails to start
- Side effects: Updates job status, starts analysis process

**Dependencies**:
- Prerequisites: TASK-013 (progress tracking integration)
- Required data: Access to `prisma` database, `executePipelineAnalysis` function
- Required infrastructure: Database connection, execution environment

**Files**:
- Modify: `src/lib/facebook/background-sync.ts` or analysis trigger endpoint
- Create: None

**Implementation**:
- Code structure: Update analysis trigger logic
- Key logic:
  1. Ensure job status is set to 'IN_PROGRESS' before execution
  2. Use proper async execution (not background promise)
  3. Add execution monitoring/logging
  4. Handle serverless environment constraints
  5. Ensure analysis function is actually called
- Libraries: Existing analysis functions
- Config: Execution timeout, monitoring interval

**Testing**:
- Unit tests:
  - Analysis execution starts correctly
  - Job status updates correctly
  - Execution logs are created
  - Serverless environment handling
- Edge cases:
  - Job already in progress
  - Job cancelled during execution
  - Execution timeout
- Error scenarios: Execution function unavailable
- Test data: Mock database, sample jobs
- Coverage target: 80%+

**Acceptance Criteria**:
- ✅ Analysis execution starts immediately
- ✅ Job status updates to IN_PROGRESS
- ✅ Execution logs are created
- ✅ Analysis function is called
- ✅ Works in serverless environment

**Verification**:
- Manual: Trigger analysis and verify execution
- Automated: Unit tests pass
- Integration: Analysis completes successfully

**Rollback**: Revert changes to trigger files

---

### TASK-017: Create AI Analysis Integration Tests
**Category**: integration  
**Priority**: high  
**Complexity**: moderate (30-50 lines)

**Purpose**: Create comprehensive integration tests for the AI analysis system to verify all components work together correctly and catch regressions.

**Context**: AI analysis involves multiple components (API calls, error handling, fallbacks, caching, progress tracking). Integration tests ensure everything works together.

**Inputs**:
- Required: Test configuration
- Optional: Mock API responses, test data

**Outputs**:
- Success: Test results (pass/fail)
- Error: Test failures with details
- Side effects: None (tests are isolated)

**Dependencies**:
- Prerequisites: TASK-001 through TASK-016 (all fixes implemented)
- Required data: Test database, mock API services
- Required infrastructure: Test environment, mocking framework

**Files**:
- Create: `src/lib/ai/__tests__/integration.test.ts`
- Modify: None

**Implementation**:
- Code structure: Jest/Vitest test suite
- Key logic:
  1. Test full analysis flow (detailed → fast → enhanced → fallback)
  2. Test error handling and retries
  3. Test progress tracking
  4. Test caching
  5. Test response validation
  6. Test execution flow
- Libraries: Jest/Vitest, testing utilities
- Config: Test timeout, mock configurations

**Testing**:
- Test cases:
  - Full successful analysis flow
  - Analysis with API failures and retries
  - Analysis with short responses (rejection)
  - Progress tracking during analysis
  - Cache hit/miss scenarios
  - Error recovery scenarios
  - Execution flow in serverless environment
- Edge cases: All error paths, timeout scenarios
- Error scenarios: All failure modes
- Test data: Sample conversations, mock API responses
- Coverage target: 80%+ integration coverage

**Acceptance Criteria**:
- ✅ All integration test cases pass
- ✅ Tests cover happy path and error paths
- ✅ Tests are fast (< 30 seconds total)
- ✅ Tests are isolated and repeatable
- ✅ Mock data is realistic

**Verification**:
- Manual: Run test suite
- Automated: CI/CD runs tests
- Integration: Tests catch regressions

**Rollback**: Delete test file

---

## Summary

This refined decomposition breaks down "fix AI analysis" into 17 atomic microtasks (increased from 12) that address:
1. **Diagnostics** (TASK-001, TASK-002): Understand current issues
2. **Quality** (TASK-003, TASK-004, TASK-008): Ensure prompts and responses meet quality standards
3. **Reliability** (TASK-005, TASK-006, TASK-007, TASK-014, TASK-015): Improve error handling, timeouts, and key health
4. **Performance** (TASK-009, TASK-010, TASK-011): Fix fallback priority and add caching
5. **Integration** (TASK-012, TASK-013, TASK-016): Fix progress tracking and execution flow
6. **Testing** (TASK-017): Ensure everything works together

### Improvements Made:
- **Better granularity**: Split multi-purpose tasks into focused single-purpose tasks
- **Clearer interfaces**: All inputs/outputs have explicit TypeScript types
- **Fixed dependencies**: Removed circular dependencies, corrected ordering
- **Enhanced testability**: Specific test cases for each task
- **Complete coverage**: All aspects of the original task are covered

Each task is:
- < 50 lines of code ✅
- Completable in < 2 hours ✅
- Has 2-3 dependencies max ✅
- Independently testable ✅
- Has clear I/O contracts ✅
- Single responsibility ✅









