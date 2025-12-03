# Pipeline Analysis Feature Documentation

## Table of Contents

1. [How to Use Pipeline Analysis](#how-to-use-pipeline-analysis)
2. [Job Status Meanings](#job-status-meanings)
3. [How to Cancel Jobs](#how-to-cancel-jobs)

---

## How to Use Pipeline Analysis

The Pipeline Analysis feature automatically analyzes your Facebook Messenger and Instagram conversations, calculates lead scores, and intelligently assigns contacts to appropriate pipeline stages based on conversation context, customer intent, and engagement level.

### Prerequisites

Before using Pipeline Analysis, ensure you have:

1. **Connected Facebook Page**: A Facebook page must be connected to your account
2. **Contacts Synced**: At least some contacts should be synced from your Facebook page
3. **Pipeline Configured** (Optional): While not required, having a pipeline configured will improve analysis accuracy

### Starting Pipeline Analysis

#### Via User Interface

1. **Navigate to Settings**
   - Go to **Settings** → **Integrations**
   - Find your connected Facebook page in the list

2. **Start Analysis**
   - Click the **"Analyze Pipeline"** button next to your Facebook page
   - If no pipeline is configured, you'll be prompted to generate one using AI first
   - If a pipeline exists, analysis will start immediately

3. **Monitor Progress**
   - The job status will update in real-time
   - You'll see progress indicators showing:
     - Total contacts being analyzed
     - Contacts successfully analyzed
     - Contacts that failed analysis
   - A toast notification will confirm when analysis starts

#### Via API

You can also start pipeline analysis programmatically using the API:

**Endpoint**: `POST /api/facebook/analyze-pipeline`

**Request Body**:
```json
{
  "facebookPageId": "your-facebook-page-id",
  "forceUpdateExisting": true  // Optional: force re-analysis of all contacts
}
```

**Response**:
```json
{
  "success": true,
  "jobId": "job-id-here",
  "message": "Pipeline analysis started"
}
```

### What Happens During Analysis

1. **Contact Selection**: The system identifies contacts that need analysis
   - By default, contacts without existing pipeline assignments are prioritized
   - If `forceUpdateExisting` is true, all contacts are re-analyzed

2. **Conversation Fetching**: For each contact, the system:
   - Fetches all messages from Facebook Messenger/Instagram
   - Filters out system messages
   - Prepares conversation context for AI analysis

3. **AI Analysis**: Each conversation is analyzed to determine:
   - **Lead Score** (0-100): Based on engagement and intent
   - **Lead Status**: NEW, CONTACTED, QUALIFIED, etc.
   - **Recommended Pipeline Stage**: Best stage for the contact
   - **Confidence Level**: How confident the AI is in the assignment
   - **Reasoning**: Explanation for the stage assignment

4. **Stage Assignment**: Contacts are automatically assigned to pipeline stages based on:
   - AI-recommended stage
   - Lead score ranges configured for each stage
   - Current pipeline configuration

5. **Database Updates**: Contact records are updated with:
   - Pipeline assignment
   - Stage assignment
   - Lead score
   - AI analysis context
   - Analysis timestamp

### Analysis Modes

The system supports two analysis modes:

1. **Skip Existing** (Default)
   - Only analyzes contacts that don't have a pipeline assignment
   - Faster processing
   - Preserves existing assignments

2. **Update Existing** (`forceUpdateExisting: true`)
   - Re-analyzes all contacts, including those already assigned
   - Useful when pipeline stages change or you want fresh analysis
   - Takes longer but ensures all contacts are up-to-date

### Performance

- **Processing Speed**: Approximately 100+ contacts per minute
- **Concurrency**: Multiple contacts are processed in parallel
- **Background Processing**: Analysis runs asynchronously, so you can continue using the app
- **Automatic Retries**: Failed analyses are automatically retried with exponential backoff

### Best Practices

1. **Run Analysis After Major Changes**
   - After creating or modifying pipeline stages
   - After syncing new contacts
   - When you want to refresh lead scores

2. **Use Force Update Sparingly**
   - Force updates take longer and consume more resources
   - Only use when necessary (e.g., after pipeline restructuring)

3. **Monitor Job Status**
   - Check the job status regularly to ensure it's progressing
   - Cancel if you notice issues or need to stop the process

4. **Check Failed Contacts**
   - Review contacts that failed analysis
   - Common reasons: missing conversations, API errors, invalid data

---

## Job Status Meanings

Pipeline Analysis jobs can have one of five statuses. Understanding these statuses helps you track progress and troubleshoot issues.

### Status Overview

| Status | Description | Can Cancel? | Next Actions |
|--------|-------------|-------------|--------------|
| `PENDING` | Job is queued but not started | ✅ Yes | Wait for processing to begin |
| `IN_PROGRESS` | Job is actively processing contacts | ✅ Yes | Monitor progress or cancel if needed |
| `COMPLETED` | Job finished successfully | ❌ No | Review results, check contact assignments |
| `FAILED` | Job encountered an error and stopped | ❌ No | Review error logs, fix issues, restart |
| `CANCELLED` | Job was cancelled by user or system | ❌ No | Start a new analysis if needed |

### Detailed Status Descriptions

#### PENDING

**What it means:**
- The job has been created and is waiting to start
- No contacts have been processed yet
- The system is preparing to begin analysis

**When you see this:**
- Immediately after starting a new analysis
- If the system is busy processing other jobs
- During initial setup phase

**What to do:**
- Wait a few seconds for processing to begin
- Status should change to `IN_PROGRESS` shortly
- If it stays `PENDING` for more than a minute, there may be an issue

#### IN_PROGRESS

**What it means:**
- The job is actively analyzing contacts
- Contacts are being processed in batches
- Progress counters are updating in real-time

**When you see this:**
- During normal analysis operation
- After the job transitions from `PENDING`

**What to do:**
- Monitor progress through the UI
- Check the progress indicators:
  - `syncedContacts` / `analyzedContacts`: Number successfully processed
  - `failedContacts`: Number that failed
  - `totalContacts`: Total to process
- You can cancel if needed (see [How to Cancel Jobs](#how-to-cancel-jobs))

**Progress Calculation:**
```
Progress % = (analyzedContacts / totalContacts) × 100
```

#### COMPLETED

**What it means:**
- All contacts were successfully analyzed (or skipped if already assigned)
- The job finished without errors
- All database updates have been applied

**When you see this:**
- After successful completion of analysis
- All contacts have been processed

**What to do:**
- Review the results:
  - Check how many contacts were analyzed
  - Verify contact assignments in your pipeline
  - Review any contacts that may need manual adjustment
- Check the `completedAt` timestamp to see when it finished
- Start a new analysis if you need to update contacts

**Success Indicators:**
- `status: "COMPLETED"`
- `completedAt` timestamp is set
- `analyzedContacts` matches or is close to `totalContacts`
- `failedContacts` is low or zero

#### FAILED

**What it means:**
- The job encountered an error and stopped processing
- Some contacts may have been analyzed before the failure
- The error details are stored in the job record

**When you see this:**
- API errors (Facebook API rate limits, authentication issues)
- Database connection problems
- Invalid pipeline configuration
- Missing or deleted Facebook page
- Token expiration

**What to do:**
1. **Check Error Details**
   - Review the `errors` field in the job record
   - Look for specific error messages
   - Check server logs for detailed information

2. **Common Issues and Fixes:**
   - **Token Expired**: Re-authenticate your Facebook page
   - **Rate Limit**: Wait a few minutes and retry
   - **Pipeline Deleted**: Recreate the pipeline or assign a different one
   - **Page Deleted**: Reconnect your Facebook page

3. **Restart Analysis**
   - Fix the underlying issue
   - Start a new analysis job
   - The system will skip already-analyzed contacts (unless using force update)

**Error Information:**
- Errors are stored as JSON in the `errors` field
- Each error includes:
  - Error message
  - Timestamp
  - Contact ID (if applicable)
  - Error type

#### CANCELLED

**What it means:**
- The job was stopped by user action or system cancellation
- Processing stopped at the point of cancellation
- Contacts processed before cancellation are saved
- No further processing will occur

**When you see this:**
- User clicked "Cancel" button
- System detected a cancellation request
- Job was cancelled via API

**What to do:**
- Review partial results:
  - Check how many contacts were analyzed before cancellation
  - Verify those contacts have correct assignments
- Start a new analysis if needed:
  - The system will skip already-analyzed contacts
  - Only unprocessed contacts will be analyzed

**Cancellation Behavior:**
- Cancellation is checked periodically during processing
- The job stops gracefully at the next check point
- No data is lost from contacts already processed
- The `completedAt` timestamp is set when cancelled

### Status Transitions

Jobs follow this typical flow:

```
PENDING → IN_PROGRESS → COMPLETED
                    ↓
                 FAILED
                    ↓
              CANCELLED (if user cancels)
```

**Important Notes:**
- Jobs cannot transition from `COMPLETED` or `FAILED` back to `IN_PROGRESS`
- Once `CANCELLED`, a job cannot be resumed (start a new job instead)
- Status changes are atomic and immediate

### Checking Job Status

#### Via UI
- Job status is displayed in the Integrations page
- Real-time updates show current status
- Progress indicators show completion percentage

#### Via API
**Endpoint**: `GET /api/facebook/sync-status/[jobId]`

**Note**: Pipeline analysis jobs use the same `SyncJob` model as contact sync jobs, so they share the same status endpoint.

**Response**:
```json
{
  "id": "job-id",
  "status": "IN_PROGRESS",
  "totalContacts": 1000,
  "syncedContacts": 450,
  "failedContacts": 2,
  "startedAt": "2025-11-12T10:00:00Z",
  "completedAt": null
}
```

**Note**: For pipeline analysis jobs, `syncedContacts` represents `analyzedContacts` (contacts successfully analyzed).

---

## How to Cancel Jobs

You can cancel pipeline analysis jobs that are in `PENDING` or `IN_PROGRESS` status. This is useful if you need to stop processing, fix configuration issues, or start a new analysis with different parameters.

### When to Cancel

Consider cancelling a job if:

- **Wrong Configuration**: You started analysis with incorrect settings
- **Performance Issues**: The job is taking too long and you want to optimize first
- **System Problems**: You notice errors and want to fix them before continuing
- **Change of Plans**: You need to modify the pipeline before analysis completes
- **Resource Constraints**: System resources are needed for other operations

### Cancellation Requirements

**Can be cancelled:**
- ✅ Jobs with status `PENDING`
- ✅ Jobs with status `IN_PROGRESS`

**Cannot be cancelled:**
- ❌ Jobs with status `COMPLETED` (already finished)
- ❌ Jobs with status `FAILED` (already stopped)
- ❌ Jobs with status `CANCELLED` (already cancelled - idempotent)

### Cancelling via User Interface

1. **Navigate to Settings**
   - Go to **Settings** → **Integrations**
   - Find the Facebook page with an active analysis job

2. **Identify Active Job**
   - Look for pages showing "Analyzing..." or progress indicators
   - The status will show `PENDING` or `IN_PROGRESS`

3. **Cancel the Job**
   - Click the **"Cancel"** or **"Stop"** button next to the active job
   - Confirm the cancellation if prompted

4. **Verify Cancellation**
   - Status should change to `CANCELLED`
   - A confirmation message will appear
   - Processing will stop at the next check point

### Cancelling via API

**Endpoint**: `POST /api/facebook/analyze-pipeline/cancel`

**Request Body**:
```json
{
  "jobId": "your-job-id"
}
```

**Success Response** (200):
```json
{
  "success": true,
  "job": {
    "id": "job-id",
    "status": "CANCELLED",
    "syncedContacts": 450,
    "failedContacts": 2,
    "totalContacts": 1000,
    "completedAt": "2025-11-12T10:15:00Z"
  }
}
```

**Error Responses**:

**Job Not Found** (404):
```json
{
  "error": "Sync job not found"
}
```

**Already Completed** (409):
```json
{
  "error": "Cannot cancel job with status: COMPLETED"
}
```

**Already Failed** (409):
```json
{
  "error": "Cannot cancel job with status: FAILED"
}
```

**Already Cancelled** (200 - Idempotent):
```json
{
  "success": true,
  "job": { ... },
  "message": "Job is already cancelled"
}
```

**Unauthorized** (403):
```json
{
  "error": "Unauthorized"
}
```

### How Cancellation Works

1. **Immediate Status Update**
   - The job status is immediately set to `CANCELLED` in the database
   - The `completedAt` timestamp is set to the current time
   - This prevents race conditions using atomic database operations

2. **Graceful Processing Stop**
   - The background worker checks for cancellation at regular intervals
   - When cancellation is detected, processing stops at the next check point
   - Current batch completes, but no new batches are started

3. **Data Preservation**
   - Contacts already analyzed before cancellation are saved
   - No data is lost from completed work
   - Partial results remain in the database

4. **Check Points**
   - Cancellation is checked:
     - Before processing each contact batch
     - After completing each batch
     - Before starting new operations
   - This ensures responsive cancellation (typically within seconds)

### After Cancellation

**What Happens:**
- Job status changes to `CANCELLED`
- Processing stops gracefully
- Contacts processed before cancellation are saved
- No further analysis occurs

**What You Can Do:**
1. **Review Partial Results**
   - Check which contacts were analyzed
   - Verify their pipeline assignments
   - Review any errors that occurred

2. **Fix Issues** (if cancellation was due to problems)
   - Address configuration issues
   - Fix pipeline settings
   - Resolve authentication problems

3. **Start New Analysis**
   - Create a new analysis job
   - The system will skip already-analyzed contacts (unless using force update)
   - Only unprocessed contacts will be analyzed

### Cancellation Best Practices

1. **Cancel Early**
   - If you need to cancel, do it as soon as possible
   - Earlier cancellation saves processing time and resources

2. **Check Status First**
   - Verify the job is in `PENDING` or `IN_PROGRESS` before attempting to cancel
   - Completed or failed jobs cannot be cancelled

3. **Wait for Confirmation**
   - Wait for the cancellation confirmation before starting a new job
   - This prevents conflicts and ensures clean state

4. **Review Partial Results**
   - Check what was accomplished before cancellation
   - This helps you understand what still needs to be done

5. **Use Force Update if Needed**
   - If you cancelled to fix configuration, use `forceUpdateExisting: true` on the next run
   - This ensures all contacts are re-analyzed with the new settings

### Troubleshooting Cancellation

**Issue: Cancel button doesn't work**
- **Solution**: Refresh the page and try again
- **Check**: Verify the job status is `PENDING` or `IN_PROGRESS`

**Issue: Job continues after cancellation**
- **Solution**: Wait a few seconds - cancellation checks happen periodically
- **Check**: Verify the status actually changed to `CANCELLED` in the database

**Issue: Cannot cancel - status is COMPLETED**
- **Solution**: This is expected - completed jobs cannot be cancelled
- **Action**: Start a new analysis if you need to re-analyze contacts

**Issue: Error when cancelling**
- **Solution**: Check error message for specific issue
- **Common causes**: Job not found, unauthorized access, job already in final state

---

## Additional Resources

- **API Documentation**: See `src/app/api/facebook/analyze-pipeline/route.ts`
- **Cancel API**: See `src/app/api/facebook/analyze-pipeline/cancel/route.ts`
- **Implementation**: See `src/lib/facebook/pipeline-analyzer.ts`
- **UI Component**: See `src/components/integrations/connected-pages-list.tsx`

## Support

If you encounter issues with Pipeline Analysis:

1. Check the job status and error messages
2. Review server logs for detailed error information
3. Verify your Facebook page connection and permissions
4. Ensure your pipeline is properly configured
5. Check that contacts have been synced from Facebook

For additional help, refer to the main [README.md](./README.md) or open an issue on GitHub.

