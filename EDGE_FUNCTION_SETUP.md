# Solution 2: Supabase Edge Functions for AI Analysis

## Overview

This solution offloads AI analysis to Supabase Edge Functions, which run in a separate environment with their own connection pool. This reduces connection pool exhaustion on the main serverless function.

## Architecture

```
┌─────────────────┐
│  Next.js API    │
│  (Vercel)       │
└────────┬────────┘
         │
         │ HTTP Request
         ▼
┌─────────────────┐
│ Edge Function   │
│ (Supabase)      │
│                 │
│ - Own DB Pool   │
│ - Longer Timeout│
│ - Isolated      │
└─────────────────┘
```

## Benefits

1. **Connection Pool Isolation**: Edge function has its own database connection pool
2. **Longer Timeouts**: Edge functions support longer execution times than Vercel serverless
3. **Better Resource Management**: AI processing doesn't compete with API requests
4. **Graceful Fallback**: Automatically falls back to local analysis if edge function fails

## Implementation Status

✅ **Completed:**
- Edge function client utility (`src/lib/ai/edge-function-client.ts`)
- Integration into `analyze-contact.ts` with fallback
- Edge function structure (`supabase/functions/analyze-contact/`)
- Configuration support via environment variables

⚠️ **Needs Implementation:**
- Edge function analysis logic (currently placeholder)
- Edge function deployment
- Environment variable configuration

## Configuration

### Enable Edge Function

Add to your `.env.local`:

```env
# Enable edge function for AI analysis
USE_EDGE_FUNCTION_FOR_AI=true

# Supabase configuration (required)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
```

### Disable Edge Function

Remove or set to `false`:

```env
USE_EDGE_FUNCTION_FOR_AI=false
```

When disabled, the system automatically uses local analysis (current behavior).

## Deployment Steps

1. **Install Supabase CLI**:
   ```bash
   npm install -g supabase
   ```

2. **Login to Supabase**:
   ```bash
   supabase login
   ```

3. **Link Project**:
   ```bash
   supabase link --project-ref your-project-ref
   ```

4. **Deploy Function**:
   ```bash
   supabase functions deploy analyze-contact
   ```

5. **Set Environment Variables** in Supabase Dashboard:
   - `NVIDIA_API_KEY`
   - `GOOGLE_AI_API_KEY` (optional)
   - `DATABASE_URL` (for API key management)

## Edge Function Implementation Options

### Option 1: Standalone Implementation (Recommended)

Copy the analysis logic from:
- `src/lib/ai/fast-detailed-analysis.ts`
- `src/lib/ai/enhanced-analysis-v2.ts`

Into the edge function. This requires adapting the code for Deno runtime.

**Pros:**
- Fully isolated
- No network overhead
- Best performance

**Cons:**
- Code duplication
- Requires Deno adaptation

### Option 2: API Proxy

Make the edge function call back to your Next.js API endpoint.

**Pros:**
- No code duplication
- Easy to implement

**Cons:**
- Adds network latency
- Still uses main server connection pool

### Option 3: Shared Service

Create a shared analysis service that both can call.

**Pros:**
- Single source of truth
- Reusable

**Cons:**
- More complex architecture
- Requires additional infrastructure

## Current Behavior

- **Edge Function Enabled**: Tries edge function first, falls back to local if it fails
- **Edge Function Disabled**: Uses local analysis (current behavior)
- **Edge Function Unavailable**: Automatically falls back to local analysis

## Testing

Test the integration:

1. Enable edge function in environment variables
2. Run pipeline analysis
3. Check logs for "Analysis successful via edge function" messages
4. Verify fallback works if edge function is unavailable

## Monitoring

- **Edge Function Logs**: Supabase Dashboard > Edge Functions > Logs
- **Application Logs**: Check for edge function call messages
- **Fallback Rate**: Monitor how often local analysis is used as fallback

## Next Steps

1. Implement analysis logic in edge function (Option 1 recommended)
2. Deploy edge function to Supabase
3. Configure environment variables
4. Test with production workload
5. Monitor performance and fallback rates









