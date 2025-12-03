# Analyze Contact Edge Function

This Supabase Edge Function offloads AI analysis to a separate environment, reducing connection pool pressure on the main serverless function.

## Benefits

- **Reduced Connection Pool Exhaustion**: AI analysis runs in a separate environment with its own connection pool
- **Longer Execution Time**: Edge functions have longer timeout limits than Vercel serverless
- **Better Resource Isolation**: AI processing doesn't compete with API requests for database connections
- **Scalability**: Edge functions can scale independently

## Deployment

### Prerequisites

1. Supabase CLI installed: `npm install -g supabase`
2. Supabase project created
3. Environment variables configured

### Deploy

```bash
# Login to Supabase
supabase login

# Link to your project
supabase link --project-ref your-project-ref

# Deploy the function
supabase functions deploy analyze-contact
```

### Environment Variables

Set these in your Supabase project dashboard under Edge Functions > Settings:

- `NVIDIA_API_KEY` - Your NVIDIA API key for AI analysis
- `GOOGLE_AI_API_KEY` - Fallback Google AI API key (optional)
- `DATABASE_URL` - Your Supabase database connection string (for API key management)

## Usage

The edge function is automatically called by the Next.js application when:
1. `USE_EDGE_FUNCTION_FOR_AI=true` is set in environment variables
2. `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` are configured

## Implementation Note

**Important**: The current edge function implementation (`index.ts`) is a placeholder. You need to:

1. **Option A**: Implement the analysis logic directly in the edge function (copy from `src/lib/ai/fast-detailed-analysis.ts` and `src/lib/ai/enhanced-analysis-v2.ts`)

2. **Option B**: Make the edge function call back to your Next.js API endpoint (simpler but adds network overhead)

3. **Option C**: Use a shared analysis service that both can call

For now, the client (`src/lib/ai/edge-function-client.ts`) will gracefully fall back to local analysis if the edge function is not available or fails.

## Testing

Test the edge function directly:

```bash
curl -X POST https://your-project.supabase.co/functions/v1/analyze-contact \
  -H "Authorization: Bearer YOUR_ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"from": "User", "text": "Hello, I am interested in your product"},
      {"from": "Business", "text": "Great! How can I help you?"}
    ],
    "useFastAnalysis": true
  }'
```

## Monitoring

Monitor edge function execution in:
- Supabase Dashboard > Edge Functions > Logs
- Check for errors, execution time, and success rates









