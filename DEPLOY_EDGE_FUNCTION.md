# Deploy Edge Function to Supabase

## Quick Deployment Guide

### Option 1: Using Supabase CLI (Recommended)

1. **Install Supabase CLI** (choose one method):

   **Windows (Scoop):**
   ```powershell
   scoop bucket add supabase https://github.com/supabase/scoop-bucket.git
   scoop install supabase
   ```

   **Windows (Chocolatey):**
   ```powershell
   choco install supabase
   ```

   **Or download directly:**
   - Visit: https://github.com/supabase/cli/releases
   - Download the Windows executable
   - Add to PATH

2. **Login to Supabase:**
   ```bash
   supabase login
   ```

3. **Link to your project:**
   ```bash
   supabase link --project-ref YOUR_PROJECT_REF
   ```
   (Find your project ref in Supabase Dashboard > Settings > General)

4. **Deploy the function:**
   ```bash
   supabase functions deploy analyze-contact
   ```

5. **Set environment variables** in Supabase Dashboard:
   - Go to: Project Settings > Edge Functions > Environment Variables
   - Add:
     - `NVIDIA_API_KEY` = your NVIDIA API key
     - `GOOGLE_AI_API_KEY` = your Google AI API key (optional)

### Option 2: Using Supabase Dashboard

1. **Go to Supabase Dashboard:**
   - Navigate to: Edge Functions > Create Function

2. **Create function:**
   - Name: `analyze-contact`
   - Copy contents from `supabase/functions/analyze-contact/index.ts`

3. **Set environment variables:**
   - Go to: Project Settings > Edge Functions > Environment Variables
   - Add your API keys

### Option 3: Using GitHub Actions (CI/CD)

Create `.github/workflows/deploy-edge-function.yml`:

```yaml
name: Deploy Edge Function

on:
  push:
    branches: [main]
    paths:
      - 'supabase/functions/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: supabase/setup-cli@v1
        with:
          version: latest
      
      - run: supabase functions deploy analyze-contact
        env:
          SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }}
          SUPABASE_PROJECT_ID: ${{ secrets.SUPABASE_PROJECT_ID }}
```

## Verify Deployment

1. **Test the function:**
   ```bash
   curl -X POST https://YOUR_PROJECT.supabase.co/functions/v1/analyze-contact \
     -H "Authorization: Bearer YOUR_ANON_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "messages": [
         {"from": "User", "text": "Hello, I am interested"},
         {"from": "Business", "text": "Great! How can I help?"}
       ]
     }'
   ```

2. **Check logs:**
   - Supabase Dashboard > Edge Functions > analyze-contact > Logs

## Enable in Next.js

Add to your `.env.local`:

```env
USE_EDGE_FUNCTION_FOR_AI=true
NEXT_PUBLIC_SUPABASE_URL=https://YOUR_PROJECT.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
```

## Troubleshooting

### Function not found
- Verify function name is exactly `analyze-contact`
- Check project ref is correct

### Authentication errors
- Verify `NEXT_PUBLIC_SUPABASE_ANON_KEY` is correct
- Check function has proper CORS headers

### API key errors
- Verify environment variables are set in Supabase Dashboard
- Check API keys are valid

### Timeout errors
- Edge functions have 60s timeout by default
- Consider breaking large analyses into smaller chunks









