# 🚀 Deployment Checklist - AI Personalization Feature

## ✅ Pre-Deployment Checks

### 1. Code Status
- [x] All tests passed (60/60)
- [x] No linting errors
- [x] All files committed (or ready to commit)
- [x] Build command configured in `package.json`

### 2. New Files Added
- [x] `src/app/api/campaigns/preview-personalized-message/route.ts` - New endpoint
- [x] Updated `src/app/(dashboard)/campaigns/new/page.tsx` - AI personalization UI
- [x] Updated `src/lib/campaigns/send.ts` - AI message generation
- [x] Updated `src/app/api/cron/send-scheduled/route.ts` - Scheduled campaign AI

### 3. Database Schema
- [x] `useAiPersonalization` field exists
- [x] `aiCustomInstructions` field exists
- [x] `aiMessagesMap` field exists
- [x] Contact `aiContext` field exists

### 4. Vercel Configuration
- [x] `vercel.json` exists with cron jobs
- [x] Build command: `npm run build`
- [x] Install command: `npm install --legacy-peer-deps`

## 📋 Deployment Steps

### Option 1: Deploy via Vercel Dashboard (Recommended)

1. **Commit your changes:**
   ```bash
   git add .
   git commit -m "Add AI personalization feature for campaigns"
   git push origin jad
   ```

2. **Go to Vercel Dashboard:**
   - Visit: https://vercel.com/dashboard
   - Select your project

3. **Deploy:**
   - Vercel will automatically detect the push
   - Or click "Deploy" → "Redeploy" on latest deployment

### Option 2: Deploy via Vercel CLI

1. **Install Vercel CLI (if not installed):**
   ```bash
   npm i -g vercel
   ```

2. **Login to Vercel:**
   ```bash
   vercel login
   ```

3. **Deploy:**
   ```bash
   # Preview deployment
   vercel

   # Production deployment
   vercel --prod
   ```

## 🔐 Environment Variables Check

Make sure these are set in Vercel Dashboard → Settings → Environment Variables:

### Required for AI Personalization:
- ✅ `NVIDIA_API_KEY` or `GOOGLE_AI_API_KEY` - For AI message generation
- ✅ `DATABASE_URL` - For contact data
- ✅ `DIRECT_URL` - For Prisma migrations
- ✅ `ENCRYPTION_KEY` - For API key encryption
- ✅ `NEXTAUTH_SECRET` - For authentication
- ✅ `NEXTAUTH_URL` - Your Vercel domain
- ✅ `NEXT_PUBLIC_APP_URL` - Your Vercel domain

### Optional but Recommended:
- `CRON_SECRET` - For cron job security
- `REDIS_URL` - For campaign processing
- `FACEBOOK_APP_ID` - For Facebook integration
- `FACEBOOK_APP_SECRET` - For Facebook integration

## 🧪 Post-Deployment Testing

After deployment, test these features:

1. **Campaign Creation:**
   - Navigate to `/campaigns/new`
   - Verify AI personalization toggle appears
   - Enable AI personalization
   - Add custom instructions
   - Test preview functionality

2. **Preview Endpoint:**
   - Test `/api/campaigns/preview-personalized-message`
   - Verify it generates personalized messages

3. **Campaign Sending:**
   - Create a test campaign with AI personalization
   - Start the campaign
   - Verify personalized messages are generated and sent

4. **Scheduled Campaigns:**
   - Create a scheduled campaign with AI personalization
   - Verify it generates AI messages when scheduled time arrives

## 🐛 Troubleshooting

### Build Fails
- Check Vercel build logs
- Verify all environment variables are set
- Check for TypeScript errors: `npm run build` locally

### AI Generation Fails
- Verify `NVIDIA_API_KEY` or `GOOGLE_AI_API_KEY` is set
- Check API key is valid and has credits
- Review error logs in Vercel dashboard

### Database Errors
- Verify `DATABASE_URL` and `DIRECT_URL` are correct
- Check Prisma schema is up to date
- Run `npx prisma generate` if needed

## 📊 Monitoring

After deployment, monitor:
- Build success rate
- API endpoint response times
- AI generation success rate
- Error logs in Vercel dashboard

## ✅ Success Criteria

Deployment is successful when:
- [ ] Build completes without errors
- [ ] All environment variables are set
- [ ] Campaign creation page loads
- [ ] AI personalization toggle works
- [ ] Preview endpoint responds correctly
- [ ] Test campaign can be created and sent


