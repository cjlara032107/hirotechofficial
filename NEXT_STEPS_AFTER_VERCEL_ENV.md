# ✅ Next Steps After Setting Up Vercel Environment Variables

## 🎯 Immediate Actions Required

### Step 1: Deploy Your Project (If Not Already Done)

**Option A: Via Vercel Dashboard (Easiest)**
1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click **"Add New"** → **"Project"**
3. Import your GitHub repository: `cjlara032107/hirotechofficial`
4. Select branch: **main** (or **jad**)
5. Vercel will auto-detect Next.js settings
6. Click **"Deploy"**

**Option B: Via Vercel CLI**
```bash
# Install Vercel CLI (if not installed)
npm install -g vercel

# Login
vercel login

# Deploy
vercel --prod
```

---

### Step 2: Get Your Vercel Domain

After deployment completes:
1. Vercel will show you a URL like: `https://your-project-name.vercel.app`
2. **Copy this URL** - you'll need it for the next steps

---

### Step 3: Update Environment Variables with Your Vercel Domain

Go back to **Vercel Dashboard** → **Settings** → **Environment Variables** and update:

```env
NEXT_PUBLIC_APP_URL=https://your-actual-vercel-domain.vercel.app
NEXTAUTH_URL=https://your-actual-vercel-domain.vercel.app
```

**Important:** Replace `your-actual-vercel-domain` with your actual Vercel domain!

After updating, **redeploy** (or wait for auto-deploy if Git is connected).

---

### Step 4: Run Database Migrations

You need to set up your database schema. Choose one method:

**Option A: Via Build Command (Recommended - Automatic)**

Update your `package.json` to include:

```json
{
  "scripts": {
    "vercel-build": "prisma generate && prisma migrate deploy && next build"
  }
}
```

Then in Vercel Dashboard → **Settings** → **General** → **Build & Development Settings**:
- Set **Build Command** to: `npm run vercel-build`

This will run migrations automatically on every deployment.

**Option B: Via Vercel CLI (One-time)**

```bash
# Install Vercel CLI
npm install -g vercel

# Login
vercel login

# Link to your project
vercel link

# Pull environment variables
vercel env pull .env.production

# Run migrations
npx prisma migrate deploy
```

**Option C: Via Supabase SQL Editor (If migrations fail)**

1. Go to [Supabase Dashboard](https://app.supabase.com)
2. Select your project
3. Go to **SQL Editor**
4. Check your `prisma/schema.prisma` file
5. Run the SQL commands manually (or use Prisma Studio to inspect)

---

### Step 5: Configure Facebook Webhook

After you have your Vercel domain:

1. Go to [Facebook Developers](https://developers.facebook.com/apps/)
2. Select your app (ID: **802438925861067**)
3. Go to **Messenger** → **Webhooks**
4. Click **"Edit"** on your webhook
5. Update **Callback URL** to:
   ```
   https://your-actual-vercel-domain.vercel.app/api/webhooks/facebook
   ```
6. Set **Verify Token** to match your `FACEBOOK_WEBHOOK_VERIFY_TOKEN` from Vercel
7. Subscribe to these events:
   - ✅ `messages`
   - ✅ `messaging_postbacks`
   - ✅ `message_deliveries`
   - ✅ `message_reads`
8. Click **"Verify and Save"**

---

### Step 6: Update Facebook OAuth Redirect URIs

1. In Facebook Developers, go to **Facebook Login** → **Settings**
2. Under **Valid OAuth Redirect URIs**, add:
   ```
   https://your-actual-vercel-domain.vercel.app/api/facebook/callback
   https://your-actual-vercel-domain.vercel.app/api/facebook/callback-popup
   ```
3. Click **"Save Changes"**

---

### Step 7: Generate and Set Facebook Webhook Verify Token

If you haven't set a secure token yet:

1. Generate a secure token:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. Update in **Vercel** → **Environment Variables**:
   - `FACEBOOK_WEBHOOK_VERIFY_TOKEN` = (the generated token)

3. Update in **Facebook App** → **Webhooks**:
   - **Verify Token** = (the same generated token)

---

## ✅ Testing Checklist

After completing all steps, test:

- [ ] **Homepage loads**: Visit your Vercel URL
- [ ] **Login works**: Try logging in
- [ ] **Registration works**: Create a new account
- [ ] **Facebook connection**: Go to Settings → Integrations → Connect Facebook
- [ ] **Webhook receives events**: Send a test message to your Facebook page
- [ ] **Database connection**: Check Vercel logs for any database errors
- [ ] **Redis connection**: If using campaigns, verify Redis is connected

---

## 🐛 Troubleshooting

### Build Fails

**Check Vercel Build Logs:**
1. Go to Vercel Dashboard → Your Project → **Deployments**
2. Click on the failed deployment
3. Check the **Build Logs** tab
4. Look for error messages

**Common Issues:**
- Missing environment variables → Add them in Vercel Dashboard
- Database connection error → Verify `DATABASE_URL` and `DIRECT_URL` are correct
- Prisma errors → Make sure `prisma generate` runs before build

### Database Migrations Fail

**Solution:**
1. Check Supabase database is accessible
2. Verify `DIRECT_URL` is correct (port 5432, not 6543)
3. Try running migrations via Supabase SQL Editor manually

### Facebook Webhook Not Working

**Solution:**
1. Verify webhook URL is accessible (no 404)
2. Check `FACEBOOK_WEBHOOK_VERIFY_TOKEN` matches in both places
3. Ensure webhook is subscribed to correct events
4. Check Vercel function logs for webhook errors

### NextAuth Errors

**Solution:**
1. Verify `NEXTAUTH_URL` matches your Vercel domain exactly
2. Check `NEXTAUTH_SECRET` is set
3. Clear browser cookies and try again

---

## 📊 Quick Status Check

Run these commands to verify everything:

```bash
# Check if Vercel CLI is installed
vercel --version

# Check deployment status
vercel ls

# View logs
vercel logs

# Check environment variables (after linking)
vercel env ls
```

---

## 🎉 You're Done When:

- ✅ Project deployed to Vercel
- ✅ Environment variables updated with Vercel domain
- ✅ Database migrations completed
- ✅ Facebook webhook configured
- ✅ Facebook OAuth redirect URIs updated
- ✅ All tests pass

---

**Next:** Once everything is working, you can start using your application! 🚀









