# 🔧 Update Vercel Environment Variables with Your Domain

## Your Vercel Domain
**Domain:** `https://hirotechofficial-beta.vercel.app`

---

## Step 1: Update Environment Variables in Vercel

Go to your Vercel Dashboard and update these two variables:

### In Vercel Dashboard:
1. Go to: https://vercel.com/dashboard
2. Click on your project: **hirotechofficial-beta**
3. Go to **Settings** → **Environment Variables**
4. Find and update these two variables:

**Update `NEXT_PUBLIC_APP_URL`:**
- Current value: (whatever it is now)
- New value: `https://hirotechofficial-beta.vercel.app`
- Click **Save**

**Update `NEXTAUTH_URL`:**
- Current value: (whatever it is now)
- New value: `https://hirotechofficial-beta.vercel.app`
- Click **Save**

### After Updating:
- Vercel will automatically redeploy, OR
- Go to **Deployments** tab → Click **"Redeploy"** → Select latest deployment → **"Redeploy"**

---

## Step 2: Verify All Environment Variables Are Set

Make sure these are all set in Vercel:

✅ `NEXT_PUBLIC_APP_URL` = `https://hirotechofficial-beta.vercel.app`
✅ `NEXTAUTH_URL` = `https://hirotechofficial-beta.vercel.app`
✅ `AUTH_SECRET` = `35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK`
✅ `NEXTAUTH_SECRET` = `"35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK="`
✅ `DATABASE_URL` = (your Supabase connection string)
✅ `DIRECT_URL` = (your Supabase direct connection)
✅ `NEXT_PUBLIC_SUPABASE_URL` = `https://qudsmrrfbatasnyvuxch.supabase.co`
✅ `NEXT_PUBLIC_SUPABASE_ANON_KEY` = (your anon key)
✅ `FACEBOOK_APP_ID` = `802438925861067`
✅ `FACEBOOK_APP_SECRET` = `99e11ff061cd03fa9348547f754f96b9`
✅ `FACEBOOK_WEBHOOK_VERIFY_TOKEN` = (your webhook token)
✅ `REDIS_URL` = (your Redis connection string)
✅ `NODE_ENV` = `production`

---

## Step 3: Next Actions After Updating URLs

After you update the environment variables and redeploy:

1. ✅ **Run Database Migrations** (see below)
2. ✅ **Configure Facebook Webhook** (see below)
3. ✅ **Update Facebook OAuth Redirect URIs** (see below)
4. ✅ **Test Your Application**

---

## Step 4: Run Database Migrations

You need to set up your database schema. Here are your options:

### Option A: Add to Build Command (Recommended)

1. In Vercel Dashboard → **Settings** → **General** → **Build & Development Settings**
2. Find **Build Command**
3. Change it to:
   ```
   npm run vercel-build
   ```
4. First, update your `package.json` (I'll help with this)

### Option B: Run Migrations via Vercel CLI

```bash
# Install Vercel CLI (if not installed)
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

---

## Step 5: Configure Facebook Webhook

1. Go to [Facebook Developers](https://developers.facebook.com/apps/)
2. Select your app (ID: **802438925861067**)
3. Go to **Messenger** → **Webhooks**
4. Update **Callback URL** to:
   ```
   https://hirotechofficial-beta.vercel.app/api/webhooks/facebook
   ```
5. Set **Verify Token** to match your `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
6. Subscribe to events:
   - ✅ `messages`
   - ✅ `messaging_postbacks`
   - ✅ `message_deliveries`
   - ✅ `message_reads`
7. Click **"Verify and Save"**

---

## Step 6: Update Facebook OAuth Redirect URIs

1. In Facebook Developers, go to **Facebook Login** → **Settings**
2. Under **Valid OAuth Redirect URIs**, add:
   ```
   https://hirotechofficial-beta.vercel.app/api/facebook/callback
   https://hirotechofficial-beta.vercel.app/api/facebook/callback-popup
   ```
3. Click **"Save Changes"**

---

## ✅ Testing Checklist

After completing all steps:

- [ ] Visit `https://hirotechofficial-beta.vercel.app` - homepage loads
- [ ] Try logging in - authentication works
- [ ] Try registering - new account creation works
- [ ] Go to Settings → Integrations → Connect Facebook - OAuth works
- [ ] Send a test message to your Facebook page - webhook receives it
- [ ] Check Vercel logs - no errors

---

**Your Domain:** `https://hirotechofficial-beta.vercel.app` 🚀







