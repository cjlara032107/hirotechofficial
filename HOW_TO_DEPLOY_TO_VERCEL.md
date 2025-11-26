# 🚀 How to Deploy to Vercel - Step by Step

## Method 1: Via Vercel Dashboard (Easiest - Recommended)

### Step 1: Push Your Code to GitHub

Make sure your code is pushed to GitHub:

```bash
# Check current status
git status

# If you have uncommitted changes, commit them
git add .
git commit -m "Ready for Vercel deployment"
git push origin main
```

### Step 2: Go to Vercel Dashboard

1. Open your browser and go to: **https://vercel.com/**
2. Click **"Sign Up"** or **"Log In"** (use GitHub to sign in)
3. After logging in, you'll see your dashboard

### Step 3: Import Your Project

1. Click the **"Add New"** button (top right)
2. Select **"Project"**
3. You'll see a list of your GitHub repositories
4. Find and click on **`cjlara032107/hirotechofficial`**
5. Click **"Import"**

### Step 4: Configure Project Settings

Vercel will auto-detect Next.js, but verify these settings:

**Project Name:**
- Keep default or change to something like `hiro-app`

**Framework Preset:**
- Should be: **Next.js** ✅

**Root Directory:**
- Leave as **`./`** (default)

**Build and Output Settings:**
- **Build Command:** `npm run build` (default)
- **Output Directory:** `.next` (default)
- **Install Command:** `npm install` (default)

**Environment Variables:**
- ✅ You've already set these up! They should appear automatically
- If not, you can add them here or add them later in Settings

### Step 5: Deploy!

1. Click the **"Deploy"** button
2. Wait for the build to complete (usually 2-5 minutes)
3. You'll see build logs in real-time
4. Once complete, you'll get a URL like: `https://your-project-name.vercel.app`

### Step 6: Get Your Deployment URL

After deployment:
- Copy your deployment URL
- It will look like: `https://hiro-app-xyz123.vercel.app`
- **Save this URL** - you'll need it for the next steps!

---

## Method 2: Via Vercel CLI (Advanced)

### Step 1: Install Vercel CLI

```bash
npm install -g vercel
```

### Step 2: Login to Vercel

```bash
vercel login
```

This will open a browser window for you to authenticate with GitHub.

### Step 3: Navigate to Your Project

```bash
cd "C:\Users\bigcl\Downloads\HIRO V1.2"
```

### Step 4: Deploy

**For preview deployment (test first):**
```bash
vercel
```

**For production deployment:**
```bash
vercel --prod
```

The CLI will ask you some questions:
- **Set up and deploy?** → Yes
- **Which scope?** → Select your account
- **Link to existing project?** → No (first time) or Yes (if redeploying)
- **Project name?** → Press Enter for default or type a name
- **Directory?** → Press Enter for `./`
- **Override settings?** → No

### Step 5: Wait for Deployment

The CLI will show build progress. Once done, you'll get a URL.

---

## ✅ After Deployment

### 1. Update Environment Variables with Your Vercel Domain

Go to **Vercel Dashboard** → Your Project → **Settings** → **Environment Variables**

Update these two variables:
- `NEXT_PUBLIC_APP_URL` = `https://your-actual-vercel-domain.vercel.app`
- `NEXTAUTH_URL` = `https://your-actual-vercel-domain.vercel.app`

Then **redeploy** (or wait for auto-deploy if Git is connected).

### 2. Check Build Logs

If deployment fails:
1. Go to **Deployments** tab
2. Click on the failed deployment
3. Check **Build Logs** for errors
4. Common issues:
   - Missing environment variables
   - Database connection errors
   - Build errors

### 3. Test Your Deployment

Visit your Vercel URL and test:
- ✅ Homepage loads
- ✅ Login page works
- ✅ No console errors

---

## 🔧 Troubleshooting

### Build Fails: "Environment variable not found"

**Solution:**
1. Go to Vercel Dashboard → Settings → Environment Variables
2. Make sure ALL required variables are added
3. Check they're set for **Production**, **Preview**, and **Development**

### Build Fails: Database Connection Error

**Solution:**
1. Verify `DATABASE_URL` and `DIRECT_URL` are correct
2. Check Supabase database is running
3. Test connection locally first

### Build Fails: Prisma Errors

**Solution:**
1. Add to `package.json`:
   ```json
   {
     "scripts": {
       "vercel-build": "prisma generate && prisma migrate deploy && next build"
     }
   }
   ```
2. In Vercel → Settings → Build & Development Settings
3. Set **Build Command** to: `npm run vercel-build`

### Deployment Succeeds But App Shows Errors

**Solution:**
1. Check Vercel Function Logs
2. Go to **Deployments** → Click deployment → **Function Logs**
3. Look for runtime errors
4. Verify environment variables are set correctly

---

## 📊 Quick Commands Reference

```bash
# Check Vercel CLI version
vercel --version

# List all deployments
vercel ls

# View deployment logs
vercel logs

# View environment variables
vercel env ls

# Pull environment variables locally
vercel env pull .env.production
```

---

## 🎯 Recommended Workflow

1. ✅ **Deploy via Dashboard** (easiest for first time)
2. ✅ **Get your Vercel domain**
3. ✅ **Update environment variables** with your domain
4. ✅ **Redeploy** (automatic if Git connected, or manual)
5. ✅ **Run database migrations**
6. ✅ **Configure Facebook webhook** with your domain
7. ✅ **Test everything**

---

**Ready to deploy?** Start with Method 1 (Dashboard) - it's the easiest! 🚀






