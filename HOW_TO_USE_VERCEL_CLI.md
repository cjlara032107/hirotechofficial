# 🚀 How to Use Vercel CLI - Complete Guide

## Step 1: Install Vercel CLI

```bash
npm install -g vercel
```

This installs Vercel CLI globally on your system.

---

## Step 2: Login to Vercel

```bash
vercel login
```

This will:
- Open your browser
- Ask you to authenticate with GitHub (or email)
- Link your local CLI to your Vercel account

**Alternative (non-interactive):**
```bash
vercel login --github
```

---

## Step 3: Navigate to Your Project

```bash
cd "C:\Users\bigcl\Downloads\HIRO V1.2"
```

Make sure you're in your project root directory.

---

## Step 4: Link to Your Vercel Project (First Time Only)

If this is your first time using CLI with this project:

```bash
vercel link
```

You'll be asked:
- **Set up and deploy?** → Type `Y` (Yes)
- **Which scope?** → Select your account (usually just press Enter)
- **Link to existing project?** → Type `Y` (Yes)
- **What's the name of your project?** → Type `hirotechofficial-beta` (or your project name)
- **In which directory is your code located?** → Press Enter (default `./`)

---

## Step 5: Deploy

### For Production Deployment:

```bash
vercel --prod
```

### For Preview Deployment (Test First):

```bash
vercel
```

This creates a preview URL for testing before going to production.

---

## Step 6: View Deployment Status

After running the deploy command, you'll see:

```
🔍  Inspect: https://vercel.com/your-project/...
✅  Production: https://hirotechofficial-beta.vercel.app
```

---

## Useful Vercel CLI Commands

### View All Deployments

```bash
vercel ls
```

Shows all your deployments with their status.

### View Deployment Logs

```bash
vercel logs
```

Shows real-time logs from your deployment.

### View Environment Variables

```bash
vercel env ls
```

Lists all environment variables for your project.

### Pull Environment Variables Locally

```bash
vercel env pull .env.production
```

Downloads your Vercel environment variables to a local file.

### Remove/Unlink Project

```bash
vercel unlink
```

Removes the link between local directory and Vercel project.

### View Project Info

```bash
vercel inspect
```

Shows detailed information about your latest deployment.

---

## Quick Deploy Workflow

**For quick production deployment:**

```bash
# 1. Make sure you're in project directory
cd "C:\Users\bigcl\Downloads\HIRO V1.2"

# 2. Deploy to production
vercel --prod
```

That's it! Vercel will:
- Build your project
- Deploy it
- Give you a URL

---

## Troubleshooting

### "Command not found: vercel"

**Solution:** Make sure Vercel CLI is installed:
```bash
npm install -g vercel
```

### "Not authenticated"

**Solution:** Login again:
```bash
vercel login
```

### "Project not found"

**Solution:** Link your project:
```bash
vercel link
```

### Build Fails

**Check logs:**
```bash
vercel logs
```

**Common issues:**
- Missing environment variables → Add them in Vercel Dashboard
- Build errors → Check your code
- Database connection → Verify `DATABASE_URL` is set

---

## Example: Full Deployment Process

```bash
# 1. Install CLI (one time)
npm install -g vercel

# 2. Login (one time)
vercel login

# 3. Go to project
cd "C:\Users\bigcl\Downloads\HIRO V1.2"

# 4. Link project (first time only)
vercel link

# 5. Deploy to production
vercel --prod
```

---

## Pro Tips

1. **Use `vercel` (without --prod) first** to test in preview
2. **Check logs** if deployment fails: `vercel logs`
3. **Environment variables** are managed in Vercel Dashboard, not CLI
4. **Auto-deploy** happens when you push to GitHub (if connected)
5. **CLI is great** for manual deployments and debugging

---

**Ready to deploy?** Run these commands! 🚀






