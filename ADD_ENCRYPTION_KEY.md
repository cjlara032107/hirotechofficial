# 🔒 Add ENCRYPTION_KEY to Vercel

## ⚠️ Error Fixed: Missing ENCRYPTION_KEY

You're seeing this error because the `ENCRYPTION_KEY` environment variable is missing on Vercel.

## ✅ Solution: Add ENCRYPTION_KEY to Vercel

### Option 1: Via Vercel Dashboard (Recommended)

1. **Go to Vercel Dashboard:**
   - Visit: https://vercel.com/dashboard
   - Select your project: `hirotechofficial-beta`

2. **Navigate to Environment Variables:**
   - Click **Settings** → **Environment Variables**

3. **Add the Key:**
   - **Key:** `ENCRYPTION_KEY`
   - **Value:** `f902ad293f5f9af42c98b007dfdc0eede8614ac2be7a985c23347e051f3bcf81`
   - **Environment:** Select all:
     - ✅ Production
     - ✅ Preview
     - ✅ Development

4. **Save and Redeploy:**
   - Click **Save**
   - Go to **Deployments** tab
   - Click **⋯** (three dots) on latest deployment
   - Click **Redeploy**

### Option 2: Via Vercel CLI

```bash
# Add to production
vercel env add ENCRYPTION_KEY production

# When prompted, paste:
f902ad293f5f9af42c98b007dfdc0eede8614ac2be7a985c23347e051f3bcf81

# Add to preview
vercel env add ENCRYPTION_KEY preview

# Add to development
vercel env add ENCRYPTION_KEY development

# Redeploy
vercel --prod
```

## 🔐 What is ENCRYPTION_KEY?

- **Purpose:** Encrypts API keys stored in the database
- **Format:** 64 hex characters (32 bytes)
- **Security:** Keep this key secret! Never commit it to git.

## ✅ After Adding the Key

1. **Redeploy your application** (required for env vars to take effect)
2. **Test API key creation** - The error should be gone
3. **Verify** - Try adding an API key in `/settings/api-keys`

## 🔄 Generate a New Key (if needed)

If you need to generate a new encryption key:

```bash
npx tsx scripts/generate-encryption-key.ts
```

Then update the `ENCRYPTION_KEY` in Vercel with the new value.

**⚠️ Warning:** Changing the encryption key will make all existing encrypted API keys unreadable! Only do this if you're starting fresh.

---

## 📋 Quick Checklist

- [ ] Added `ENCRYPTION_KEY` to Vercel environment variables
- [ ] Enabled for Production, Preview, and Development
- [ ] Redeployed the application
- [ ] Tested adding an API key
- [ ] Verified no more encryption errors

---

**Status:** Ready to add to Vercel ✅







