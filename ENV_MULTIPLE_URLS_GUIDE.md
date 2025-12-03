# 📝 Multiple URLs in .env.local Guide

## ✅ Yes, You Can Have Both!

You can include both ngrok and Vercel URLs in your `.env.local` file, but **only one will be active at a time**.

---

## 🎯 Best Practice: Use Comments

### Recommended Structure

```env
# ============================================
# LOCAL DEVELOPMENT (Currently Active)
# ============================================
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXTAUTH_URL=http://localhost:3000

# ============================================
# NGROK TUNNEL (Comment out when not using)
# ============================================
# NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev
# NEXTAUTH_URL=https://abc123.ngrok-free.dev

# ============================================
# VERCEL PRODUCTION (Comment out when not using)
# ============================================
# NEXT_PUBLIC_APP_URL=https://your-project.vercel.app
# NEXTAUTH_URL=https://your-project.vercel.app
```

**How it works:**
- ✅ The **last uncommented** value wins
- ✅ Comment out the ones you're not using
- ✅ Easy to switch between environments

---

## 🔄 Switching Between Environments

### Scenario 1: Local Development (No Ngrok)

```env
# Active
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXTAUTH_URL=http://localhost:3000

# Commented out
# NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev
# NEXTAUTH_URL=https://abc123.ngrok-free.dev
```

### Scenario 2: Testing with Ngrok

```env
# Commented out
# NEXT_PUBLIC_APP_URL=http://localhost:3000
# NEXTAUTH_URL=http://localhost:3000

# Active
NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev
NEXTAUTH_URL=https://abc123.ngrok-free.dev
```

### Scenario 3: Production (Vercel)

```env
# Commented out
# NEXT_PUBLIC_APP_URL=http://localhost:3000
# NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev

# Active
NEXT_PUBLIC_APP_URL=https://your-project.vercel.app
NEXTAUTH_URL=https://your-project.vercel.app
```

---

## ⚠️ Important Notes

### 1. Only One Active Value

**❌ DON'T DO THIS:**
```env
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev  # This overwrites the first one!
```

**✅ DO THIS:**
```env
# Comment out the one you're not using
# NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev
```

### 2. Environment Variable Precedence

Next.js loads environment variables in this order (last one wins):
1. `.env` (lowest priority)
2. `.env.local` (highest priority - overrides all)
3. System environment variables (if set)

### 3. Restart Required

After changing environment variables:
1. ✅ Stop your dev server (`Ctrl+C`)
2. ✅ Start it again (`npm run dev`)
3. ✅ Changes take effect immediately

---

## 🎯 When to Use Which URL

### Use `http://localhost:3000` When:
- ✅ Developing locally
- ✅ Not testing Facebook webhooks
- ✅ Not testing OAuth callbacks
- ✅ Just working on UI/features

### Use Ngrok URL When:
- ✅ Testing Facebook webhooks
- ✅ Testing Facebook OAuth
- ✅ Need public URL for external services
- ✅ Testing on mobile devices

### Use Vercel URL When:
- ✅ Deployed to production
- ✅ Testing production environment
- ✅ Production webhooks/OAuth

---

## 🔧 Quick Switch Script

Create a helper script to switch between environments:

### `switch-env.bat` (Windows)

```batch
@echo off
echo Switching environment...
echo.
echo 1. Local (localhost:3000)
echo 2. Ngrok
echo 3. Vercel
echo.
set /p choice="Select (1-3): "

if "%choice%"=="1" (
    echo Setting to localhost...
    powershell -Command "(Get-Content .env.local) -replace '^NEXT_PUBLIC_APP_URL=.*', 'NEXT_PUBLIC_APP_URL=http://localhost:3000' | Set-Content .env.local"
    powershell -Command "(Get-Content .env.local) -replace '^NEXTAUTH_URL=.*', 'NEXTAUTH_URL=http://localhost:3000' | Set-Content .env.local"
    echo ✅ Switched to localhost
) else if "%choice%"=="2" (
    set /p ngrok_url="Enter ngrok URL: "
    powershell -Command "(Get-Content .env.local) -replace '^NEXT_PUBLIC_APP_URL=.*', 'NEXT_PUBLIC_APP_URL=%ngrok_url%' | Set-Content .env.local"
    powershell -Command "(Get-Content .env.local) -replace '^NEXTAUTH_URL=.*', 'NEXTAUTH_URL=%ngrok_url%' | Set-Content .env.local"
    echo ✅ Switched to ngrok
) else if "%choice%"=="3" (
    set /p vercel_url="Enter Vercel URL: "
    powershell -Command "(Get-Content .env.local) -replace '^NEXT_PUBLIC_APP_URL=.*', 'NEXT_PUBLIC_APP_URL=%vercel_url%' | Set-Content .env.local"
    powershell -Command "(Get-Content .env.local) -replace '^NEXTAUTH_URL=.*', 'NEXTAUTH_URL=%vercel_url%' | Set-Content .env.local"
    echo ✅ Switched to Vercel
)

echo.
echo ⚠️  Restart your dev server for changes to take effect!
pause
```

---

## 📋 Complete Example

Here's a complete `.env.local` example with all options:

```env
# ============================================
# APPLICATION URLs
# ============================================
# Uncomment the one you want to use:

# Option 1: Local Development
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXTAUTH_URL=http://localhost:3000

# Option 2: Ngrok (for Facebook testing)
# NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev
# NEXTAUTH_URL=https://abc123.ngrok-free.dev

# Option 3: Vercel Production
# NEXT_PUBLIC_APP_URL=https://your-project.vercel.app
# NEXTAUTH_URL=https://your-project.vercel.app

# ============================================
# DATABASE
# ============================================
DATABASE_URL=postgresql://...
DIRECT_URL=postgresql://...

# ============================================
# AUTH
# ============================================
NEXTAUTH_SECRET=your-secret
AUTH_SECRET=your-secret

# ============================================
# SUPABASE
# ============================================
NEXT_PUBLIC_SUPABASE_URL=https://...
NEXT_PUBLIC_SUPABASE_ANON_KEY=...

# ============================================
# FACEBOOK
# ============================================
FACEBOOK_APP_ID=...
FACEBOOK_APP_SECRET=...
FACEBOOK_WEBHOOK_VERIFY_TOKEN=...

# ============================================
# REDIS (Optional)
# ============================================
REDIS_URL=redis://...

# ============================================
# ENVIRONMENT
# ============================================
NODE_ENV=development
```

---

## ✅ Summary

**Can you have both?** ✅ **YES!**

**How?** 
- ✅ Use comments to keep both URLs
- ✅ Only uncomment the one you're using
- ✅ Last uncommented value wins
- ✅ Restart dev server after changes

**Best Practice:**
- Keep all options in the file (commented)
- Switch by commenting/uncommenting
- Add clear comments explaining each option
- Document which one is currently active

---

## 🚀 Quick Reference

```env
# Switch to localhost
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXTAUTH_URL=http://localhost:3000

# Switch to ngrok (uncomment, comment localhost)
# NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_APP_URL=https://your-ngrok-url.ngrok-free.dev
NEXTAUTH_URL=https://your-ngrok-url.ngrok-free.dev

# Switch to Vercel (uncomment, comment others)
# NEXT_PUBLIC_APP_URL=http://localhost:3000
# NEXT_PUBLIC_APP_URL=https://your-ngrok-url.ngrok-free.dev
NEXT_PUBLIC_APP_URL=https://your-project.vercel.app
NEXTAUTH_URL=https://your-project.vercel.app
```

---

**That's it!** You can keep all URLs in your `.env.local` file and easily switch between them! 🎉









