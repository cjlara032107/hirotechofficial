# 🚀 Ngrok Setup Guide

Complete guide to setting up and using ngrok for local development with Facebook webhooks and OAuth.

---

## 📋 Quick Start

### 1. Start Ngrok (Easiest Method)

```bash
npm run ngrok:start
```

This will:
- ✅ Check if ngrok is already running
- ✅ Start ngrok tunnel on port 3000
- ✅ Display your public URL
- ✅ Show instructions for next steps

### 2. Start Dev Server + Ngrok Together

```bash
npm run dev:with-ngrok
```

This starts both Next.js dev server and ngrok in parallel.

### 3. Stop Ngrok

```bash
npm run ngrok:stop
```

Or manually:
```bash
taskkill /F /IM ngrok.exe
```

---

## 🔧 Manual Setup

### Option 1: Using the Script (Recommended)

```bash
# Start ngrok
npm run ngrok:start

# In another terminal, start dev server
npm run dev
```

### Option 2: Direct Command

```bash
# Start ngrok directly
./ngrok.exe http 3000

# Or if ngrok is in PATH
ngrok http 3000
```

---

## 📝 Configuration Steps

### Step 1: Get Your Ngrok URL

After starting ngrok, you'll see output like:

```
Forwarding  https://abc123.ngrok-free.dev -> http://localhost:3000
```

**Copy the HTTPS URL** (the one starting with `https://`)

### Step 2: Update Environment Variables

Open `.env.local` and add/update:

```env
# Your ngrok URL (no trailing slash!)
NEXT_PUBLIC_APP_URL=https://abc123.ngrok-free.dev
NEXTAUTH_URL=https://abc123.ngrok-free.dev
```

**Important:** 
- ✅ Use HTTPS URL (not HTTP)
- ✅ No trailing slash at the end
- ✅ Update this every time ngrok URL changes

### Step 3: Restart Dev Server

After updating `.env.local`:

```bash
# Stop current server (Ctrl+C)
# Then restart:
npm run dev
```

### Step 4: Update Facebook App Settings

#### A. OAuth Redirect URIs

1. Go to [Facebook Developers](https://developers.facebook.com/apps/)
2. Select your app
3. Go to **Facebook Login** → **Settings**
4. Under **Valid OAuth Redirect URIs**, add:
   ```
   https://abc123.ngrok-free.dev/api/facebook/callback
   https://abc123.ngrok-free.dev/api/facebook/callback-popup
   ```
5. Click **Save Changes**

#### B. Webhook URL

1. In Facebook App, go to **Messenger** → **Webhooks**
2. Click **Edit** on your webhook
3. Update **Callback URL** to:
   ```
   https://abc123.ngrok-free.dev/api/webhooks/facebook
   ```
4. Set **Verify Token** to match your `.env.local`:
   ```env
   FACEBOOK_WEBHOOK_VERIFY_TOKEN=your-secret-token-here
   ```
5. Subscribe to events:
   - ✅ `messages`
   - ✅ `messaging_postbacks`
   - ✅ `message_deliveries`
   - ✅ `message_reads`
6. Click **Verify and Save**

### Step 5: Clear Browser Cookies

Since you're switching domains, clear cookies:

**Method 1: DevTools (Recommended)**
1. Open DevTools (`F12`)
2. Go to **Application** tab
3. Expand **Cookies** in sidebar
4. Right-click on old domain → **Clear**
5. Refresh page

**Method 2: Incognito Window**
- Press `Ctrl+Shift+N` (Chrome) or `Ctrl+Shift+P` (Firefox)
- Navigate to your ngrok URL

---

## 🎯 What Ngrok Does

Ngrok creates a **public HTTPS URL** that tunnels to your local server:

```
Internet → https://abc123.ngrok-free.dev → ngrok → http://localhost:3000
```

This allows:
- ✅ Facebook webhooks to reach your local server
- ✅ Facebook OAuth callbacks to work locally
- ✅ Testing on mobile devices
- ✅ Sharing your local app with others

---

## ⚠️ Important Notes

### Ngrok URL Changes

**Free ngrok accounts** get a new URL every time you restart ngrok.

**If URL changes:**
1. Update `.env.local` with new URL
2. Update Facebook OAuth redirect URIs
3. Update Facebook webhook URL
4. Restart dev server
5. Clear browser cookies

### Keep Ngrok Running

- ✅ Keep the ngrok terminal/process running
- ✅ Don't close it while testing
- ✅ If it stops, restart it and update URLs

### Ngrok Dashboard

View tunnel stats at:
```
http://localhost:4040
```

This shows:
- Request/response logs
- Public URL
- Tunnel status

---

## 🔍 Troubleshooting

### Problem: "Ngrok is already running"

**Solution:**
```bash
npm run ngrok:stop
# Then start again
npm run ngrok:start
```

### Problem: "Port 3000 already in use"

**Solution:**
1. Stop your dev server
2. Or use a different port:
   ```bash
   # Start dev server on different port
   PORT=3001 npm run dev
   
   # Start ngrok on that port
   ./ngrok.exe http 3001
   ```

### Problem: "Facebook webhook verification fails"

**Check:**
1. ✅ Ngrok is running
2. ✅ `.env.local` has correct `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
3. ✅ Facebook webhook URL matches your ngrok URL
4. ✅ Verify token in Facebook matches `.env.local`
5. ✅ Dev server is running on port 3000

### Problem: "OAuth redirect fails"

**Check:**
1. ✅ `NEXT_PUBLIC_APP_URL` in `.env.local` matches ngrok URL
2. ✅ Facebook OAuth redirect URI matches exactly
3. ✅ No trailing slash in URLs
4. ✅ Using HTTPS URL (not HTTP)
5. ✅ Cleared browser cookies

### Problem: "Can't access ngrok URL"

**Check:**
1. ✅ Ngrok is running (check `http://localhost:4040`)
2. ✅ Dev server is running on port 3000
3. ✅ Firewall isn't blocking ngrok
4. ✅ Internet connection is active

---

## 📊 Ngrok Account Types

### Free Account
- ✅ New URL each restart
- ✅ Limited bandwidth
- ✅ Good for development

### Paid Account
- ✅ Static domain (URL doesn't change)
- ✅ More bandwidth
- ✅ Better for production testing

**To get static domain:**
1. Sign up at [ngrok.com](https://ngrok.com)
2. Get authtoken
3. Configure: `ngrok config add-authtoken YOUR_TOKEN`
4. Use reserved domain: `ngrok http 3000 --domain=your-domain.ngrok.io`

---

## 🎯 Quick Reference

### Commands

```bash
# Start ngrok
npm run ngrok:start

# Stop ngrok
npm run ngrok:stop

# Start dev + ngrok together
npm run dev:with-ngrok

# Check ngrok status
curl http://localhost:4040/api/tunnels
```

### URLs to Update

1. **`.env.local`:**
   ```env
   NEXT_PUBLIC_APP_URL=https://your-url.ngrok-free.dev
   NEXTAUTH_URL=https://your-url.ngrok-free.dev
   ```

2. **Facebook OAuth:**
   - `https://your-url.ngrok-free.dev/api/facebook/callback`
   - `https://your-url.ngrok-free.dev/api/facebook/callback-popup`

3. **Facebook Webhook:**
   - `https://your-url.ngrok-free.dev/api/webhooks/facebook`

---

## ✅ Checklist

Before testing Facebook integration:

- [ ] Ngrok is running (`npm run ngrok:start`)
- [ ] Dev server is running (`npm run dev`)
- [ ] `.env.local` has correct `NEXT_PUBLIC_APP_URL`
- [ ] `.env.local` has correct `NEXTAUTH_URL`
- [ ] Facebook OAuth redirect URIs updated
- [ ] Facebook webhook URL updated
- [ ] Facebook webhook verify token matches `.env.local`
- [ ] Browser cookies cleared
- [ ] Tested login at ngrok URL

---

## 🚀 Next Steps

After ngrok is set up:

1. **Test OAuth:**
   - Visit: `https://your-ngrok-url.ngrok-free.dev/login`
   - Try Facebook login

2. **Test Webhooks:**
   - Send a message to your Facebook page
   - Check if webhook receives it

3. **Monitor:**
   - Watch ngrok dashboard: `http://localhost:4040`
   - Check dev server logs
   - Check browser console

---

**Status:** ✅ Ready to use!

**Created:** December 2024  
**Last Updated:** December 2024









