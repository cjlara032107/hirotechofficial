# 📋 Facebook App Settings Update Guide

## Your Ngrok URL

```
https://unglamourous-unaccustomedly-audra.ngrok-free.dev
```

---

## 🔵 Step-by-Step: Update Facebook App

### Step 1: Go to Facebook Developers

1. Open: https://developers.facebook.com/apps/
2. **Log in** with your Facebook account
3. **Select your app** (or create a new one)

---

### Step 2: Update OAuth Redirect URIs

1. In your Facebook App dashboard, go to:
   - **Products** → **Facebook Login** → **Settings**
   - OR: **Settings** → **Basic** → Scroll to **Facebook Login Settings**

2. Find **"Valid OAuth Redirect URIs"** section

3. **Add these two URLs** (one per line):
   ```
   https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback
   https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback-popup
   ```

4. **Click "Save Changes"**

---

### Step 3: Update Webhook URL

1. In your Facebook App dashboard, go to:
   - **Products** → **Messenger** → **Webhooks**
   - OR: **Settings** → **Webhooks**

2. **Click "Edit"** on your existing webhook (or "Add Webhook" if none exists)

3. **Update Callback URL** to:
   ```
   https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/webhooks/facebook
   ```

4. **Set Verify Token** to match your `.env.local`:
   - Check your `.env.local` for `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
   - Enter the same value in Facebook

5. **Subscribe to these events:**
   - ✅ `messages`
   - ✅ `messaging_postbacks`
   - ✅ `message_deliveries`
   - ✅ `message_reads`
   - ✅ `messaging_optins` (optional)
   - ✅ `messaging_referrals` (optional)

6. **Click "Verify and Save"**

   - Facebook will send a GET request to verify the webhook
   - Your server should respond with the challenge token
   - If verification fails, check your webhook endpoint is accessible

---

## ✅ Verification Checklist

After updating, verify:

- [ ] OAuth Redirect URIs added (both callback URLs)
- [ ] Webhook URL updated
- [ ] Verify Token matches `.env.local`
- [ ] Webhook events subscribed
- [ ] Webhook verified (green checkmark)
- [ ] Dev server is running
- [ ] Ngrok is running

---

## 🧪 Test Your Setup

### Test OAuth:

1. Visit: `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/login`
2. Click "Login with Facebook"
3. Should redirect to Facebook
4. After authorization, should redirect back to your app

### Test Webhook:

1. Send a message to your Facebook Page
2. Check ngrok dashboard: `http://localhost:4040`
3. Should see incoming webhook requests
4. Check your dev server logs for webhook processing

---

## ⚠️ Common Issues

### "Invalid OAuth Redirect URI"

**Fix:**
- ✅ Ensure URL matches exactly (no trailing slash)
- ✅ Use HTTPS (not HTTP)
- ✅ URL is added in Facebook App settings
- ✅ Wait a few minutes for changes to propagate

### "Webhook Verification Failed"

**Fix:**
- ✅ Check webhook URL is accessible
- ✅ Verify token matches exactly
- ✅ Ensure dev server is running
- ✅ Check ngrok is running
- ✅ Check webhook endpoint returns challenge correctly

### "Redirect URI Mismatch"

**Fix:**
- ✅ Update `NEXT_PUBLIC_APP_URL` in `.env.local`
- ✅ Restart dev server
- ✅ Clear browser cookies
- ✅ Try in incognito window

---

## 📊 Quick Reference

**Your URLs:**
- **App:** `https://unglamourous-unaccustomedly-audra.ngrok-free.dev`
- **OAuth Callback:** `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback`
- **OAuth Popup:** `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback-popup`
- **Webhook:** `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/webhooks/facebook`

**Facebook Developer Console:**
- https://developers.facebook.com/apps/

**Ngrok Dashboard:**
- http://localhost:4040

---

## 🎯 Summary

**What to Update in Facebook:**

1. ✅ **OAuth Redirect URIs** (2 URLs)
2. ✅ **Webhook Callback URL** (1 URL)
3. ✅ **Verify Token** (match `.env.local`)
4. ✅ **Subscribe to Events** (check the boxes)

**After Updating:**
1. ✅ Restart dev server
2. ✅ Test OAuth login
3. ✅ Test webhook (send a message)

---

**Status:** Ready to update Facebook settings! 🚀









