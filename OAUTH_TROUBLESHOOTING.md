# 🔧 Facebook OAuth Troubleshooting Guide

## Current Configuration

**Ngrok URL**: `https://unglamourous-unaccustomedly-audra.ngrok-free.dev`

**Required OAuth Callback URLs** (must be added to Facebook App):
1. `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback`
2. `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback-popup`

---

## Common Errors & Solutions

### Error 1: "Redirect URI Mismatch"

**Error Message:**
```
This redirect failed because the redirect URI is not whitelisted in the app's Client OAuth Settings.
```

**Solution:**
1. Go to https://developers.facebook.com/apps/
2. Select your app → **Facebook Login** → **Settings**
3. Under **"Valid OAuth Redirect URIs"**, add BOTH URLs above
4. **IMPORTANT**: Copy-paste the URLs exactly (no trailing slashes, exact case)
5. Click **"Save Changes"**
6. Wait 10-30 seconds for changes to propagate
7. Clear browser cookies and try again

---

### Error 2: "Error validating verification code"

**Error Message:**
```
Facebook API Error (100): Error validating verification code. 
Please make sure your redirect_uri is identical to the one you used in the OAuth dialog request.
```

**Solution:**
This means the redirect URI used in the OAuth request doesn't match what's in Facebook settings.

1. Verify the URLs in Facebook settings match EXACTLY:
   - `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback`
   - `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback-popup`

2. Make sure your `.env.local` has:
   ```
   NEXT_PUBLIC_APP_URL=https://unglamourous-unaccustomedly-audra.ngrok-free.dev
   ```

3. **Restart your dev server** to load the new environment variables:
   ```bash
   # Stop current server (Ctrl+C)
   npm run dev
   ```

4. Clear browser cookies/cache

---

### Error 3: "Access Denied" or User Cancelled

**Error Message:**
```
error=access_denied
```

**Solution:**
- User clicked "Cancel" on Facebook login
- This is normal - just try again
- Make sure you're granting all required permissions

---

### Error 4: Dev Server Not Loading Environment Variables

**Symptoms:**
- OAuth URLs still show `localhost:3000` instead of ngrok URL
- Environment variables not updating

**Solution:**
1. Stop the dev server completely (Ctrl+C)
2. Verify `.env.local` has the correct values:
   ```bash
   npm run ngrok:update-env
   ```
3. Restart dev server:
   ```bash
   npm run dev
   ```
4. Check if variables are loaded:
   ```bash
   curl http://localhost:3000/api/debug/oauth-urls
   ```

---

## Step-by-Step Verification

### Step 1: Verify Environment Variables

Run:
```bash
npm run ngrok:url
node scripts/test-oauth-config.js
```

Should show:
- ✅ `NEXT_PUBLIC_APP_URL` set to ngrok URL
- ✅ `FACEBOOK_APP_ID` set
- ✅ `FACEBOOK_APP_SECRET` set

### Step 2: Verify Facebook App Settings

1. Go to https://developers.facebook.com/apps/
2. Select your app
3. Go to **Facebook Login** → **Settings**
4. Check **"Valid OAuth Redirect URIs"** contains:
   - `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback`
   - `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback-popup`

### Step 3: Test OAuth URLs

Visit in browser (must be logged in):
```
https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/debug/oauth-urls
```

This will show the exact URLs your app is using.

### Step 4: Check Server Logs

When you try OAuth, check the terminal running `npm run dev` for:
- `NEXT_PUBLIC_APP_URL` value
- Redirect URI being used
- Any error messages

---

## Quick Fix Checklist

- [ ] `.env.local` has `NEXT_PUBLIC_APP_URL` set to ngrok URL
- [ ] Dev server restarted after changing `.env.local`
- [ ] Facebook App has BOTH callback URLs added
- [ ] URLs in Facebook match EXACTLY (copy-paste)
- [ ] Clicked "Save Changes" in Facebook
- [ ] Waited 10-30 seconds after saving
- [ ] Cleared browser cookies/cache
- [ ] Ngrok tunnel is still running
- [ ] Dev server is running on port 3000

---

## Still Not Working?

1. **Check the exact error message** in:
   - Browser console (F12)
   - Server terminal logs
   - Facebook error response

2. **Verify ngrok URL hasn't changed**:
   ```bash
   npm run ngrok:url
   npm run ngrok:update-env  # If it changed
   ```

3. **Test the callback endpoint directly**:
   Visit: `https://unglamourous-unaccustomedly-audra.ngrok-free.dev/api/facebook/callback`
   (Should redirect to login if not authenticated)

4. **Check Facebook App is in correct mode**:
   - Development mode: Only you and test users can use it
   - Live mode: Public access (requires app review)

---

## Need More Help?

Share:
1. The exact error message you're seeing
2. Browser console errors (F12 → Console)
3. Server terminal logs
4. What happens when you click "Connect with Facebook"





