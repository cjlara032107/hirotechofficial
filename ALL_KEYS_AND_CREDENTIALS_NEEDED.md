# 🔑 All Keys and Credentials You Need for Vercel

## Summary of All Required Keys

Here's a complete list of all the keys and credentials you need to set in Vercel:

---

## 1. 🔐 Supabase Keys (Already Have These)

### `NEXT_PUBLIC_SUPABASE_URL`
- **What it is:** Your Supabase project URL
- **Your value:** `https://qudsmrrfbatasnyvuxch.supabase.co`
- **Where to find:** Supabase Dashboard → Settings → API → Project URL

### `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- **What it is:** Public anonymous key for client-side Supabase access
- **Your value:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1ZHNtcnJmYmF0YXNueXZ1eGNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5MjgxMDMsImV4cCI6MjA3ODUwNDEwM30.S2WNnRwW0XHyrj5KwGOgcKHuxN4EXKi5rBTX7mscuLA`
- **Where to find:** Supabase Dashboard → Settings → API → Project API keys → `anon` `public` key

**✅ You already have both of these!**

---

## 2. 🗄️ Database Connection Strings (Already Have These)

### `DATABASE_URL`
- **What it is:** Connection string for regular database queries (with connection pooling)
- **Your value:** `postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true`
- **Where to find:** Supabase Dashboard → Settings → Database → Connection string → URI (use port 6543)

### `DIRECT_URL`
- **What it is:** Direct connection string for migrations (no pooling)
- **Your value:** `postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres`
- **Where to find:** Supabase Dashboard → Settings → Database → Connection string → URI (use port 5432)

**✅ You already have both of these!**

---

## 3. 📘 Facebook App Keys (Already Have These)

### `FACEBOOK_APP_ID`
- **What it is:** Your Facebook App ID
- **Your value:** `802438925861067`
- **Where to find:** Facebook Developers → Your App → Settings → Basic → App ID

### `FACEBOOK_APP_SECRET`
- **What it is:** Your Facebook App Secret (keep this private!)
- **Your value:** `99e11ff061cd03fa9348547f754f96b9`
- **Where to find:** Facebook Developers → Your App → Settings → Basic → App Secret (click "Show")

### `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
- **What it is:** A custom token you create for webhook verification
- **Your value:** (You need to generate this - see below)
- **Where to find:** You create this yourself (any random secure string)

**✅ You have App ID and Secret, but need to generate the webhook token!**

---

## 4. 🔒 Authentication Secrets (Already Generated)

### `NEXTAUTH_SECRET` or `AUTH_SECRET`
- **What it is:** Secret key for encrypting JWT tokens and sessions
- **Your value:** `35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK` (or the longer one)
- **Where to find:** We generated this earlier - it's in your `.env.local`

**✅ You already have this!**

---

## 5. ⚡ Redis Connection (Already Have This)

### `REDIS_URL`
- **What it is:** Redis connection string for campaign processing
- **Your value:** `redis://default:KGg04axFynrwFjFjFaEEX5yK3lPAVpyN@redis-14778.c326.us-east-1-3.ec2.redns.redis-cloud.com:14778`
- **Where to find:** Redis Cloud Dashboard → Your Database → Configuration → Endpoint

**✅ You already have this!**

---

## 6. 🌐 Application URLs (Need to Update)

### `NEXT_PUBLIC_APP_URL`
- **What it is:** Your public application URL
- **Your value:** `https://hirotechofficial-beta.vercel.app` (update this!)
- **Where to find:** Your Vercel deployment URL

### `NEXTAUTH_URL`
- **What it is:** URL for NextAuth callbacks
- **Your value:** `https://hirotechofficial-beta.vercel.app` (update this!)
- **Where to find:** Same as above

**⚠️ Update these with your actual Vercel domain!**

---

## 📋 Complete List for Vercel Dashboard

Copy and paste these into Vercel → Settings → Environment Variables:

```env
# Application URLs
NEXT_PUBLIC_APP_URL=https://hirotechofficial-beta.vercel.app
NEXTAUTH_URL=https://hirotechofficial-beta.vercel.app

# Authentication
AUTH_SECRET=35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK
NEXTAUTH_SECRET="35N2uXdsujOpav4kgFsedFkQeyF_7u2dqhp9EMSnbAbDNhiSK="
NODE_ENV=production

# Database
DATABASE_URL=postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true
DIRECT_URL=postgresql://postgres.qudsmrrfbatasnyvuxch:demet5732595@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres

# Supabase
NEXT_PUBLIC_SUPABASE_URL=https://qudsmrrfbatasnyvuxch.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1ZHNtcnJmYmF0YXNueXZ1eGNoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5MjgxMDMsImV4cCI6MjA3ODUwNDEwM30.S2WNnRwW0XHyrj5KwGOgcKHuxN4EXKi5rBTX7mscuLA

# Facebook
FACEBOOK_APP_ID=802438925861067
FACEBOOK_APP_SECRET=99e11ff061cd03fa9348547f754f96b9
FACEBOOK_WEBHOOK_VERIFY_TOKEN=GENERATE_THIS_BELOW

# Redis
REDIS_URL=redis://default:KGg04axFynrwFjFjFaEEX5yK3lPAVpyN@redis-14778.c326.us-east-1-3.ec2.redns.redis-cloud.com:14778
```

---

## 🔑 Generate Facebook Webhook Verify Token

Run this command to generate a secure token:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Then:
1. Copy the output
2. Add it to Vercel as `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
3. Use the same token in Facebook App → Webhooks → Verify Token

---

## ❓ Which Key Are You Asking About?

If you're asking about a specific key, here's what each one is:

- **Supabase Anon Key** = Public key for client-side Supabase access (already have it)
- **Supabase Service Role Key** = NOT NEEDED (only for admin operations)
- **Facebook App Secret** = Secret key for Facebook API (already have it)
- **Database Password** = `demet5732595` (in your connection strings)
- **Redis Password** = `KGg04axFynrwFjFjFaEEX5yK3lPAVpyN` (in your Redis URL)

**Most likely you're asking about the Supabase Anon Key, which you already have!** ✅

---

**All your keys are ready - just need to add them to Vercel Dashboard!** 🚀





