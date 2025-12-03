# 🔑 Supabase Keys for All Databases

## 📋 Current Status

**Database 0 (qudsmrrfbatasnyvuxch):**
- ✅ `NEXT_PUBLIC_SUPABASE_URL` - Set
- ✅ `NEXT_PUBLIC_SUPABASE_ANON_KEY` - Set

**Database 1 (vivelzjlltbytnhybdcm):**
- ❌ `NEXT_PUBLIC_SUPABASE_URL_1` - **NOT SET**
- ❌ `NEXT_PUBLIC_SUPABASE_ANON_KEY_1` - **NOT SET**

**Database 2 (kzvhbgqpxykganquikmv):**
- ❌ `NEXT_PUBLIC_SUPABASE_URL_2` - **NOT SET**
- ❌ `NEXT_PUBLIC_SUPABASE_ANON_KEY_2` - **NOT SET**

## 🔍 Why This Matters

Currently, the app uses **one Supabase project** (Database 0) for:
- Authentication (login/signup)
- Realtime subscriptions
- Client-side Supabase operations

However, if databases 1 and 2 are **separate Supabase projects**, they each have their own:
- Project URL
- Anon key
- Auth system

## 🔧 How to Get the Keys

### For Database 1 (vivelzjlltbytnhybdcm):

1. **Go to Supabase Dashboard:**
   - Visit: https://vivelzjlltbytnhybdcm.supabase.co
   - Or: https://supabase.com/dashboard → Select project `vivelzjlltbytnhybdcm`

2. **Get Project URL:**
   - Navigate to: **Settings → API**
   - Copy **"Project URL"** → This is your `NEXT_PUBLIC_SUPABASE_URL_1`
   - Should be: `https://vivelzjlltbytnhybdcm.supabase.co`

3. **Get Anon Key:**
   - Same page: **Settings → API**
   - Under **"Project API keys"**
   - Copy the **`anon` `public`** key → This is your `NEXT_PUBLIC_SUPABASE_ANON_KEY_1`

### For Database 2 (kzvhbgqpxykganquikmv):

1. **Go to Supabase Dashboard:**
   - Visit: https://kzvhbgqpxykganquikmv.supabase.co
   - Or: https://supabase.com/dashboard → Select project `kzvhbgqpxykganquikmv`

2. **Get Project URL:**
   - Navigate to: **Settings → API**
   - Copy **"Project URL"** → This is your `NEXT_PUBLIC_SUPABASE_URL_2`
   - Should be: `https://kzvhbgqpxykganquikmv.supabase.co`

3. **Get Anon Key:**
   - Same page: **Settings → API**
   - Under **"Project API keys"**
   - Copy the **`anon` `public`** key → This is your `NEXT_PUBLIC_SUPABASE_ANON_KEY_2`

## 📝 Add to .env.local

After getting the keys, add them to `.env.local`:

```env
# Supabase Configuration for Database 0 (already set)
NEXT_PUBLIC_SUPABASE_URL=https://qudsmrrfbatasnyvuxch.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Supabase Configuration for Database 1
NEXT_PUBLIC_SUPABASE_URL_1=https://vivelzjlltbytnhybdcm.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY_1=[paste anon key from Database 1 here]

# Supabase Configuration for Database 2
NEXT_PUBLIC_SUPABASE_URL_2=https://kzvhbgqpxykganquikmv.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY_2=[paste anon key from Database 2 here]
```

## ⚠️ Important Note

**Current Code Limitation:**
The current codebase only uses `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` (without index) for authentication. This means:
- All users authenticate through Database 0's Supabase project
- Databases 1 & 2 are only used for **data storage** (via Prisma)

**If you want separate auth per database:**
- The Supabase client code would need to be updated to support multiple projects
- This is more complex and may not be necessary if all databases share the same user base

## ✅ Quick Check

Run this to verify your configuration:

```bash
npx tsx scripts/get-supabase-keys.ts
```

This will show which keys are set and which are missing.



## 📋 Current Status

**Database 0 (qudsmrrfbatasnyvuxch):**
- ✅ `NEXT_PUBLIC_SUPABASE_URL` - Set
- ✅ `NEXT_PUBLIC_SUPABASE_ANON_KEY` - Set

**Database 1 (vivelzjlltbytnhybdcm):**
- ❌ `NEXT_PUBLIC_SUPABASE_URL_1` - **NOT SET**
- ❌ `NEXT_PUBLIC_SUPABASE_ANON_KEY_1` - **NOT SET**

**Database 2 (kzvhbgqpxykganquikmv):**
- ❌ `NEXT_PUBLIC_SUPABASE_URL_2` - **NOT SET**
- ❌ `NEXT_PUBLIC_SUPABASE_ANON_KEY_2` - **NOT SET**

## 🔍 Why This Matters

Currently, the app uses **one Supabase project** (Database 0) for:
- Authentication (login/signup)
- Realtime subscriptions
- Client-side Supabase operations

However, if databases 1 and 2 are **separate Supabase projects**, they each have their own:
- Project URL
- Anon key
- Auth system

## 🔧 How to Get the Keys

### For Database 1 (vivelzjlltbytnhybdcm):

1. **Go to Supabase Dashboard:**
   - Visit: https://vivelzjlltbytnhybdcm.supabase.co
   - Or: https://supabase.com/dashboard → Select project `vivelzjlltbytnhybdcm`

2. **Get Project URL:**
   - Navigate to: **Settings → API**
   - Copy **"Project URL"** → This is your `NEXT_PUBLIC_SUPABASE_URL_1`
   - Should be: `https://vivelzjlltbytnhybdcm.supabase.co`

3. **Get Anon Key:**
   - Same page: **Settings → API**
   - Under **"Project API keys"**
   - Copy the **`anon` `public`** key → This is your `NEXT_PUBLIC_SUPABASE_ANON_KEY_1`

### For Database 2 (kzvhbgqpxykganquikmv):

1. **Go to Supabase Dashboard:**
   - Visit: https://kzvhbgqpxykganquikmv.supabase.co
   - Or: https://supabase.com/dashboard → Select project `kzvhbgqpxykganquikmv`

2. **Get Project URL:**
   - Navigate to: **Settings → API**
   - Copy **"Project URL"** → This is your `NEXT_PUBLIC_SUPABASE_URL_2`
   - Should be: `https://kzvhbgqpxykganquikmv.supabase.co`

3. **Get Anon Key:**
   - Same page: **Settings → API**
   - Under **"Project API keys"**
   - Copy the **`anon` `public`** key → This is your `NEXT_PUBLIC_SUPABASE_ANON_KEY_2`

## 📝 Add to .env.local

After getting the keys, add them to `.env.local`:

```env
# Supabase Configuration for Database 0 (already set)
NEXT_PUBLIC_SUPABASE_URL=https://qudsmrrfbatasnyvuxch.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Supabase Configuration for Database 1
NEXT_PUBLIC_SUPABASE_URL_1=https://vivelzjlltbytnhybdcm.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY_1=[paste anon key from Database 1 here]

# Supabase Configuration for Database 2
NEXT_PUBLIC_SUPABASE_URL_2=https://kzvhbgqpxykganquikmv.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY_2=[paste anon key from Database 2 here]
```

## ⚠️ Important Note

**Current Code Limitation:**
The current codebase only uses `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` (without index) for authentication. This means:
- All users authenticate through Database 0's Supabase project
- Databases 1 & 2 are only used for **data storage** (via Prisma)

**If you want separate auth per database:**
- The Supabase client code would need to be updated to support multiple projects
- This is more complex and may not be necessary if all databases share the same user base

## ✅ Quick Check

Run this to verify your configuration:

```bash
npx tsx scripts/get-supabase-keys.ts
```

This will show which keys are set and which are missing.




