# 🔗 How to Get Database Connection String from Supabase

## 📍 Step-by-Step Instructions

### For Database 1 (vivelzjlltbytnhybdcm):

1. **In the left sidebar, click "Database"** (under "CONFIGURATION" section)
   - This will open the Database settings page

2. **On the Database page, look for "Connection Pooling"** section
   - You'll see different connection modes

3. **Copy the "Transaction mode" connection string**
   - Look for the connection string with port **6543**
   - It should look like: `postgresql://postgres.[ref]:[password]@[hostname]:6543/postgres?pgbouncer=true`
   - Click the "Copy" button next to it

4. **Update `.env.local`:**
   - Replace the current `DATABASE_URL_1` value with the copied connection string

### For Database 2 (kzvhbgqpxykganquikmv):

1. **Switch to the other project** (kzvhbgqpxykganquikmv)
2. **Follow the same steps** as above
3. **Update `DATABASE_URL_2`** in `.env.local`

## 🎯 What to Look For

The connection string should have:
- ✅ Port **6543** (for connection pooling)
- ✅ `pgbouncer=true` parameter
- ✅ Format: `postgresql://postgres.[project-ref]:[password]@[hostname]:6543/postgres?pgbouncer=true`

## ⚠️ Important Notes

- Make sure the project is **NOT paused** (if you see "Restore" button, click it first)
- Use the **Transaction mode** connection string (not Session mode)
- The hostname might be different from what's currently in `.env.local`



## 📍 Step-by-Step Instructions

### For Database 1 (vivelzjlltbytnhybdcm):

1. **In the left sidebar, click "Database"** (under "CONFIGURATION" section)
   - This will open the Database settings page

2. **On the Database page, look for "Connection Pooling"** section
   - You'll see different connection modes

3. **Copy the "Transaction mode" connection string**
   - Look for the connection string with port **6543**
   - It should look like: `postgresql://postgres.[ref]:[password]@[hostname]:6543/postgres?pgbouncer=true`
   - Click the "Copy" button next to it

4. **Update `.env.local`:**
   - Replace the current `DATABASE_URL_1` value with the copied connection string

### For Database 2 (kzvhbgqpxykganquikmv):

1. **Switch to the other project** (kzvhbgqpxykganquikmv)
2. **Follow the same steps** as above
3. **Update `DATABASE_URL_2`** in `.env.local`

## 🎯 What to Look For

The connection string should have:
- ✅ Port **6543** (for connection pooling)
- ✅ `pgbouncer=true` parameter
- ✅ Format: `postgresql://postgres.[project-ref]:[password]@[hostname]:6543/postgres?pgbouncer=true`

## ⚠️ Important Notes

- Make sure the project is **NOT paused** (if you see "Restore" button, click it first)
- Use the **Transaction mode** connection string (not Session mode)
- The hostname might be different from what's currently in `.env.local`




