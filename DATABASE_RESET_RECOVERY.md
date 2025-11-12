# 🔄 Database Reset - Recovery Guide

**Issue:** Foreign key constraint error after database reset  
**Error Code:** P2003  
**Constraint:** `FacebookPage_organizationId_fkey`

---

## 🔍 What Happened

When you reset the database, all data was deleted including:
- ❌ Your user account
- ❌ Your organization
- ❌ All contacts
- ❌ All campaigns
- ❌ All Facebook page connections

Now when you try to connect a Facebook page, it fails because there's no organization to link it to.

---

## ✅ Solution: Register a New Account

### Step 1: Go to Registration Page
```
http://localhost:3000/register
```

### Step 2: Create a New Account
Fill in the form:
- **Email:** your-email@example.com
- **Password:** your-secure-password
- **Name:** Your Name
- **Organization Name:** Your Company Name

### Step 3: Login
After registration, you'll be redirected to login or automatically logged in.

### Step 4: Connect Facebook Pages
Now you can connect Facebook pages:
1. Go to Settings > Integrations
2. Click "Connect Facebook"
3. Authorize and select pages
4. Success! ✅

---

## 🔧 Alternative: Create User via Script

If you want to create a user programmatically:

### Create Test User Script

Create `scripts/create-user.ts`:

```typescript
import { prisma } from '../src/lib/db';
import bcrypt from 'bcrypt';

async function createTestUser() {
  try {
    // Create organization
    const org = await prisma.organization.create({
      data: {
        name: 'Test Organization',
        slug: 'test-org',
      },
    });

    console.log('✅ Organization created:', org.id);

    // Create user
    const hashedPassword = await bcrypt.hash('password123', 10);
    const user = await prisma.user.create({
      data: {
        email: 'admin@test.com',
        password: hashedPassword,
        name: 'Admin User',
        role: 'ADMIN',
        organizationId: org.id,
      },
    });

    console.log('✅ User created:', user.email);
    console.log('✅ Password: password123');
    console.log('✅ Organization ID:', org.id);

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createTestUser();
```

### Run the Script

```bash
npx tsx scripts/create-user.ts
```

### Login with Test Account

```
Email: admin@test.com
Password: password123
```

---

## 🔄 If You Need to Reset Again

### Option 1: Reset Database and Keep Schema

```bash
# This clears all data but keeps the schema
npx prisma migrate reset --skip-seed

# Or manually clear tables
npx prisma studio
# Then delete all records from each table
```

### Option 2: Full Reset with New Schema

```bash
# Push schema to database (recreates everything)
npx prisma db push --force-reset

# Generate Prisma client
npx prisma generate
```

---

## 📊 What Gets Created on Registration

When you register a new account through the UI:

```
POST /api/auth/register
  ↓
1. Create Organization
   - name: "Your Company"
   - slug: "your-company"
   ↓
2. Create User
   - email: "your@email.com"
   - password: (hashed with bcrypt)
   - role: "ADMIN"
   - organizationId: (linked to org)
   ↓
3. Return Success
   ↓
4. Auto-login or redirect to login
```

---

## ✅ Verification Steps

After creating a new account, verify everything works:

### 1. Check User Exists
```bash
npx prisma studio
```
- Open "User" table
- Should see your account

### 2. Check Organization Exists
- Open "Organization" table
- Should see your organization

### 3. Test Login
```
http://localhost:3000/login
```
- Login with your credentials
- Should redirect to dashboard

### 4. Test Facebook Connection
```
http://localhost:3000/settings/integrations
```
- Click "Connect Facebook"
- Should work without foreign key error

---

## 🐛 Common Issues After Reset

### Issue 1: "No organization found"
**Solution:** Register a new account first

### Issue 2: "Cannot read property 'organizationId'"
**Solution:** Clear cookies and login again

### Issue 3: "Invalid session"
**Solution:** 
```bash
# Clear Next.js cache
rm -rf .next

# Restart dev server
npm run dev
```

### Issue 4: Prisma Client out of sync
**Solution:**
```bash
npx prisma generate
npm run dev
```

---

## 💾 Backup Before Reset (Next Time)

Before resetting the database in the future:

### Export Data
```bash
# Export all data to SQL
pg_dump "your-database-url" > backup.sql

# Or use Prisma Studio to export specific tables
npx prisma studio
# Export each table as CSV
```

### Import Data Later
```bash
# Import SQL backup
psql "your-database-url" < backup.sql
```

---

## 🎯 Quick Recovery Checklist

After database reset:

1. [ ] Register new account at `/register`
2. [ ] Verify login works at `/login`
3. [ ] Go to Settings > Integrations
4. [ ] Connect Facebook pages
5. [ ] Sync contacts
6. [ ] Verify AI analysis works
7. [ ] Test creating campaigns

---

## 📞 Still Having Issues?

### Debug Organization ID

Check what organizationId the session has:

Add this to any API route:
```typescript
console.log('Session:', session);
console.log('Organization ID:', session.user.organizationId);
```

### Check Database

```bash
# Connect to database
npx prisma studio

# Or use psql
psql "your-database-url"

# Check if organization exists
SELECT * FROM "Organization";

# Check if user exists
SELECT * FROM "User";
```

---

## ✅ Summary

**What you need to do:**
1. Go to http://localhost:3000/register
2. Create a new account
3. Login
4. Connect Facebook pages again
5. Everything should work! ✅

The AI conversation analysis feature is still working perfectly - you just need a user account to use it!

---

**Created:** November 12, 2025  
**Issue:** Database reset causing foreign key error  
**Solution:** Register new account

