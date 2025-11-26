# 🔒 Secret Management Guide

## ⚠️ CRITICAL: Never Commit Secrets to Git

**NEVER commit files containing sensitive credentials to version control.** This includes:
- Database passwords
- API keys
- Encryption keys
- OAuth secrets
- Tokens
- Any authentication credentials

## ✅ Proper Secret Management

### For Vercel Deployments

All secrets should be managed through the **Vercel Dashboard**, not in files:

1. **Go to Vercel Dashboard**
   - Navigate to: https://vercel.com/dashboard
   - Select your project: `hirotechofficial-beta`
   - Go to **Settings** → **Environment Variables**

2. **Add Environment Variables**
   Add these variables for **Production**, **Preview**, and **Development**:

   ```env
   # Database
   DATABASE_URL=postgresql://...
   DIRECT_URL=postgresql://...
   
   # Authentication
   NEXTAUTH_SECRET=your-secret-here
   NEXTAUTH_URL=https://your-domain.vercel.app
   
   # Encryption
   ENCRYPTION_KEY=your-64-char-hex-key
   
   # Facebook
   FACEBOOK_APP_ID=your-app-id
   FACEBOOK_APP_SECRET=your-app-secret
   FACEBOOK_WEBHOOK_VERIFY_TOKEN=your-token
   
   # Supabase
   NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
   
   # Redis
   REDIS_URL=redis://...
   
   # App URL
   NEXT_PUBLIC_APP_URL=https://your-domain.vercel.app
   ```

3. **After Adding Variables**
   - **Redeploy** your application for changes to take effect
   - Variables are automatically available in your application at runtime

### For Local Development

Use `.env.local` file (which is already in `.gitignore`):

```bash
# Create .env.local from template
cp .env.example .env.local

# Edit with your local values
# NEVER commit .env.local to git
```

## 🚨 If Secrets Were Committed

If secrets were accidentally committed:

1. **Immediately rotate all exposed credentials:**
   - Change database passwords
   - Regenerate API keys
   - Create new encryption keys
   - Update OAuth secrets

2. **Remove from Git History** (if needed):
   ```bash
   # Remove file from tracking
   git rm --cached .env.vercel
   
   # Add to .gitignore
   echo ".env.vercel" >> .gitignore
   
   # Commit the removal
   git add .gitignore
   git commit -m "Remove .env.vercel from tracking"
   ```

3. **Update Vercel Environment Variables** with new credentials

## 📋 Checklist

- [x] `.env.vercel` removed from git tracking
- [x] `.env.vercel` added to `.gitignore`
- [x] All secrets managed in Vercel Dashboard
- [ ] All exposed credentials rotated (DO THIS IMMEDIATELY)
- [ ] Team notified about credential rotation

## 🔐 Generating New Encryption Key

If you need to generate a new encryption key:

```bash
npx tsx scripts/generate-encryption-key.ts
```

This will output a secure 64-character hex key that you can add to Vercel.

## 📚 Additional Resources

- [Vercel Environment Variables Docs](https://vercel.com/docs/concepts/projects/environment-variables)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [OWASP Secret Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)





