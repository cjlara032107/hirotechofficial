# Developer Account Feature

## Overview

This feature adds a **DEVELOPER** role that allows developers to:
1. **Enable/disable access to specific pages** - Control which pages are accessible
2. **Manage API keys** - Add, update, and delete API keys for AI services

---

## Database Changes

### New Role
- Added `DEVELOPER` to the `Role` enum in `prisma/schema.prisma`

### New Model: PageAccess
```prisma
model PageAccess {
  id             String   @id @default(cuid())
  userId         String
  pagePath       String   // e.g., "/dashboard", "/contacts"
  isEnabled      Boolean  @default(true)
  createdAt      DateTime @default(now())
  updatedAt      DateTime @updatedAt
  user           User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([userId, pagePath])
  @@index([userId])
  @@index([pagePath])
}
```

---

## Migration Steps

### 1. Run Database Migration

```bash
# Create migration
npx prisma migrate dev --name add_developer_role_and_page_access

# Or push directly (development only)
npx prisma db push

# Generate Prisma Client
npx prisma generate
```

### 2. Update Existing Users (Optional)

To convert an existing user to a developer:

```sql
-- Update user role to DEVELOPER
UPDATE "User" SET role = 'DEVELOPER' WHERE email = 'developer@example.com';
```

Or use Prisma Studio:
```bash
npx prisma studio
```

---

## Features

### 1. Page Access Management

**Location:** `/settings/developer`

Developers can enable/disable access to specific pages:
- Dashboard
- Contacts
- Campaigns
- Pipelines
- Templates
- Tags
- Team
- AI Automations
- Settings pages

**How it works:**
- When a page is disabled, developers are redirected to `/dashboard` when trying to access it
- Middleware checks page access on every request
- Default state: All pages are enabled (no setting = enabled)

### 2. API Key Management

**Location:** `/settings/api-keys`

Developers can now:
- View all API keys
- Add new API keys (single or bulk)
- Enable/disable keys
- Delete keys
- View key statistics (usage, success rate, etc.)

**Access:** Previously admin-only, now available to both ADMIN and DEVELOPER roles

---

## API Routes

### Page Access Management

#### GET `/api/developer/page-access`
Get all page access settings for the current developer

**Response:**
```json
[
  {
    "id": "clx...",
    "pagePath": "/contacts",
    "isEnabled": false,
    "createdAt": "2025-01-01T00:00:00Z",
    "updatedAt": "2025-01-01T00:00:00Z"
  }
]
```

#### POST `/api/developer/page-access`
Create or update page access setting

**Request:**
```json
{
  "pagePath": "/contacts",
  "isEnabled": false
}
```

#### PATCH `/api/developer/page-access/[pagePath]`
Update specific page access

#### DELETE `/api/developer/page-access/[pagePath]`
Delete page access setting (resets to default enabled)

---

## Middleware Protection

The middleware (`src/middleware.ts`) now checks page access for developers:

1. Authenticates user via Supabase
2. Checks if user is a DEVELOPER
3. If developer, checks `PageAccess` table for the requested path
4. If page is disabled, redirects to `/dashboard`
5. Otherwise, allows access

**Note:** This check happens on every request, so it's fast and secure.

---

## UI Components

### Settings Navigation
- Added `SettingsNav` component that shows:
  - Profile (all users)
  - Integrations (all users)
  - API Keys (ADMIN & DEVELOPER)
  - Developer Settings (DEVELOPER only)

### Page Access Client
- `PageAccessClient` component for managing page access
- Shows all available pages with toggle switches
- Real-time updates via API

---

## Security Considerations

1. **Role-based Access:** Only users with `DEVELOPER` role can access developer features
2. **Page-level Protection:** Middleware enforces page access restrictions
3. **API Protection:** All API routes check for DEVELOPER role
4. **Default Behavior:** Pages are enabled by default (fail-open for safety)

---

## Usage Examples

### Creating a Developer Account

```typescript
// Via Prisma
await prisma.user.update({
  where: { email: 'dev@example.com' },
  data: { role: 'DEVELOPER' }
});
```

### Disabling a Page for Developer

```typescript
// Via API
await fetch('/api/developer/page-access', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    pagePath: '/contacts',
    isEnabled: false
  })
});
```

### Checking Page Access (Server-side)

```typescript
import { checkPageAccess } from '@/lib/developer/check-page-access';

const hasAccess = await checkPageAccess(userId, '/contacts');
// Returns: true (enabled), false (disabled), or null (no setting = enabled)
```

---

## Testing

### Test Page Access

1. Create a developer account
2. Go to `/settings/developer`
3. Disable "Contacts" page
4. Try to access `/contacts` - should redirect to `/dashboard`
5. Re-enable the page - should work again

### Test API Keys

1. As a developer, go to `/settings/api-keys`
2. Add a new API key
3. Verify it appears in the list
4. Test enabling/disabling keys

---

## Files Changed

### Database
- `prisma/schema.prisma` - Added DEVELOPER role and PageAccess model

### API Routes
- `src/app/api/developer/page-access/route.ts` - Page access CRUD
- `src/app/api/developer/page-access/[pagePath]/route.ts` - Individual page operations
- `src/app/api/api-keys/route.ts` - Updated to allow DEVELOPER
- `src/app/api/api-keys/[id]/route.ts` - Updated to allow DEVELOPER

### Components
- `src/components/settings/page-access-client.tsx` - Page access UI
- `src/components/settings/settings-nav.tsx` - Settings navigation

### Pages
- `src/app/(dashboard)/settings/developer/page.tsx` - Developer settings page
- `src/app/(dashboard)/settings/layout.tsx` - Settings layout with nav
- `src/app/(dashboard)/settings/api-keys/page.tsx` - Updated to allow DEVELOPER

### Middleware
- `src/middleware.ts` - Added page access checking for developers

### Utilities
- `src/lib/developer/check-page-access.ts` - Helper functions for page access

---

## Next Steps

1. **Run Migration:** `npx prisma migrate dev --name add_developer_role_and_page_access`
2. **Create Developer User:** Update an existing user's role or create a new one
3. **Test Features:** Verify page access and API key management work correctly
4. **Deploy:** Push changes to production after testing

---

## Support

If you encounter any issues:
1. Check that migrations have been applied
2. Verify user has DEVELOPER role
3. Check middleware logs for access denials
4. Verify API routes are returning correct responses






