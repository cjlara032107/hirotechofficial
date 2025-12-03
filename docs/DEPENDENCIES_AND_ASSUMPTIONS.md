# Dependencies and Assumptions

This document outlines all external dependencies, their versions, purposes, and critical assumptions about the system.

## Table of Contents

1. [Runtime Dependencies](#runtime-dependencies)
2. [Development Dependencies](#development-dependencies)
3. [External Services](#external-services)
4. [Infrastructure Assumptions](#infrastructure-assumptions)
5. [Data Assumptions](#data-assumptions)
6. [Security Assumptions](#security-assumptions)
7. [Performance Assumptions](#performance-assumptions)
8. [Compatibility Requirements](#compatibility-requirements)

---

## Runtime Dependencies

### Core Framework

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `next` | `16.0.1` | React framework with SSR/SSG | ✅ Yes |
| `react` | `19.2.0` | UI library | ✅ Yes |
| `react-dom` | `19.2.0` | React DOM renderer | ✅ Yes |
| `typescript` | `^5` | Type safety | ✅ Yes |

**Assumptions:**
- Next.js 16 App Router is used (not Pages Router)
- React Server Components are the default
- TypeScript strict mode is enabled

### Database & ORM

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `@prisma/client` | `^6.19.0` | Prisma ORM client | ✅ Yes |
| `prisma` | `6.19.0` | Prisma CLI and schema | ✅ Yes |
| `@prisma/engines` | `^6.19.0` | Prisma query engine | ✅ Yes |

**Assumptions:**
- PostgreSQL database is available
- Database connection string is provided via `DATABASE_URL`
- Prisma migrations are run before deployment
- Connection pooling is handled by database provider (Supabase pooler)

**Database Requirements:**
- PostgreSQL 12+ (recommended: 14+)
- Support for connection pooling (PgBouncer or Supabase pooler)
- SSL/TLS encryption enabled

### Authentication

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `next-auth` | `^5.0.0-beta.30` | Authentication framework | ✅ Yes |
| `@auth/prisma-adapter` | `^2.11.1` | Prisma adapter for NextAuth | ✅ Yes |
| `@supabase/ssr` | `^0.7.0` | Supabase SSR client | ✅ Yes |
| `@supabase/supabase-js` | `^2.81.0` | Supabase JavaScript client | ✅ Yes |
| `bcrypt` | `^6.0.0` | Password hashing | ✅ Yes |

**Assumptions:**
- Supabase is used for authentication backend
- Supabase project is configured with proper RLS policies
- Session management uses HTTP-only cookies
- Password hashing uses bcrypt with salt rounds 10+

### Queue & Caching

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `ioredis` | `^5.8.2` | Redis client for BullMQ | ✅ Yes |
| `bullmq` | (implied) | Job queue (via ioredis) | ✅ Yes |

**Assumptions:**
- Redis server is available and accessible
- Redis connection string is provided via `REDIS_URL`
- Redis is used for job queues (BullMQ) and optional caching
- Redis version 6.0+ recommended

### UI Components

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `@radix-ui/*` | Various | Headless UI components | ✅ Yes |
| `tailwindcss` | `^4` | CSS framework | ✅ Yes |
| `@tailwindcss/postcss` | `^4` | PostCSS plugin | ✅ Yes |
| `lucide-react` | `^0.553.0` | Icon library | ⚠️ Partial |
| `recharts` | `^3.4.1` | Chart library | ⚠️ Partial |

**Assumptions:**
- Tailwind CSS is configured with custom theme
- Radix UI components are styled with Tailwind
- Icons are loaded on-demand (tree-shaking)

### Data Fetching & State

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `@tanstack/react-query` | `^5.90.7` | Data fetching and caching | ✅ Yes |
| `@tanstack/react-table` | `^8.21.3` | Table component | ⚠️ Partial |
| `@tanstack/react-virtual` | `^3.13.12` | Virtual scrolling | ⚠️ Partial |
| `axios` | `^1.13.2` | HTTP client | ⚠️ Partial |

**Assumptions:**
- React Query is used for all server state management
- React Query cache is configured with appropriate TTLs
- Axios is used for external API calls (Facebook Graph API)

### Forms & Validation

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `react-hook-form` | `^7.66.0` | Form state management | ✅ Yes |
| `@hookform/resolvers` | `^5.2.2` | Form validation resolvers | ✅ Yes |
| `zod` | `^4.1.12` | Schema validation | ✅ Yes |

**Assumptions:**
- All form inputs are validated with Zod schemas
- React Hook Form is used for all forms
- Validation runs on both client and server

### AI & External APIs

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `openai` | `^4.104.0` | OpenAI API client | ⚠️ Partial |
| `@fal-ai/client` | `^1.7.2` | Fal.ai client | ⚠️ Partial |

**Assumptions:**
- AI services are optional features
- API keys are stored encrypted in database
- API key rotation is supported
- Fallback to alternative providers is possible

### Utilities

| Package | Version | Purpose | Critical |
|---------|---------|---------|----------|
| `date-fns` | `^4.1.0` | Date manipulation | ⚠️ Partial |
| `papaparse` | `^5.5.3` | CSV parsing | ⚠️ Partial |
| `nuqs` | `^2.7.3` | URL search params | ⚠️ Partial |
| `socket.io` | `^4.8.1` | WebSocket client | ⚠️ Partial |
| `socket.io-client` | `^4.8.1` | WebSocket client | ⚠️ Partial |

**Assumptions:**
- Date handling uses UTC internally
- CSV import/export is optional
- Real-time features use Socket.io (optional)

---

## Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `eslint` | `^9` | Linting |
| `eslint-config-next` | `16.0.1` | Next.js ESLint config |
| `jest` | `^29.7.0` | Testing framework |
| `@testing-library/react` | `^16.3.0` | React testing utilities |
| `@testing-library/jest-dom` | `^6.9.1` | Jest DOM matchers |
| `ts-jest` | `^29.2.5` | TypeScript Jest transformer |
| `tsx` | `^4.19.2` | TypeScript execution |
| `rimraf` | `^6.1.0` | File deletion utility |

**Assumptions:**
- Node.js 20+ is required for development
- Tests run in Jest with jsdom environment
- TypeScript is used for all code

---

## External Services

### Supabase

**Purpose:** Authentication, database hosting, real-time features

**Required Configuration:**
- `NEXT_PUBLIC_SUPABASE_URL`: Supabase project URL
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`: Supabase anonymous key

**Assumptions:**
- Supabase project is created and configured
- Row Level Security (RLS) policies are set up
- Database migrations are applied
- Real-time subscriptions are optional

**Limitations:**
- Free tier: 500MB database, 2GB bandwidth
- Paid tiers required for production scale

### Facebook Graph API

**Purpose:** Messenger and Instagram integration

**Required Configuration:**
- Facebook App ID and Secret
- Page Access Token
- Webhook verification token

**Assumptions:**
- Facebook App is created with Messenger product
- App is approved for production use
- Webhook URL is configured and verified
- Required permissions are granted:
  - `pages_messaging`
  - `pages_manage_metadata`
  - `instagram_basic`
  - `instagram_manage_messages`

**Rate Limits:**
- Messenger API: 200 requests/second per page
- Graph API: 200 requests/hour per user (default)
- Webhook delivery: Unlimited

**Limitations:**
- 24-hour messaging window (unless using message tags)
- Message tags have specific use cases
- Instagram messaging requires business account

### Redis (Upstash/Railway/Other)

**Purpose:** Job queue (BullMQ) and optional caching

**Required Configuration:**
- `REDIS_URL`: Redis connection string

**Assumptions:**
- Redis server is accessible from application
- Redis persistence is configured (optional)
- Redis version 6.0+ recommended

**Limitations:**
- Free tier: Limited memory and connections
- Paid tiers required for production scale

### AI Services (Optional)

**Purpose:** Contact analysis, message personalization

**Supported Providers:**
- OpenAI (GPT models)
- Fal.ai (alternative provider)
- Custom API keys stored encrypted

**Assumptions:**
- API keys are provided by users
- API key rotation is supported
- Fallback providers available
- Rate limiting is handled per provider

---

## Infrastructure Assumptions

### Deployment Platform

**Primary:** Vercel (serverless)

**Assumptions:**
- Serverless functions with cold starts
- Edge network for static assets
- Automatic HTTPS
- Environment variables configured in Vercel dashboard

**Limitations:**
- Function timeout: 10 seconds (Hobby), 60 seconds (Pro)
- Memory: 1024 MB per function
- Concurrent executions: Limited by plan

### Database Hosting

**Primary:** Supabase (PostgreSQL)

**Assumptions:**
- Connection pooling via Supabase pooler
- SSL/TLS encryption enabled
- Automatic backups configured
- Point-in-time recovery available

**Connection Pooling:**
- Pooler URL format: `postgresql://...@pooler.supabase.com:6543/...`
- Direct URL format: `postgresql://...@db.supabase.com:5432/...`
- Connection limit: 10 per serverless instance

### File Storage

**Assumptions:**
- User images stored in Supabase Storage (optional)
- Profile pictures use external URLs (Facebook/Instagram)
- No local file storage required

### CDN & Static Assets

**Assumptions:**
- Next.js handles static asset optimization
- Images optimized via Next.js Image component
- Automatic WebP conversion
- Edge caching via Vercel

---

## Data Assumptions

### Database Schema

**Assumptions:**
- All tables have `id` as primary key (CUID format)
- All tables have `createdAt` and `updatedAt` timestamps
- Soft deletes are not used (hard deletes)
- Foreign keys have `onDelete: Cascade` where appropriate

### Data Types

**Assumptions:**
- Dates stored as `DateTime` (UTC)
- JSON fields stored as `Json` type
- Large text stored as `String` (not `Text`)
- IDs use CUID format (not UUID)

### Data Relationships

**Assumptions:**
- One organization has many users, contacts, campaigns, etc.
- One contact belongs to one organization and one Facebook page
- One contact can have many tags (many-to-many)
- One contact belongs to one pipeline and one stage

### Data Validation

**Assumptions:**
- All user inputs are validated with Zod schemas
- Database constraints enforce data integrity
- Foreign key constraints prevent orphaned records
- Unique constraints prevent duplicates

---

## Security Assumptions

### Authentication

**Assumptions:**
- Passwords are hashed with bcrypt (salt rounds 10+)
- Sessions are stored in HTTP-only cookies
- CSRF protection via NextAuth
- Session expiration: 30 days (default)

### API Security

**Assumptions:**
- All API routes require authentication (except public endpoints)
- Rate limiting is applied to all public endpoints
- Input validation on all endpoints
- SQL injection prevented by Prisma ORM
- XSS prevented by React's automatic escaping

### Data Encryption

**Assumptions:**
- API keys stored encrypted in database
- Encryption key stored in `ENCRYPTION_KEY` environment variable
- Encryption uses AES-256-GCM
- Passwords never stored in plain text

### Environment Variables

**Assumptions:**
- Secrets are never committed to version control
- Environment variables are set in deployment platform
- `.env.local` is in `.gitignore`
- Production secrets are rotated regularly

---

## Performance Assumptions

### Response Times

**Assumptions:**
- API responses < 500ms for simple operations
- API responses < 2000ms for complex operations
- Database queries < 200ms for indexed queries
- Page load < 3s for first contentful paint

### Scalability

**Assumptions:**
- Application scales horizontally (serverless)
- Database connection pooling handles concurrency
- Redis handles job queue distribution
- CDN handles static asset delivery

### Caching

**Assumptions:**
- Message cache: 5-minute TTL
- Pipeline cache: Request-scoped (React cache)
- React Query cache: 30-second stale time
- Browser caching: Standard HTTP headers

### Rate Limiting

**Assumptions:**
- Standard API rate limit: 100 requests/minute
- Auth endpoints: 5 requests/minute
- File uploads: 10 requests/minute
- Facebook API: Respects provider limits

---

## Compatibility Requirements

### Node.js

**Required:** Node.js 20+

**Assumptions:**
- ES2022 features are available
- Async/await is fully supported
- Top-level await is available
- Native fetch API is available

### Browser Support

**Assumptions:**
- Modern browsers (Chrome, Firefox, Safari, Edge)
- ES2022 features supported
- CSS Grid and Flexbox supported
- WebSocket support (for real-time features)

### Database

**Required:** PostgreSQL 12+

**Assumptions:**
- JSON/JSONB support
- Full-text search support (optional)
- Extensions: `uuid-ossp` (optional)

---

## Critical Dependencies

### Must-Have for Production

1. **Next.js 16+** - Core framework
2. **PostgreSQL** - Database
3. **Supabase** - Authentication and database hosting
4. **Redis** - Job queue
5. **Prisma** - ORM

### Optional but Recommended

1. **Sentry** - Error monitoring (not in dependencies, but recommended)
2. **Vercel Analytics** - Performance monitoring
3. **Logging service** - Application logs

### Can Be Replaced

1. **AI Services** - OpenAI/Fal.ai can be swapped
2. **Redis** - Can use alternative queue systems
3. **UI Components** - Radix UI can be replaced
4. **Icons** - Lucide can be replaced

---

## Version Pinning Strategy

### Strictly Pinned

- `prisma`: `6.19.0` (exact version)
- `next`: `16.0.1` (exact version for stability)

### Semver Ranges

- Most packages use `^` (compatible versions)
- React 19.x is required (breaking changes from 18)

### Update Policy

- **Security updates**: Apply immediately
- **Minor updates**: Test and apply monthly
- **Major updates**: Plan migration, test thoroughly

---

## Breaking Changes to Watch

### Next.js 16

- App Router is default (no Pages Router)
- React Server Components are default
- Middleware changes

### React 19

- New JSX transform
- Automatic batching
- Concurrent features

### Prisma 6

- Connection pooling changes
- Query engine updates
- Migration format changes

---

## Troubleshooting Dependencies

### Common Issues

1. **Prisma Client Not Generated**
   - Run: `npx prisma generate`
   - Check: `package.json` postinstall script

2. **Redis Connection Failed**
   - Check: `REDIS_URL` environment variable
   - Verify: Redis server is accessible

3. **Supabase Auth Errors**
   - Check: `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - Verify: RLS policies are configured

4. **Build Errors**
   - Run: `npm run clean-prisma && npm install`
   - Check: Node.js version (20+)

---

*Last Updated: 2025-01-27*









