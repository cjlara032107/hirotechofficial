# Messenger Bulk - Business Messaging Platform

A comprehensive bulk messaging platform for Facebook Messenger and Instagram business communications with CRM pipelines, tag-based targeting, and campaign management.

## Features

### Core Functionality
- **Facebook Messenger & Instagram Integration** - Connect Facebook pages and Instagram business accounts
- **Auto-sync Contacts** - Automatically fetch contacts from conversations
- **Contact Management** - Complete CRM for managing contacts with tags and notes
- **Pipeline System** - Visual kanban boards for tracking leads through stages
- **Tag-based Segmentation** - Organize contacts with customizable tags
- **Bulk Campaigns** - Send targeted messages to segments with rate limiting
- **Message Tags** - Support for Facebook message tags (ACCOUNT_UPDATE, EVENT_UPDATE, etc.)
- **Real-time Inbox** - Unified inbox for Messenger and Instagram conversations
- **Activity Timeline** - Track all interactions with contacts
- **Templates** - Reusable message templates with variable support

### Technical Stack
- **Framework**: Next.js 16 with App Router
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: NextAuth.js with Supabase
- **Queue System**: BullMQ with Redis
- **UI**: shadcn/ui with Tailwind CSS
- **Real-time**: Webhooks for instant updates

## Setup Instructions

### Prerequisites
- Node.js 20+
- PostgreSQL database
- Redis server
- Facebook App with Messenger product
- Supabase account

### Environment Variables

Create a `.env.local` file with the following variables:

#### Required Variables

```env
# Database (REQUIRED)
DATABASE_URL="postgresql://user:password@localhost:5432/messenger_bulk"
DIRECT_URL="postgresql://user:password@localhost:5432/messenger_bulk"

# Supabase (REQUIRED)
NEXT_PUBLIC_SUPABASE_URL="https://your-project.supabase.co"
NEXT_PUBLIC_SUPABASE_ANON_KEY="your-anon-key"

# NextAuth (REQUIRED)
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-nextauth-secret-min-32-characters"

# Facebook App (REQUIRED)
FACEBOOK_APP_ID="your-facebook-app-id"
FACEBOOK_APP_SECRET="your-facebook-app-secret"
FACEBOOK_WEBHOOK_VERIFY_TOKEN="random-secure-token-123"
NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

#### Optional Variables

```env
# Redis (OPTIONAL - for background jobs and campaigns)
REDIS_URL="redis://localhost:6379"

# AI/ML Services (OPTIONAL)
GOOGLE_AI_API_KEY="your-google-ai-api-key"
# Can use multiple keys: GOOGLE_AI_API_KEY_2, GOOGLE_AI_API_KEY_3, etc. (up to 8)
NVIDIA_API_KEY="your-nvidia-api-key"
AI_PRIMARY_MODEL="openai/gpt-oss-120b"
AI_FAST_MODEL="openai/gpt-oss-20b"

# Encryption (OPTIONAL)
ENCRYPTION_KEY="your-32-byte-hex-encryption-key"

# Cron Jobs (OPTIONAL)
CRON_SECRET="your-cron-secret-token"

# Logging (OPTIONAL)
LOG_LEVEL="info"  # debug, info, warn, error

# Performance Tuning (OPTIONAL)
MAX_CONCURRENT_API_CALLS="50"
MAX_CONCURRENT_DB_QUERIES="30"
MAX_CONCURRENT_DB_WRITES="20"
MAX_CONCURRENT_AI_REQUESTS="50"
MAX_CONCURRENT_FACEBOOK_API="30"
MAX_CONCURRENT_FILE_IO="10"
MAX_CONCURRENT_NETWORK="50"

# Memory Management (OPTIONAL)
MEMORY_WARNING_THRESHOLD="70"
MEMORY_CRITICAL_THRESHOLD="85"
MEMORY_MAX_HEAP_MB=""
MEMORY_CHECK_INTERVAL="5000"
GC_INTERVAL="100"

# Socket.io (OPTIONAL)
NEXT_PUBLIC_SOCKET_URL="http://localhost:3000"
```

**Note**: For a complete list of all environment variables with descriptions, see the `.env.example` file (if available) or check the codebase for `process.env.*` references.

### Installation

1. Install dependencies:
```bash
npm install
```

2. Set up the database:
```bash
npx prisma generate
npx prisma db push
```

3. Run the development server:
```bash
npm run dev
```

4. Start the BullMQ worker (in separate terminal):
```bash
node -r esbuild-register src/lib/campaigns/worker.ts
```

5. Open [http://localhost:3000](http://localhost:3000)

### Facebook App Setup

1. **Create Facebook App**
   - Go to https://developers.facebook.com
   - Create a new app
   - Add "Messenger" product

2. **Configure Webhook**
   - Webhook URL: `https://your-domain.com/api/webhooks/facebook`
   - Verify Token: Use the value from `FACEBOOK_WEBHOOK_VERIFY_TOKEN`
   - Subscribe to: messages, messaging_postbacks, message_deliveries, message_reads

3. **Get Permissions**
   - Request these permissions: `pages_messaging`, `pages_manage_metadata`, `instagram_basic`, `instagram_manage_messages`

4. **Generate Tokens**
   - Use Graph API Explorer to generate a user access token
   - Get your page ID from page settings

5. **Connect in App**
   - Navigate to Settings > Integrations
   - Enter your user access token and page ID
   - Click "Connect Facebook Page"

## Usage Guide

### 1. Connect Facebook Page
- Go to Settings > Integrations
- Enter your Facebook user access token and page ID
- System will automatically detect Instagram if connected
- Click "Sync Contacts" to import existing conversations

### 2. Organize Contacts
- **Tags**: Create tags to segment contacts (VIP, Hot Lead, etc.)
- **Pipelines**: Set up sales or support pipelines with custom stages
- **Activity Timeline**: View all interactions with each contact

### 3. Create Campaign
- Navigate to Campaigns > New Campaign
- Select platform (Messenger or Instagram)
- Choose message tag (optional, for sending outside 24hr window)
- Select target audience by tags or pipeline stages
- Write message with personalization variables: `{firstName}`, `{lastName}`, `{name}`
- Set rate limit (messages per hour)
- Launch campaign

### 4. Monitor Results
- View delivery, read, and reply rates
- Track campaign progress in real-time
- Check failed messages and retry if needed

### 5. Manage Inbox
- View all conversations in unified inbox
- Filter by platform and status
- Respond to messages directly

## Message Tag Guidelines

### CONFIRMED_EVENT_UPDATE
✅ Use for: Event reminders, appointment confirmations, schedule changes
❌ Don't use for: Promotional content, marketing messages

### POST_PURCHASE_UPDATE
✅ Use for: Order confirmations, shipping updates, receipts
❌ Don't use for: Cross-selling, upselling

### ACCOUNT_UPDATE
✅ Use for: Password resets, payment issues, security alerts
❌ Don't use for: General notifications, promotions

### HUMAN_AGENT
✅ Use for: Active customer support conversations
❌ Don't use for: Automated broadcasts

## API Routes

### Authentication
- `POST /api/auth/register` - Register new user and organization
- `POST /api/auth/[...nextauth]` - NextAuth handlers

### Facebook Integration
- `POST /api/facebook/auth` - Connect Facebook page
- `POST /api/facebook/sync` - Sync contacts from Facebook
- `POST /api/webhooks/facebook` - Facebook webhook receiver

### Contacts
- `GET /api/contacts` - List contacts with filters
- `GET /api/contacts/[id]` - Get contact details
- `PATCH /api/contacts/[id]` - Update contact
- `POST /api/contacts/[id]/tags` - Add tag to contact
- `DELETE /api/contacts/[id]/tags` - Remove tag from contact
- `POST /api/contacts/[id]/move` - Move contact to different stage

### Tags
- `GET /api/tags` - List all tags
- `POST /api/tags` - Create new tag
- `PATCH /api/tags/[id]` - Update tag
- `DELETE /api/tags/[id]` - Delete tag

### Pipelines
- `GET /api/pipelines` - List all pipelines
- `POST /api/pipelines` - Create new pipeline
- `GET /api/pipelines/[id]` - Get pipeline with stages
- `DELETE /api/pipelines/[id]` - Delete pipeline

### Campaigns
- `GET /api/campaigns` - List all campaigns
- `POST /api/campaigns` - Create new campaign
- `POST /api/campaigns/[id]/send` - Start campaign

### Templates
- `GET /api/templates` - List all templates
- `POST /api/templates` - Create new template

### Conversations
- `GET /api/conversations` - List all conversations

## Deployment

### Vercel Deployment

1. **Push to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git push origin main
```

2. **Deploy to Vercel**
- Import project from GitHub
- Add environment variables
- Deploy

3. **Set up PostgreSQL**
- Use Supabase or other PostgreSQL provider
- Update `DATABASE_URL` in Vercel environment variables
- Run migrations: `npx prisma db push`

4. **Set up Redis**
- Use Upstash Redis or Railway
- Update `REDIS_URL` in Vercel environment variables

5. **Configure Facebook Webhook**
- Update webhook URL in Facebook App settings to your Vercel domain
- Test webhook connection

6. **Run Worker**
- Deploy worker as separate service or use Vercel cron jobs
- Ensure Redis connection is configured

## Production Checklist

- [ ] Environment variables configured in Vercel
- [ ] Database migrations run
- [ ] Redis instance connected
- [ ] Facebook app approved and live
- [ ] Webhook URL configured and verified
- [ ] BullMQ worker running
- [ ] Domain SSL configured
- [ ] Error monitoring set up (✅ Built-in monitoring available)
- [ ] Backup strategy configured
- [ ] Rate limiting tested
- [ ] Load testing completed

## Monitoring & Observability

The platform includes comprehensive monitoring capabilities:

- **Error Rate Monitoring**: Track errors by type, code, and time window
- **Performance Metrics**: Database queries, memory, CPU, and network usage
- **User Feedback**: Aggregate and analyze user feedback with sentiment analysis
- **Resource Usage**: Monitor CPU, memory, network, and disk usage
- **Production Issues**: Document and track production incidents

See [Monitoring Guide](./docs/MONITORING_GUIDE.md) for detailed documentation.

### Quick Start

```bash
# Get system metrics
GET /api/monitoring/metrics

# Get error rates
GET /api/monitoring/error-rates?timeWindow=24h

# Get user feedback
GET /api/monitoring/user-feedback?timeWindow=30d

# Get resource usage
GET /api/monitoring/resource-usage

# List production issues
GET /api/monitoring/production-issues
```

## Development

### Project Structure
```
src/
├── app/                    # Next.js app directory
│   ├── (auth)/            # Authentication pages
│   ├── (dashboard)/       # Dashboard pages
│   └── api/               # API routes
├── components/            # React components
│   ├── ui/               # shadcn components
│   ├── layout/           # Layout components
│   ├── contacts/         # Contact components
│   ├── campaigns/        # Campaign components
│   ├── pipelines/        # Pipeline components
│   └── tags/             # Tag components
├── lib/                  # Utility functions
│   ├── facebook/        # Facebook API integration
│   ├── campaigns/       # Campaign logic
│   ├── pipelines/       # Pipeline templates
│   └── supabase/        # Supabase clients
└── types/               # TypeScript types
```

### Key Files
- `prisma/schema.prisma` - Database schema
- `src/lib/auth.ts` - NextAuth configuration
- `src/lib/db.ts` - Prisma client
- `src/middleware.ts` - Authentication middleware
- `src/lib/campaigns/worker.ts` - BullMQ message worker

## Troubleshooting

### 🚨 Getting 500 Internal Server Error?

**Quick Fix:**
```bash
.\quick-fix.bat
```

See: [HOW_TO_FIX_500_ERROR.md](./HOW_TO_FIX_500_ERROR.md)

### 📚 Comprehensive Guides

- **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - Complete troubleshooting guide with solutions for common issues
- **[PERFORMANCE_EXPECTATIONS.md](./PERFORMANCE_EXPECTATIONS.md)** - Performance benchmarks and expected behavior
- **[LIMITATIONS_AND_KNOWN_ISSUES.md](./LIMITATIONS_AND_KNOWN_ISSUES.md)** - Platform limitations and known issues
- **[FIX_INTERNAL_SERVER_ERROR.md](./FIX_INTERNAL_SERVER_ERROR.md)** - Detailed fix instructions
- **[DIAGNOSIS_SUMMARY.md](./DIAGNOSIS_SUMMARY.md)** - Root cause analysis

### 🔧 Diagnostic Tools

```bash
# Run full system diagnostics
npm run diagnose

# Clean and regenerate Prisma
npm run clean-prisma
npm run prisma:generate

# Full reset
npm run reset
```

### Common Issues

**1. 500 Internal Server Error**
- **Cause:** Prisma client locked by Node processes
- **Fix:** Run `.\quick-fix.bat`
- **Prevention:** Always use Ctrl+C to stop servers

**1a. JSON Parse Error (Console)**
- **Error:** `Unexpected token '<', "<!DOCTYPE "... is not valid JSON`
- **Cause:** Client trying to parse HTML as JSON
- **Fix:** ✅ Already fixed! Content-type validation added
- **See:** `JSON_PARSE_ERROR_FIX_COMPLETE.md`

**2. Webhook not receiving events**
- Verify webhook URL in Facebook App settings
- Check verify token matches environment variable
- Ensure webhook is subscribed to correct events

**3. Messages not sending**
- Check Facebook page permissions
- Verify message tag is appropriate for use case
- Check if contacts are within 24-hour window (if no tag)

**4. Campaign stuck in SENDING**
- Check BullMQ worker is running
- Verify Redis connection
- Check worker logs for errors

**5. Contact sync not working**
- Verify Facebook page access token is valid
- Check token has required permissions
- Review API error logs

**6. Environment variable issues**
- Ensure `.env.local` exists
- Check all required variables are set
- Run `npm run diagnose` to verify

## License

MIT

## Support

For issues and questions, please open an issue on GitHub.
# hiro
# hirotechofficial
