import { Suspense, cache } from 'react';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { Button } from '@/components/ui/button';
import { ContactsSearch } from '@/components/contacts/contacts-search';
import { DateRangeFilter } from '@/components/contacts/date-range-filter';
import { PageFilter } from '@/components/contacts/page-filter';
import { TagsFilter } from '@/components/contacts/tags-filter';
import { PlatformFilter } from '@/components/contacts/platform-filter';
import { ScoreFilter } from '@/components/contacts/score-filter';
import { StageFilter } from '@/components/contacts/stage-filter';
import { ContactsContentClient } from '@/components/contacts/contacts-content-client';
import { Plus, ShieldCheck } from 'lucide-react';
import { redirect } from 'next/navigation';
import Link from 'next/link';

interface SearchParams {
  search?: string;
  page?: string;
  pageId?: string;
  dateFrom?: string;
  dateTo?: string;
  sortBy?: string;
  sortOrder?: string;
  tags?: string;
  platform?: string;
  scoreRange?: string;
  stageId?: string;
}

interface ContactsPageProps {
  searchParams: Promise<SearchParams>;
}

export const revalidate = 60;

async function getContacts(params: SearchParams) {
  const session = await auth();
  if (!session?.user) {
    redirect('/login');
  }

  const page = parseInt(params.page || '1');
  const limit = 20;
  const skip = (page - 1) * limit;

  // Using Prisma.ContactWhereInput type would be ideal, but we'll use Record for flexibility
  interface ContactWhereInput {
    organizationId?: string;
    facebookPageId?: string | { in: string[] };
    OR?: Array<{
      firstName?: { contains: string; mode: 'insensitive' };
      lastName?: { contains: string; mode: 'insensitive' };
    }>;
    stageId?: string;
    tags?: { hasSome: string[] } | { has: string };
    facebookPage?: { id: string };
    createdAt?: {
      gte?: Date;
      lte?: Date;
    };
    AND?: Array<{
      tags: { has: string };
    }>;
    hasMessenger?: boolean;
    hasInstagram?: boolean;
    leadScore?: {
      gte?: number;
      lte?: number;
    };
    id?: string; // For impossible condition fallback
  }

  // First, get all page IDs that belong to the user's organization
  // This ensures we find contacts even if they have a different organizationId than the session
  const prisma = getPrismaForOrg(session.user.organizationId);
  const userPages = await prisma.facebookPage.findMany({
    where: {
      organizationId: session.user.organizationId,
      isActive: true,
    },
    select: { id: true },
  });
  let userPageIds = userPages.map(p => p.id);

  console.log('[Contacts Page] Found pages in routed database:', {
    organizationId: session.user.organizationId,
    pageCount: userPageIds.length,
    pageIds: userPageIds.slice(0, 5), // Log first 5
  });

  // If no pages found, also check default database as fallback
  if (userPageIds.length === 0 && process.env.ENABLE_MULTI_DB === 'true') {
    try {
      const { prisma: defaultPrisma } = await import('@/lib/db');
      const defaultPages = await defaultPrisma.facebookPage.findMany({
        where: {
          organizationId: session.user.organizationId,
          isActive: true,
        },
        select: { id: true },
      });
      const defaultPageIds = defaultPages.map(p => p.id);
      userPageIds.push(...defaultPageIds);
      console.log('[Contacts Page] Found pages in default database:', {
        organizationId: session.user.organizationId,
        pageCount: defaultPageIds.length,
        pageIds: defaultPageIds.slice(0, 5),
      });
    } catch (error) {
      console.error('[Contacts Page] Error checking default database for pages:', error);
    }
  }

  // If still no pages, check ALL databases (all 3 databases in multi-DB setup)
  if (userPageIds.length === 0 && process.env.ENABLE_MULTI_DB === 'true') {
    try {
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const allDbConfigs = router.getAllDatabaseConfigs();
      
      console.log('[Contacts Page] Checking all databases for pages:', {
        totalDatabases: allDbConfigs.length,
        organizationId: session.user.organizationId,
      });

      // Search all databases for pages
      const allPagesPromises = allDbConfigs.map(async (dbConfig, index) => {
        try {
          const pages = await dbConfig.client.facebookPage.findMany({
            where: {
              organizationId: session.user.organizationId,
              isActive: true,
            },
            select: { id: true, organizationId: true },
          });
          console.log(`[Contacts Page] Database ${index} (${dbConfig.index}): Found ${pages.length} pages`);
          return pages;
        } catch (error) {
          console.error(`[Contacts Page] Error querying database ${index}:`, error);
          return [];
        }
      });

      const allPagesResults = await Promise.all(allPagesPromises);
      const allPages = allPagesResults.flat();
      
      console.log('[Contacts Page] Found pages across all databases:', {
        totalPages: allPages.length,
        pages: allPages.slice(0, 10).map(p => ({ id: p.id, orgId: p.organizationId })),
      });
      
      // Use all pages found across all databases
      userPageIds = allPages.map(p => p.id);
    } catch (error) {
      console.error('[Contacts Page] Error finding pages across all databases:', error);
    }
  }

  // Build where clause - filter contacts by page IDs if available
  // If no pages found, query by organizationId directly (contacts might not have facebookPageId set)
  const where: ContactWhereInput = {
    ...(userPageIds.length > 0 
      ? { facebookPageId: params.pageId ? params.pageId : { in: userPageIds } }
      : { organizationId: session.user.organizationId } // Fallback: query by organizationId if no pages found
    ),
    ...(params.search && {
      OR: [
        { firstName: { contains: params.search, mode: 'insensitive' as const } },
        { lastName: { contains: params.search, mode: 'insensitive' as const } },
      ],
    }),
  };

  // Filter by date range
  if (params.dateFrom || params.dateTo) {
    where.createdAt = {};
    if (params.dateFrom) {
      where.createdAt.gte = new Date(params.dateFrom);
    }
    if (params.dateTo) {
      const endDate = new Date(params.dateTo);
      endDate.setHours(23, 59, 59, 999);
      where.createdAt.lte = endDate;
    }
  }

  // Filter by tags
  if (params.tags) {
    const tagsArray = params.tags.split(',').filter(Boolean);
    if (tagsArray.length > 0) {
      where.AND = tagsArray.map((tag) => ({
        tags: { has: tag },
      }));
    }
  }

  // Filter by platform
  if (params.platform === 'messenger') {
    where.hasMessenger = true;
  } else if (params.platform === 'instagram') {
    where.hasInstagram = true;
  } else if (params.platform === 'both') {
    where.hasMessenger = true;
    where.hasInstagram = true;
  }

  // Filter by score range
  if (params.scoreRange) {
    const [min, max] = params.scoreRange.split('-').map(Number);
    if (!isNaN(min) && !isNaN(max)) {
      where.leadScore = {
        gte: min,
        lte: max,
      };
    }
  }

  // Filter by stage
  if (params.stageId) {
    where.stageId = params.stageId;
  }

  // Determine orderBy
  const sortBy = params.sortBy || 'date';
  const sortOrder = (params.sortOrder || 'desc') as 'asc' | 'desc';

  type ContactOrderBy = 
    | { createdAt: 'asc' | 'desc' }
    | { firstName: 'asc' | 'desc' }
    | { leadScore: 'asc' | 'desc' }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    | any;

  let orderBy: ContactOrderBy = { createdAt: sortOrder };

  if (sortBy === 'name') {
    orderBy = { firstName: sortOrder };
  } else if (sortBy === 'score') {
    orderBy = { leadScore: sortOrder };
  } else if (sortBy === 'priority') {
    // Auto-prioritization: Hot leads first, Urgent next, Waiting reply, Low intent last
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    orderBy = [
      { conversionProbability: 'desc' },
      { leadScore: 'desc' },
      { lastInteraction: 'desc' },
    ] as any;
  }

  // Prisma client already obtained above when fetching pages
  console.log('[Contacts Page] Querying contacts:', {
    userPageIds: userPageIds.length,
    pageIds: userPageIds.slice(0, 5),
    whereKeys: Object.keys(where),
    whereClause: JSON.stringify(where, null, 2),
    skip,
    take: limit,
    organizationId: session.user.organizationId,
  });

  let [contacts, total] = await Promise.all([
    prisma.contact.findMany({
      where: where as any, // Use 'as any' to bypass TypeScript interface limitations
      skip,
      take: limit,
      orderBy,
      select: {
        id: true,
        firstName: true,
        lastName: true,
        profilePicUrl: true,
        hasMessenger: true,
        hasInstagram: true,
        leadScore: true,
        tags: true,
        lastInteraction: true,
        createdAt: true,
        stage: {
          select: {
            id: true,
            name: true,
            color: true,
          },
        },
        facebookPage: {
          select: {
            id: true,
            pageName: true,
            instagramUsername: true,
          },
        },
      },
    }),
    prisma.contact.count({ where }),
  ]);

  // If no contacts found and multi-DB is enabled, check ALL databases (all 3 databases)
  if (contacts.length === 0 && total === 0 && process.env.ENABLE_MULTI_DB === 'true') {
    console.log('[Contacts Page] No contacts found in routed database, checking all databases:', {
      organizationId: session.user.organizationId,
      userPageIds: userPageIds.length,
    });
    
    try {
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const allDbConfigs = router.getAllDatabaseConfigs();
      
      console.log('[Contacts Page] Searching all databases for contacts:', {
        totalDatabases: allDbConfigs.length,
      });

      // Search all databases for contacts
      const allContactsPromises = allDbConfigs.map(async (dbConfig, index) => {
        try {
          const [dbContacts, dbTotal] = await Promise.all([
            dbConfig.client.contact.findMany({
              where: where as any,
              skip,
              take: limit,
              orderBy,
              select: {
                id: true,
                firstName: true,
                lastName: true,
                profilePicUrl: true,
                hasMessenger: true,
                hasInstagram: true,
                leadScore: true,
                tags: true,
                lastInteraction: true,
                createdAt: true,
                stage: {
                  select: {
                    id: true,
                    name: true,
                    color: true,
                  },
                },
                facebookPage: {
                  select: {
                    id: true,
                    pageName: true,
                    instagramUsername: true,
                  },
                },
              },
            }),
            dbConfig.client.contact.count({ where: where as any }),
          ]);
          
          console.log(`[Contacts Page] Database ${index} (${dbConfig.index}): Found ${dbContacts.length} contacts (total: ${dbTotal})`);
          return { contacts: dbContacts, total: dbTotal };
        } catch (error) {
          console.error(`[Contacts Page] Error querying database ${index} for contacts:`, error);
          return { contacts: [], total: 0 };
        }
      });

      const allContactsResults = await Promise.all(allContactsPromises);
      
      // Combine results from all databases
      const allFoundContacts = allContactsResults.flatMap(r => r.contacts);
      const allFoundTotal = allContactsResults.reduce((sum, r) => sum + r.total, 0);
      
      if (allFoundContacts.length > 0 || allFoundTotal > 0) {
        console.log('[Contacts Page] Found contacts across all databases:', {
          contacts: allFoundContacts.length,
          total: allFoundTotal,
          organizationId: session.user.organizationId,
        });
        contacts = allFoundContacts;
        total = allFoundTotal;
      }
    } catch (allDbError) {
      console.error('[Contacts Page] Error checking all databases:', allDbError);
    }
  }

  // Final fallback: If still no contacts, try querying ALL contacts by organizationId across all databases
  // This is a last resort to find contacts that might not have facebookPageId set
  if (contacts.length === 0 && total === 0 && process.env.ENABLE_MULTI_DB === 'true') {
    console.log('[Contacts Page] Still no contacts found, trying final fallback: query by organizationId only across all databases');
    
    try {
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const allDbConfigs = router.getAllDatabaseConfigs();
      
      // Build a simpler where clause - just organizationId and other filters (no page filter)
      const fallbackWhere: any = {
        organizationId: session.user.organizationId,
        ...(params.search && {
          OR: [
            { firstName: { contains: params.search, mode: 'insensitive' } },
            { lastName: { contains: params.search, mode: 'insensitive' } },
          ],
        }),
        ...(params.stageId && { stageId: params.stageId }),
        ...(params.platform === 'messenger' && { hasMessenger: true }),
        ...(params.platform === 'instagram' && { hasInstagram: true }),
        ...(params.platform === 'both' && { hasMessenger: true, hasInstagram: true }),
        ...(params.scoreRange && (() => {
          const [min, max] = params.scoreRange.split('-').map(Number);
          if (!isNaN(min) && !isNaN(max)) {
            return { leadScore: { gte: min, lte: max } };
          }
          return {};
        })()),
      };

      const allContactsPromises = allDbConfigs.map(async (dbConfig, index) => {
        try {
          const [dbContacts, dbTotal] = await Promise.all([
            dbConfig.client.contact.findMany({
              where: fallbackWhere,
              skip,
              take: limit,
              orderBy,
              select: {
                id: true,
                firstName: true,
                lastName: true,
                profilePicUrl: true,
                hasMessenger: true,
                hasInstagram: true,
                leadScore: true,
                tags: true,
                lastInteraction: true,
                createdAt: true,
                stage: {
                  select: {
                    id: true,
                    name: true,
                    color: true,
                  },
                },
                facebookPage: {
                  select: {
                    id: true,
                    pageName: true,
                    instagramUsername: true,
                  },
                },
              },
            }),
            dbConfig.client.contact.count({ where: fallbackWhere }),
          ]);
          
          console.log(`[Contacts Page] Fallback - Database ${index} (${dbConfig.index}): Found ${dbContacts.length} contacts (total: ${dbTotal})`);
          return { contacts: dbContacts, total: dbTotal };
        } catch (error) {
          console.error(`[Contacts Page] Fallback - Error querying database ${index}:`, error);
          return { contacts: [], total: 0 };
        }
      });

      const allContactsResults = await Promise.all(allContactsPromises);
      const allFoundContacts = allContactsResults.flatMap(r => r.contacts);
      const allFoundTotal = allContactsResults.reduce((sum, r) => sum + r.total, 0);
      
      if (allFoundContacts.length > 0 || allFoundTotal > 0) {
        console.log('[Contacts Page] Found contacts in fallback query (by organizationId only):', {
          contacts: allFoundContacts.length,
          total: allFoundTotal,
          organizationId: session.user.organizationId,
        });
        contacts = allFoundContacts;
        total = allFoundTotal;
      }
    } catch (fallbackError) {
      console.error('[Contacts Page] Error in fallback query:', fallbackError);
    }
  }

  console.log('[Contacts Page] Final result:', {
    contactsFound: contacts.length,
    total,
    organizationId: session.user.organizationId,
  });

  return {
    contacts,
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
}

const getTags = cache(async () => {
  const session = await auth();
  if (!session?.user) return [];

  const prisma = getPrismaForOrg(session.user.organizationId);
  return prisma.tag.findMany({
    where: { organizationId: session.user.organizationId },
  });
});

import { getCachedPipelines } from '@/lib/cache/pipeline-cache';

// Use the centralized caching utility for pipelines
const getPipelines = cache(async () => {
  const session = await auth();
  if (!session?.user) return [];

  return getCachedPipelines(session.user.organizationId, false);
});

const getFacebookPages = cache(async () => {
  const session = await auth();
  if (!session?.user) return [];

  const prisma = getPrismaForOrg(session.user.organizationId);
  return prisma.facebookPage.findMany({
    where: {
      organizationId: session.user.organizationId,
      isActive: true,
    },
    select: {
      id: true,
      pageName: true,
      instagramUsername: true,
    },
  });
});

async function ContactsContent({ 
  searchParams, 
  tags, 
  pipelines 
}: { 
  searchParams: SearchParams;
  tags: Awaited<ReturnType<typeof getTags>>;
  pipelines: Awaited<ReturnType<typeof getPipelines>>;
}) {
  // Initial server-side data fetch for fast first load
  const initialData = await getContacts(searchParams);

  const hasFilters = !!(
    searchParams.search ||
    searchParams.pageId ||
    searchParams.dateFrom ||
    searchParams.tags ||
    searchParams.platform ||
    searchParams.scoreRange ||
    searchParams.stageId
  );

  return (
    <ContactsContentClient
      initialData={initialData}
      tags={tags}
      pipelines={pipelines}
      hasFilters={hasFilters}
    />
  );
}

export default async function ContactsPage({ searchParams }: ContactsPageProps) {
  // Check if page is disabled for current user
  const session = await auth();
  if (!session?.user?.id) {
    redirect('/login');
  }

  const { getPageAccessStatus } = await import('@/lib/developer/get-page-access');
  const pageAccess = await getPageAccessStatus(session.user.id, '/contacts');
  
  if (pageAccess === false) {
    const { default: UnderDevelopmentPage } = await import('../under-development/page');
    return <UnderDevelopmentPage searchParams={Promise.resolve({ page: '/contacts' })} />;
  }

  const params = await searchParams;
  const [facebookPages, tags, pipelines] = await Promise.all([
    getFacebookPages(),
    getTags(),
    getPipelines(),
  ]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Contacts</h1>
          <p className="text-muted-foreground mt-2">
            Manage your messenger and Instagram contacts
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" asChild>
            <Link href="/contacts/approval-queue">
              <ShieldCheck className="h-4 w-4 mr-2" />
              Approval Queue
            </Link>
          </Button>
          <Button asChild>
            <Link href="/campaigns/new">
              <Plus className="h-4 w-4 mr-2" />
              Create Campaign
            </Link>
          </Button>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <ContactsSearch />
        <DateRangeFilter />
        <PageFilter pages={facebookPages} />
        <PlatformFilter />
        <ScoreFilter />
        <StageFilter pipelines={pipelines} />
        <TagsFilter tags={tags} />
      </div>

      <Suspense
        fallback={
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        }
      >
        <ContactsContent searchParams={params} tags={tags} pipelines={pipelines} />
      </Suspense>
    </div>
  );
}
