import { Suspense } from 'react';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { EmptyState } from '@/components/ui/empty-state';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { Button } from '@/components/ui/button';
import { ContactsSearch } from '@/components/contacts/contacts-search';
import { DateRangeFilter } from '@/components/contacts/date-range-filter';
import { PageFilter } from '@/components/contacts/page-filter';
import { TagsFilter } from '@/components/contacts/tags-filter';
import { PlatformFilter } from '@/components/contacts/platform-filter';
import { ScoreFilter } from '@/components/contacts/score-filter';
import { StageFilter } from '@/components/contacts/stage-filter';
import { ContactsTable } from '@/components/contacts/contacts-table';
import { ContactsPagination } from '@/components/contacts/contacts-pagination';
import { AnalyzeAllButton } from '@/components/contacts/analyze-all-button';
import { Users, Plus } from 'lucide-react';
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
    organizationId: string;
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
  }

  const where: ContactWhereInput = {
    organizationId: session.user.organizationId,
    ...(params.search && {
      OR: [
        { firstName: { contains: params.search, mode: 'insensitive' as const } },
        { lastName: { contains: params.search, mode: 'insensitive' as const } },
      ],
    }),
  };

  // Filter by page
  if (params.pageId) {
    where.facebookPage = { id: params.pageId };
  }

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
    | { leadScore: 'asc' | 'desc' };

  let orderBy: ContactOrderBy = { createdAt: sortOrder };

  if (sortBy === 'name') {
    orderBy = { firstName: sortOrder };
  } else if (sortBy === 'score') {
    orderBy = { leadScore: sortOrder };
  }

  const [contacts, total] = await Promise.all([
    prisma.contact.findMany({
      where,
      skip,
      take: limit,
      orderBy,
      include: {
        stage: true,
        pipeline: true,
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

async function getTags() {
  const session = await auth();
  if (!session?.user) return [];

  return prisma.tag.findMany({
    where: { organizationId: session.user.organizationId },
  });
    }

async function getPipelines() {
  const session = await auth();
  if (!session?.user) return [];

  return prisma.pipeline.findMany({
    where: { organizationId: session.user.organizationId },
    include: {
      stages: {
        orderBy: { order: 'asc' },
      },
    },
  });
}

async function getFacebookPages() {
  const session = await auth();
  if (!session?.user) return [];

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
}

async function ContactsContent({ searchParams }: { searchParams: SearchParams }) {
  const [{ contacts, pagination }, tags, pipelines] = await Promise.all([
    getContacts(searchParams),
    getTags(),
    getPipelines(),
  ]);

  const hasFilters = !!(
    searchParams.search ||
    searchParams.pageId ||
    searchParams.dateFrom ||
    searchParams.tags ||
    searchParams.platform ||
    searchParams.scoreRange ||
    searchParams.stageId
  );

  if (contacts.length === 0 && !hasFilters) {
    return (
      <EmptyState
        icon={<Users className="h-12 w-12" />}
        title="No contacts yet"
        description="Connect your Facebook page and sync contacts to get started"
        action={{
          label: 'Go to Integrations',
          href: '/settings/integrations',
        }}
      />
    );
  }

  if (contacts.length === 0 && hasFilters) {
    return (
      <div className="border rounded-lg p-12 text-center">
        <Users className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
        <h3 className="text-lg font-semibold mb-2">No contacts found</h3>
        <p className="text-muted-foreground">
          Try adjusting your filters to see more results
        </p>
      </div>
    );
  }

  return (
    <>
      <ContactsTable contacts={contacts} tags={tags} pipelines={pipelines} />

      {pagination.pages > 1 && (
        <ContactsPagination
          currentPage={pagination.page}
          totalPages={pagination.pages}
          totalContacts={pagination.total}
          limit={pagination.limit}
        />
      )}
    </>
  );
}

export default async function ContactsPage({ searchParams }: ContactsPageProps) {
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
          <AnalyzeAllButton />
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
        <ContactsContent searchParams={params} />
      </Suspense>
    </div>
  );
}
