import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    // Ensure Prisma is connected before queries
    await connectPrisma();
    
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '50');
    const search = searchParams.get('search');
    const tags = searchParams.get('tags');
    const stageId = searchParams.get('stageId');
    const platform = searchParams.get('platform');
    const scoreRange = searchParams.get('scoreRange');
    const dateFrom = searchParams.get('dateFrom');
    const dateTo = searchParams.get('dateTo');
    const sortBy = searchParams.get('sortBy') || 'date';
    const sortOrder = (searchParams.get('sortOrder') || 'desc') as 'asc' | 'desc';

    const skip = (page - 1) * limit;

    const pageId = searchParams.get('pageId');

    // Using Record for flexible Prisma where clause
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const where: Record<string, any> = {
      organizationId: session.user.organizationId,
    };

    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
      ];
    }

    // Filter by multiple tags
    if (tags) {
      const tagsArray = tags.split(',').filter(Boolean);
      if (tagsArray.length > 0) {
        where.AND = tagsArray.map((tag) => ({
          tags: { has: tag },
        }));
      }
    }

    if (stageId) {
      where.stageId = stageId;
    }

    if (pageId) {
      where.facebookPageId = pageId;
    }

    // Filter by platform
    if (platform === 'messenger') {
      where.hasMessenger = true;
    } else if (platform === 'instagram') {
      where.hasInstagram = true;
    } else if (platform === 'both') {
      where.hasMessenger = true;
      where.hasInstagram = true;
    }

    // Filter by score range
    if (scoreRange) {
      const [min, max] = scoreRange.split('-').map(Number);
      if (!isNaN(min) && !isNaN(max)) {
        where.leadScore = {
          gte: min,
          lte: max,
        };
      }
    }

    // Date range filtering (filter by createdAt date)
    if (dateFrom || dateTo) {
      where.createdAt = {};
      if (dateFrom) {
        where.createdAt.gte = new Date(dateFrom);
      }
      if (dateTo) {
        // Add 1 day to include the entire end date
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999);
        where.createdAt.lte = endDate;
      }
    }

    // Determine orderBy based on sortBy parameter
    type OrderByClause = 
      | { createdAt: 'asc' | 'desc' }
      | { firstName: 'asc' | 'desc' }
      | { leadScore: 'asc' | 'desc' };

    let orderBy: OrderByClause = { createdAt: 'desc' as 'asc' | 'desc' };
    if (sortBy === 'name') {
      orderBy = { firstName: sortOrder };
    } else if (sortBy === 'score') {
      orderBy = { leadScore: sortOrder };
    } else if (sortBy === 'date') {
      orderBy = { createdAt: sortOrder };
    }

    const [contacts, total] = await Promise.all([
      prisma.contact.findMany({
        where,
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

    return NextResponse.json({
      contacts,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error: unknown) {
    console.error('Get contacts error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch contacts';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

