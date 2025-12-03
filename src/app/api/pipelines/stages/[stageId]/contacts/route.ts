import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ stageId: string }> }
) {
  try {
    const { stageId } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const search = searchParams.get('search');
    const page = parseInt(searchParams.get('page') || '1');
    // Reduced default page size for better performance
    const limit = parseInt(searchParams.get('limit') || '25');

    // Verify stage belongs to user's organization
    const stage = await prisma.pipelineStage.findFirst({
      where: {
        id: stageId,
        pipeline: {
          organizationId: session.user.organizationId,
        },
      },
    });

    if (!stage) {
      return NextResponse.json({ error: 'Stage not found' }, { status: 404 });
    }

    const where = {
      stageId: stageId,
      ...(search && {
        OR: [
          { firstName: { contains: search, mode: 'insensitive' as const } },
          { lastName: { contains: search, mode: 'insensitive' as const } },
        ],
      }),
    };

    // Get sort parameter (default to leadScore)
    const sortBy = searchParams.get('sort') || 'leadScore';
    const sortOrder = searchParams.get('order') || 'desc';

    // Determine orderBy based on sort parameter
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let orderBy: any;
    switch (sortBy) {
      case 'leadScore':
        // Primary sort by lead score (highest first), secondary by stage entry time
        orderBy = [
          { leadScore: sortOrder as 'asc' | 'desc' },
          { stageEnteredAt: 'desc' as const }
        ];
        break;
      case 'stageEnteredAt':
        orderBy = { stageEnteredAt: sortOrder as 'asc' | 'desc' };
        break;
      case 'name':
        orderBy = { firstName: sortOrder as 'asc' | 'desc' };
        break;
      default:
        orderBy = [
          { leadScore: 'desc' as const },
          { stageEnteredAt: 'desc' as const }
        ];
    }

    const [contacts, total] = await Promise.all([
      prisma.contact.findMany({
        where,
        take: limit,
        skip: (page - 1) * limit,
        orderBy,
        select: {
          id: true,
          firstName: true,
          lastName: true,
          profilePicUrl: true,
          leadScore: true,
          leadStatus: true,
          tags: true,
          stageEnteredAt: true,
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
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error: unknown) {
    console.error('Get stage contacts error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch contacts';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

