import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';
import { logger } from '@/lib/utils/logger';
import { logRequest, logResponse } from '@/lib/utils/request-logger';
import { RateLimitPresets } from '@/lib/api/rate-limit';
import { NumericPresets } from '@/lib/api/validate-numeric';

export async function GET(request: NextRequest) {
  const startTime = Date.now();
  logRequest(request);
  
  let session: Awaited<ReturnType<typeof auth>> = null;

  try {
    // Apply rate limiting
    const rateLimitResponse = await RateLimitPresets.standard(request);
    if (rateLimitResponse) {
      logResponse(request, rateLimitResponse, startTime);
      return rateLimitResponse;
    }

    // Ensure Prisma is connected before queries
    await connectPrisma();
    
    session = await auth();
    if (!session?.user) {
      const response = NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      logResponse(request, response, startTime);
      return response;
    }

    logRequest(request, {
      userId: session.user.id,
      organizationId: session.user.organizationId,
    });

    const searchParams = request.nextUrl.searchParams;
    const pageParam = searchParams.get('page') || '1';
    const limitParam = searchParams.get('limit') || '25';

    // Validate numeric pagination parameters
    const pageValidation = NumericPresets.pageNumber(pageParam, 'Page');
    if (!pageValidation.valid) {
      return NextResponse.json(
        { error: pageValidation.errors.join(', ') },
        { status: 400 }
      );
    }

    const limitValidation = NumericPresets.limit(limitParam, 100, 'Limit');
    if (!limitValidation.valid) {
      return NextResponse.json(
        { error: limitValidation.errors.join(', ') },
        { status: 400 }
      );
    }

    const page = pageValidation.value!;
    const limit = limitValidation.value!;
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
    let orderBy: any = { createdAt: 'desc' as 'asc' | 'desc' };
    if (sortBy === 'name') {
      orderBy = { firstName: sortOrder };
    } else if (sortBy === 'score') {
      orderBy = { leadScore: sortOrder };
    } else if (sortBy === 'date') {
      orderBy = { createdAt: sortOrder };
    } else if (sortBy === 'priority') {
      // Auto-prioritization: Hot leads first, Urgent next, Waiting reply, Low intent last
      // Priority order: conversion probability → lead score → last interaction
      orderBy = [
        { conversionProbability: 'desc' },
        { leadScore: 'desc' },
        { lastInteraction: 'desc' },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ] as any;
    }

    // Optimize for large-scale queries (10,000+ contacts)
    // Use cursor-based pagination hint for very large datasets
    // For now, we'll use offset pagination but optimize the query
    
    // For large datasets, we can use a more efficient count strategy
    // Only count if we're on the first page or if explicitly needed
    const shouldCount = page === 1 || searchParams.get('includeCount') === 'true';
    
    const [contacts, total] = await Promise.all([
      prisma.contact.findMany({
        where,
        skip,
        take: limit,
        orderBy,
        // Optimize select to only fetch needed fields
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
          conversionProbability: true,
          buyerIntent: true,
          sentiment: true,
          nextBestAction: true,
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
      // For very large datasets, we can skip count on later pages
      // This significantly improves performance for 10,000+ contacts
      shouldCount 
        ? prisma.contact.count({ where })
        : Promise.resolve(0), // Return 0 if we skip count, frontend will handle
    ]);

    // For large datasets where count was skipped, estimate pages
    // This allows pagination to work even without exact count
    const estimatedPages = total > 0 
      ? Math.ceil(total / limit)
      : (contacts.length === limit ? page + 1 : page); // If we got a full page, there might be more

    const response = NextResponse.json({
      contacts,
      pagination: {
        total: total || (contacts.length > 0 ? (page - 1) * limit + contacts.length : 0),
        page,
        limit,
        pages: estimatedPages,
        // Indicate if count was estimated (for very large datasets)
        countEstimated: !shouldCount && total === 0 && contacts.length === limit,
      },
    });

    logResponse(request, response, startTime, {
      userId: session.user.id,
      organizationId: session.user.organizationId,
    });

    logger.info('Contacts fetched successfully', {
      count: contacts.length,
      total,
      page,
      limit,
      organizationId: session.user.organizationId,
    });

    return response;
  } catch (error: unknown) {
    // Get session for error logging (may not be available if error occurred before auth)
    let session = null;
    try {
      session = await auth();
    } catch {
      // Ignore auth errors in error handler
    }

    logger.error('Get contacts error', error instanceof Error ? error : new Error(String(error)), {
      operation: 'get_contacts',
      organizationId: session?.user?.organizationId,
    });
    
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    const errorResponse = NextResponse.json(
      { error: 'Failed to fetch contacts. Please try again.' },
      { status: 500 }
    );
    
    logResponse(request, errorResponse, startTime, {
      userId: session?.user?.id,
      organizationId: session?.user?.organizationId,
    });
    
    return errorResponse;
  }
}

