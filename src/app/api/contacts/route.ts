import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
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

    session = await auth();
    
    // Ensure Prisma is connected before queries (with error handling)
    try {
      await connectPrisma();
    } catch (connectError) {
      console.error('[Contacts API] Database connection error:', connectError);
      // Continue anyway - queries might still work even if connectPrisma fails
      // The actual query will fail if database is truly unavailable
    }
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

    // Get Prisma client routed to correct database based on organizationId
    const prisma = getPrismaForOrg(session.user.organizationId);

    // First, get all page IDs that belong to the user's organization
    // This ensures we find contacts even if they have a different organizationId than the session
    const userPages = await prisma.facebookPage.findMany({
      where: {
        organizationId: session.user.organizationId,
        isActive: true,
      },
      select: { id: true },
    });
    const userPageIds = userPages.map(p => p.id);

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
        userPageIds.push(...defaultPages.map(p => p.id));
      } catch (error) {
        console.error('[Contacts API] Error checking default database for pages:', error);
      }
    }

    // Build where clause - filter contacts by page IDs if available
    // If no pages found, query by organizationId directly (contacts might not have facebookPageId set)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const where: Record<string, any> = {
      ...(userPageIds.length > 0 
        ? { facebookPageId: pageId ? pageId : { in: userPageIds } }
        : { organizationId: session.user.organizationId } // Fallback: query by organizationId if no pages found
      ),
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
      // If filtering by specific page, use that page ID directly
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
    
    let [contacts, total] = await Promise.all([
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

    // If no contacts found and multi-DB is enabled, check ALL databases (all 3 databases)
    if (contacts.length === 0 && total === 0 && process.env.ENABLE_MULTI_DB === 'true') {
      console.log('[Contacts API] No contacts found in routed database, checking all databases:', {
        organizationId: session.user.organizationId,
        userPageIds: userPageIds.length,
      });
      
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allDbConfigs = router.getAllDatabaseConfigs();
        
        console.log('[Contacts API] Searching all databases for contacts:', {
          totalDatabases: allDbConfigs.length,
        });

        // Search all databases for contacts
        const allContactsPromises = allDbConfigs.map(async (dbConfig, index) => {
          try {
            const [dbContacts, dbTotal] = await Promise.all([
              dbConfig.client.contact.findMany({
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
              shouldCount 
                ? dbConfig.client.contact.count({ where })
                : Promise.resolve(0),
            ]);
            
            console.log(`[Contacts API] Database ${index} (${dbConfig.index}): Found ${dbContacts.length} contacts (total: ${dbTotal})`);
            return { contacts: dbContacts, total: dbTotal };
          } catch (error) {
            console.error(`[Contacts API] Error querying database ${index} for contacts:`, error);
            return { contacts: [], total: 0 };
          }
        });

        const allContactsResults = await Promise.all(allContactsPromises);
        
        // Combine results from all databases
        const allFoundContacts = allContactsResults.flatMap(r => r.contacts);
        const allFoundTotal = allContactsResults.reduce((sum, r) => sum + r.total, 0);
        
        if (allFoundContacts.length > 0 || allFoundTotal > 0) {
          console.log('[Contacts API] Found contacts across all databases:', {
            contacts: allFoundContacts.length,
            total: allFoundTotal,
            organizationId: session.user.organizationId,
          });
          contacts = allFoundContacts;
          total = allFoundTotal;
        }
      } catch (allDbError) {
        console.error('[Contacts API] Error checking all databases:', allDbError);
      }
    }

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

