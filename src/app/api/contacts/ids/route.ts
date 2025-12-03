import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma as defaultPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';

/**
 * GET /api/contacts/ids - Get all contact IDs matching filters
 * Used for "select all across pagination" feature
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const search = searchParams.get('search');
    const tags = searchParams.get('tags');
    const stageId = searchParams.get('stageId');
    const platform = searchParams.get('platform');
    const scoreRange = searchParams.get('scoreRange');
    const dateFrom = searchParams.get('dateFrom');
    const dateTo = searchParams.get('dateTo');
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
        console.error('[Contacts IDs API] Error checking default database for pages:', error);
      }
    }

    // Build where clause - filter contacts by page IDs if available
    // If no pages found, query by organizationId directly (contacts might not have facebookPageId set)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const where: Record<string, any> = {
      ...(userPageIds.length > 0 
        ? { facebookPageId: { in: userPageIds } }
        : { organizationId: session.user.organizationId } // Fallback: query by organizationId if no pages found
      ),
    };

    // Apply same filters as main contacts query
    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
      ];
    }

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

    if (platform === 'messenger') {
      where.hasMessenger = true;
    } else if (platform === 'instagram') {
      where.hasInstagram = true;
    } else if (platform === 'both') {
      where.hasMessenger = true;
      where.hasInstagram = true;
    }

    if (scoreRange) {
      const [min, max] = scoreRange.split('-').map(Number);
      if (!isNaN(min) && !isNaN(max)) {
        where.leadScore = {
          gte: min,
          lte: max,
        };
      }
    }

    if (dateFrom || dateTo) {
      where.createdAt = {};
      if (dateFrom) {
        where.createdAt.gte = new Date(dateFrom);
      }
      if (dateTo) {
        const endDate = new Date(dateTo);
        endDate.setHours(23, 59, 59, 999);
        where.createdAt.lte = endDate;
      }
    }

    // Get all matching contact IDs
    let contacts = await prisma.contact.findMany({
      where,
      select: { id: true },
      orderBy: { createdAt: 'desc' },
    });

    // If no contacts found and multi-DB is enabled, try checking the default database
    if (contacts.length === 0 && process.env.ENABLE_MULTI_DB === 'true') {
      console.log('[Contacts IDs API] No contacts found in routed database, checking default database:', {
        organizationId: session.user.organizationId,
      });
      
      try {
        const defaultContacts = await defaultPrisma.contact.findMany({
          where,
          select: { id: true },
          orderBy: { createdAt: 'desc' },
        });
        
        if (defaultContacts.length > 0) {
          console.log('[Contacts IDs API] Found contacts in default database:', {
            count: defaultContacts.length,
            organizationId: session.user.organizationId,
          });
          contacts = defaultContacts;
        }
      } catch (defaultDbError) {
        console.error('[Contacts IDs API] Error checking default database:', defaultDbError);
      }
    }

    return NextResponse.json({
      contactIds: contacts.map((c) => c.id),
      total: contacts.length,
    });
  } catch (error) {
    const err = error as Error;
    console.error('Get contact IDs error:', err);
    return NextResponse.json(
      { error: 'Failed to fetch contact IDs' },
      { status: 500 }
    );
  }
}

