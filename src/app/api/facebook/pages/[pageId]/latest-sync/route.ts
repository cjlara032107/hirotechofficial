import { NextRequest, NextResponse } from 'next/server';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { getLatestSyncJob } from '@/lib/facebook/background-sync';
import { requireAuth } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ pageId: string }> }
) {
  try {
    // Validate session with token expiration handling
    const authResult = await requireAuth();
    if ('error' in authResult) {
      return authResult.error;
    }
    const { session } = authResult;

    let { pageId } = await props.params;

    // Validate pageId format
    if (!pageId || typeof pageId !== 'string' || pageId.trim().length === 0) {
      return NextResponse.json(
        { error: 'Invalid page ID' },
        { status: 400 }
      );
    }

    pageId = pageId.trim();

    // Validate UUID format
    const uuidValidation = validateUUID(pageId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: uuidValidation.error.message },
        { status: uuidValidation.error.status }
      );
    }

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);

    console.log('[Latest Sync API] Looking for page:', {
      pageId,
      organizationId: session.user.organizationId,
    });

    // First check if the page exists in the routed database
    let page = await prisma.facebookPage.findFirst({
      where: {
        id: pageId,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        pageId: true,
        pageName: true,
        organizationId: true,
      },
    });

    // If not found and multi-DB is enabled, try checking the default database as fallback
    if (!page && process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const { prisma: defaultPrisma } = await import('@/lib/db');
        const pageInDefault = await defaultPrisma.facebookPage.findFirst({
          where: { id: pageId },
          select: { id: true, organizationId: true },
        });
        
        if (pageInDefault) {
          if (pageInDefault.organizationId !== session.user.organizationId) {
            console.error('[Latest Sync API] Page belongs to different organization:', {
              pageId,
              pageOrganizationId: pageInDefault.organizationId,
              userOrganizationId: session.user.organizationId,
            });
            return NextResponse.json(
              { error: 'Forbidden: You do not have access to this page. This page belongs to a different organization.' },
              { status: 403 }
            );
          }
          console.warn('[Latest Sync API] Page found in default database but not in routed database. This may indicate a routing issue.');
          // Use the page from default database
          page = await defaultPrisma.facebookPage.findFirst({
            where: { id: pageId },
            select: { id: true, pageId: true, pageName: true, organizationId: true },
          });
        }
      } catch (fallbackError) {
        console.error('[Latest Sync API] Error checking default database:', fallbackError);
      }
    }

    if (!page) {
      console.warn('[Latest Sync API] Page not found:', {
        pageId,
        organizationId: session.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      return NextResponse.json({ error: 'Page not found' }, { status: 404 });
    }

    console.log('[Latest Sync API] Found page:', {
      databaseId: page.id,
      facebookPageId: page.pageId,
      pageName: page.pageName,
    });

    const latestJob = await getLatestSyncJob(pageId);

    if (!latestJob) {
      return NextResponse.json({ job: null });
    }

    return NextResponse.json({
      job: {
        id: latestJob.id,
        status: latestJob.status,
        syncedContacts: latestJob.syncedContacts,
        failedContacts: latestJob.failedContacts,
        totalContacts: latestJob.totalContacts,
        tokenExpired: latestJob.tokenExpired,
        startedAt: latestJob.startedAt,
        completedAt: latestJob.completedAt,
      createdAt: latestJob.createdAt,
    },
  });
  } catch (error) {
    console.error('Error fetching latest sync job:', error);
    return NextResponse.json(
      { error: 'Failed to fetch latest sync job' },
      { status: 500 }
    );
  }
}

