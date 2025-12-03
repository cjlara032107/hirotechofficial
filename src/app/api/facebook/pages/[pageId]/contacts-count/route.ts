import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ pageId: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const params = await props.params;
    const { pageId } = params;

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);

    console.log('[Contacts Count API] Looking for page:', {
      pageId,
      organizationId: session.user.organizationId,
    });

    // Verify the page belongs to the user's organization
    const page = await prisma.facebookPage.findFirst({
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

    if (!page) {
      console.warn('[Contacts Count API] Page not found:', {
        pageId,
        organizationId: session.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      
      // If multi-DB is enabled, try checking the default database as fallback
      if (process.env.ENABLE_MULTI_DB === 'true') {
        try {
          const { prisma: defaultPrisma } = await import('@/lib/db');
          const pageInDefault = await defaultPrisma.facebookPage.findFirst({
            where: { id: pageId },
            select: { id: true, organizationId: true },
          });
          
          if (pageInDefault && pageInDefault.organizationId !== session.user.organizationId) {
            console.error('[Contacts Count API] Page belongs to different organization:', {
              pageId,
              pageOrganizationId: pageInDefault.organizationId,
              userOrganizationId: session.user.organizationId,
            });
            return NextResponse.json(
              { error: 'Page not found or access denied. This page belongs to a different organization.' },
              { status: 403 }
            );
          }
        } catch (fallbackError) {
          console.error('[Contacts Count API] Error checking default database:', fallbackError);
        }
      }
      
      return NextResponse.json({ error: 'Page not found' }, { status: 404 });
    }

    console.log('[Contacts Count API] Found page:', {
      databaseId: page.id,
      facebookPageId: page.pageId,
      pageName: page.pageName,
    });

    // Get contact count for this page
    const count = await prisma.contact.count({
      where: {
        facebookPageId: pageId,
        organizationId: session.user.organizationId,
      },
    });

    return NextResponse.json({ count });
  } catch (error) {
    console.error('Error fetching contact count:', error);
    return NextResponse.json(
      { error: 'Failed to fetch contact count' },
      { status: 500 }
    );
  }
}

