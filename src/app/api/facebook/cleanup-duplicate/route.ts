import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * Cleanup endpoint to handle duplicate Facebook pages
 * This helps when pages are stuck in the database from previous connections
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    
    if (!session?.user?.organizationId) {
      return NextResponse.json({ 
        error: 'Unauthorized',
      }, { status: 401 });
    }

    const body = await request.json();
    const { pageId, action } = body;

    if (!pageId) {
      return NextResponse.json({
        error: 'Missing pageId',
      }, { status: 400 });
    }

    // Find the page
    const page = await prisma.facebookPage.findFirst({
      where: { 
        pageId,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        pageId: true,
        pageName: true,
        organizationId: true,
        isActive: true,
      },
    });

    if (!page) {
      return NextResponse.json({
        error: 'Page not found in database',
        pageId,
      }, { status: 404 });
    }

    // Action: Take ownership (transfer to current org)
    if (action === 'take-ownership') {
      const updated = await prisma.facebookPage.update({
        where: { id: page.id },
        data: {
          organizationId: session.user.organizationId,
          updatedAt: new Date(),
        },
      });

      return NextResponse.json({
        success: true,
        message: `Page "${page.pageName}" transferred to your organization`,
        page: {
          id: updated.id,
          pageId: updated.pageId,
          pageName: updated.pageName,
        },
      });
    }

    // Action: Delete (if belongs to current org)
    if (action === 'delete') {
      if (page.organizationId !== session.user.organizationId) {
        return NextResponse.json({
          error: 'Cannot delete page from another organization',
          currentOrg: session.user.organizationId,
          pageOrg: page.organizationId,
        }, { status: 403 });
      }

      await prisma.facebookPage.delete({
        where: { id: page.id },
      });

      return NextResponse.json({
        success: true,
        message: `Page "${page.pageName}" deleted successfully`,
      });
    }

    // Action: Check status
    if (action === 'check') {
      return NextResponse.json({
        success: true,
        page: {
          id: page.id,
          pageId: page.pageId,
          pageName: page.pageName,
          organizationId: page.organizationId,
          isActive: page.isActive,
          belongsToYou: page.organizationId === session.user.organizationId,
          yourOrganizationId: session.user.organizationId,
        },
      });
    }

    return NextResponse.json({
      error: 'Invalid action. Use: check, take-ownership, or delete',
    }, { status: 400 });

  } catch (error: unknown) {
    console.error('Cleanup error:', error);
    return NextResponse.json({
      error: 'Cleanup failed',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, { status: 500 });
  }
}

/**
 * GET - List all duplicate/orphaned pages
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    
    if (!session?.user?.organizationId) {
      return NextResponse.json({ 
        error: 'Unauthorized',
      }, { status: 401 });
    }

    // Find all pages
    const allPages = await prisma.facebookPage.findMany({
      select: {
        id: true,
        pageId: true,
        pageName: true,
        organizationId: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    const yourPages = allPages.filter(p => p.organizationId === session.user.organizationId);
    const otherPages = allPages.filter(p => p.organizationId !== session.user.organizationId);

    return NextResponse.json({
      success: true,
      yourOrganizationId: session.user.organizationId,
      summary: {
        total: allPages.length,
        yours: yourPages.length,
        others: otherPages.length,
      },
      yourPages: yourPages.map(p => ({
        id: p.id,
        pageId: p.pageId,
        pageName: p.pageName,
        isActive: p.isActive,
        createdAt: p.createdAt,
      })),
      otherPages: otherPages.map(p => ({
        id: p.id,
        pageId: p.pageId,
        pageName: p.pageName,
        organizationId: p.organizationId,
        isActive: p.isActive,
        createdAt: p.createdAt,
      })),
    });

  } catch (error: unknown) {
    console.error('List pages error:', error);
    return NextResponse.json({
      error: 'Failed to list pages',
      message: error instanceof Error ? error.message : 'Unknown error',
    }, { status: 500 });
  }
}

