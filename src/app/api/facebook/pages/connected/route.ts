import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';

// Force dynamic rendering to prevent static generation issues
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * GET - Fetch organization's connected Facebook pages
 */
export async function GET(request: NextRequest) {
  try {
    // Step 1: Connect to database
    try {
      await connectPrisma();
    } catch (dbError) {
      console.error('[Connected Pages] Database connection error:', dbError);
      return NextResponse.json(
        { error: 'Database connection failed. Please try again.' },
        { 
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    // Step 2: Get session
    let session;
    try {
      session = await auth();
      console.log('[Connected Pages] Session check:', {
        hasSession: !!session,
        hasUser: !!session?.user,
        userId: session?.user?.id,
        organizationId: session?.user?.organizationId,
      });
    } catch (authError) {
      console.error('[Connected Pages] Auth error:', authError);
      return NextResponse.json(
        { error: 'Authentication failed. Please log in again.' },
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
    
    if (!session?.user) {
      console.warn('[Connected Pages] No session or user found');
      return NextResponse.json(
        { error: 'Unauthorized. Please log in again.' },
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Step 3: Validate organizationId
    if (!session.user.organizationId) {
      console.error('[Connected Pages] User missing organizationId:', {
        userId: session.user.id,
        email: session.user.email,
      });
      return NextResponse.json(
        { error: 'User organization not found. Please complete your profile.' },
        { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Step 4: Fetch pages
    let pages;
    try {
      // Use getPrismaForOrg to route to correct database when multi-DB is enabled
      const prisma = getPrismaForOrg(session.user.organizationId);
      pages = await prisma.facebookPage.findMany({
        where: {
          organizationId: session.user.organizationId,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
    } catch (queryError) {
      console.error('[Connected Pages] Query error:', queryError);
      return NextResponse.json(
        { error: 'Failed to fetch pages from database' },
        { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Map database fields to frontend-expected format
    // ConnectedPagesList expects: id (database ID), pageId (Facebook page ID), pageName
    const mappedPages = pages.map(page => ({
      id: page.id, // Database ID (used for API calls)
      pageId: page.pageId, // Facebook page ID
      pageName: page.pageName,
      instagramAccountId: page.instagramAccountId,
      instagramUsername: page.instagramUsername,
      isActive: page.isActive,
      lastSyncedAt: page.lastSyncedAt?.toISOString() || null,
      autoSync: page.autoSync,
      autoPipelineId: page.autoPipelineId,
    }));

    return NextResponse.json(
      { pages: mappedPages },
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    // Catch-all for any unexpected errors
    console.error('[Connected Pages] Unexpected error:', {
      message: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      error,
    });
    
    const errorMessage = error instanceof Error 
      ? error.message 
      : 'Failed to fetch connected pages';
    
    // Always return JSON, never HTML - this prevents Next.js from rendering error pages
    return NextResponse.json(
      { 
        error: errorMessage,
        ...(process.env.NODE_ENV === 'development' && {
          details: error instanceof Error ? error.stack : undefined
        })
      },
      { 
        status: 500,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  }
}

