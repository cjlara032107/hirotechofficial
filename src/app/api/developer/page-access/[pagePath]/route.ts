import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * PATCH /api/developer/page-access/[pagePath]
 * Update page access setting for a specific page
 */
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ pagePath: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check developer role
    if (session.user.role !== 'DEVELOPER') {
      return NextResponse.json(
        { error: 'Forbidden - Developer access required' },
        { status: 403 }
      );
    }

    const { pagePath } = await params;
    const decodedPagePath = decodeURIComponent(pagePath);
    const body = await request.json();
    const { isEnabled } = body;

    if (typeof isEnabled !== 'boolean') {
      return NextResponse.json(
        { error: 'isEnabled must be a boolean' },
        { status: 400 }
      );
    }

    const pageAccess = await prisma.pageAccess.update({
      where: {
        userId_pagePath: {
          userId: session.user.id,
          pagePath: decodedPagePath,
        },
      },
      data: {
        isEnabled,
      },
    });

    return NextResponse.json(pageAccess);
  } catch (error) {
    console.error('Update page access error:', error);
    
    // Handle not found
    if ((error as { code?: string })?.code === 'P2025') {
      return NextResponse.json(
        { error: 'Page access not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(
      { error: 'Failed to update page access' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/developer/page-access/[pagePath]
 * Delete page access setting (reset to default enabled)
 */
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ pagePath: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check developer role
    if (session.user.role !== 'DEVELOPER') {
      return NextResponse.json(
        { error: 'Forbidden - Developer access required' },
        { status: 403 }
      );
    }

    const { pagePath } = await params;
    const decodedPagePath = decodeURIComponent(pagePath);

    await prisma.pageAccess.delete({
      where: {
        userId_pagePath: {
          userId: session.user.id,
          pagePath: decodedPagePath,
        },
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete page access error:', error);
    
    // Handle not found
    if ((error as { code?: string })?.code === 'P2025') {
      return NextResponse.json(
        { error: 'Page access not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(
      { error: 'Failed to delete page access' },
      { status: 500 }
    );
  }
}

