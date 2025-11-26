import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPageAccessStatus } from '@/lib/developer/get-page-access';

/**
 * GET /api/developer/page-access/check
 * Check if a page is enabled for the current user
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const searchParams = request.nextUrl.searchParams;
    const pagePath = searchParams.get('path');

    if (!pagePath) {
      return NextResponse.json(
        { error: 'path parameter is required' },
        { status: 400 }
      );
    }

    const isEnabled = await getPageAccessStatus(session.user.id, pagePath);

    return NextResponse.json({
      pagePath,
      isEnabled: isEnabled !== false, // Return true if null (default enabled) or true
    });
  } catch (error) {
    console.error('Check page access error:', error);
    return NextResponse.json(
      { error: 'Failed to check page access' },
      { status: 500 }
    );
  }
}



