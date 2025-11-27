import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startBackgroundSync } from '@/lib/facebook/background-sync';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { facebookPageId } = body;

    if (!facebookPageId) {
      return NextResponse.json(
        { error: 'Missing facebookPageId' },
        { status: 400 }
      );
    }

    // Verify the page belongs to the user's organization
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: facebookPageId,
        organizationId: session.user.organizationId,
      },
    });

    if (!page) {
      return NextResponse.json(
        { error: 'Facebook page not found' },
        { status: 404 }
      );
    }

    const result = await startBackgroundSync(facebookPageId);
    
    // CRITICAL: Use Vercel's waitUntil to keep the function alive for background tasks
    // This ensures the background promise continues executing after the response is sent
    if ('waitUntil' in request) {
      // Store the background promise and wait for it
      const backgroundPromise = (globalThis as any).__activeSyncPromises?.values().next().value;
      if (backgroundPromise) {
        (request as any).waitUntil(backgroundPromise);
      }
    }

    return NextResponse.json(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to start sync';
    console.error('Background sync error:', error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

