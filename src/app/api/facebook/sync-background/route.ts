import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startBackgroundSync } from '@/lib/facebook/background-sync';
import { validateUUID } from '@/lib/api/validate-uuid';

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

    // Validate facebookPageId is valid UUID format
    if (typeof facebookPageId !== 'string') {
      return NextResponse.json(
        { error: 'facebookPageId must be a string' },
        { status: 400 }
      );
    }

    const trimmedFacebookPageId = facebookPageId.trim();
    if (trimmedFacebookPageId.length === 0) {
      return NextResponse.json(
        { error: 'facebookPageId cannot be empty' },
        { status: 400 }
      );
    }
    const uuidValidation = validateUUID(trimmedFacebookPageId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: uuidValidation.error.message },
        { status: uuidValidation.error.status }
      );
    }

    // Verify the page belongs to the user's organization
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: trimmedFacebookPageId,
        organizationId: session.user.organizationId,
      },
    });

    if (!page) {
      return NextResponse.json(
        { error: 'Facebook page not found' },
        { status: 404 }
      );
    }

    const result = await startBackgroundSync(trimmedFacebookPageId);
    
    // CRITICAL: Use Vercel's waitUntil to keep the function alive for background tasks
    // This ensures the background promise continues executing after the response is sent
    if ('waitUntil' in request) {
      // Store the background promise and wait for it
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const backgroundPromise = (globalThis as any).__activeSyncPromises?.values().next().value;
      if (backgroundPromise) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (request as any).waitUntil(backgroundPromise);
      }
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('Background sync error:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    return NextResponse.json(
      { error: 'Failed to start sync. Please try again.' },
      { status: 500 }
    );
  }
}

