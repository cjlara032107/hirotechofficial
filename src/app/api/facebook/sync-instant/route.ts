import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startInstantSync } from '@/lib/facebook/instant-sync';

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

    // Start instant sync (stores contacts immediately, queues AI analysis)
    const result = await startInstantSync(facebookPageId, session.user.id);

    return NextResponse.json(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to start instant sync';
    console.error('Instant sync error:', error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

