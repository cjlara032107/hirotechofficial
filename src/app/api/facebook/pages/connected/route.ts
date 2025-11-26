import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';

/**
 * GET - Fetch organization's connected Facebook pages
 */
export async function GET() {
  try {
    // Ensure Prisma is connected before queries
    await connectPrisma();
    
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const pages = await prisma.facebookPage.findMany({
      where: {
        organizationId: session.user.organizationId,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return NextResponse.json({ pages });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch connected pages';
    console.error('Fetch connected pages error:', error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

