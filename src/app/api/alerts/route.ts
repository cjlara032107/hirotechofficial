import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { AlertStatus } from '@prisma/client';
import { auth } from '@/auth';

/**
 * GET /api/alerts
 * Get system alerts (active, resolved, or all)
 */
export async function GET(request: NextRequest) {
  try {
    // Check authentication
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Only admins can view system alerts
    // You may want to adjust this based on your role system
    const searchParams = request.nextUrl.searchParams;
    const status = searchParams.get('status') as AlertStatus | null;
    const limit = parseInt(searchParams.get('limit') || '50', 10);

    const where: { status?: AlertStatus } = {};
    if (status) {
      where.status = status;
    }

    const alerts = await prisma.systemAlert.findMany({
      where,
      orderBy: {
        createdAt: 'desc',
      },
      take: limit,
    });

    return NextResponse.json({ alerts });
  } catch (error) {
    console.error('[API] Error fetching alerts:', error);
    return NextResponse.json(
      { error: 'Failed to fetch alerts' },
      { status: 500 }
    );
  }
}

