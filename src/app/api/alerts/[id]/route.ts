import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { AlertStatus } from '@prisma/client';
import { auth } from '@/auth';

/**
 * PATCH /api/alerts/[id]
 * Resolve or acknowledge an alert
 */
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;
    const body = await request.json();
    const { action, userId } = body;

    if (action === 'resolve') {
      await prisma.systemAlert.update({
        where: { id },
        data: {
          status: AlertStatus.RESOLVED,
          resolvedAt: new Date(),
        },
      });
    } else if (action === 'acknowledge') {
      await prisma.systemAlert.update({
        where: { id },
        data: {
          status: AlertStatus.ACKNOWLEDGED,
          acknowledgedAt: new Date(),
          acknowledgedBy: userId || session.user.id,
        },
      });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('[API] Error updating alert:', error);
    return NextResponse.json(
      { error: 'Failed to update alert' },
      { status: 500 }
    );
  }
}

