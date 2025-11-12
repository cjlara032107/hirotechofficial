import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { jobId } = body;

    if (!jobId) {
      return NextResponse.json(
        { error: 'Missing jobId' },
        { status: 400 }
      );
    }

    // Get the sync job
    const job = await prisma.syncJob.findUnique({
      where: { id: jobId },
      include: {
        facebookPage: {
          select: {
            organizationId: true,
          },
        },
      },
    });

    if (!job) {
      return NextResponse.json(
        { error: 'Sync job not found' },
        { status: 404 }
      );
    }

    // Verify job belongs to user's organization
    if (job.facebookPage.organizationId !== session.user.organizationId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 403 }
      );
    }

    // Only allow cancelling jobs that are pending or in progress
    if (!['PENDING', 'IN_PROGRESS'].includes(job.status)) {
      return NextResponse.json(
        { error: `Cannot cancel job with status: ${job.status}` },
        { status: 400 }
      );
    }

    // Mark job as cancelled
    const cancelledJob = await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'CANCELLED',
        completedAt: new Date(),
      },
    });

    console.log(`[Sync Cancel] Job ${jobId} cancelled by user`);

    return NextResponse.json({
      success: true,
      job: cancelledJob,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to cancel sync';
    console.error('Cancel sync error:', error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

