import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateUUID } from '@/lib/api/validate-uuid';

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

    // Validate jobId format
    if (typeof jobId !== 'string' || jobId.trim().length === 0) {
      return NextResponse.json(
        { error: 'Invalid job ID format' },
        { status: 400 }
      );
    }

    const trimmedJobId = jobId.trim();
    const uuidValidation = validateUUID(trimmedJobId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: uuidValidation.error.message },
        { status: uuidValidation.error.status }
      );
    }

    // Get the sync job
    const job = await prisma.syncJob.findUnique({
      where: { id: trimmedJobId },
    });

    if (!job) {
      return NextResponse.json(
        { error: 'Sync job not found' },
        { status: 404 }
      );
    }

    // Verify job belongs to user's organization by checking the FacebookPage
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: job.facebookPageId,
        organizationId: session.user.organizationId,
      },
    });

    if (!page) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 403 }
      );
    }

    // Only allow cancelling jobs that are pending or in progress
    if (!['PENDING', 'IN_PROGRESS'].includes(job.status)) {
      // If already cancelled, return success (idempotent)
      if (job.status === 'CANCELLED') {
        return NextResponse.json({
          success: true,
          job,
          message: 'Job is already cancelled',
        });
      }
      return NextResponse.json(
        { error: `Cannot cancel job with status: ${job.status}` },
        { status: 400 }
      );
    }

    // Use conditional update to prevent race conditions
    // Only update if status is still PENDING or IN_PROGRESS (atomic operation)
    const updateResult = await prisma.syncJob.updateMany({
      where: {
        id: trimmedJobId,
        status: {
          in: ['PENDING', 'IN_PROGRESS'],
        },
      },
      data: {
        status: 'CANCELLED',
        completedAt: new Date(),
      },
    });

    // If no rows were updated, job was already cancelled or completed by another request
    if (updateResult.count === 0) {
      // Re-fetch to get current status
      const currentJob = await prisma.syncJob.findUnique({
        where: { id: trimmedJobId },
      });

      if (currentJob?.status === 'CANCELLED') {
        return NextResponse.json({
          success: true,
          job: currentJob,
          message: 'Job was already cancelled',
        });
      }

      return NextResponse.json(
        { error: `Cannot cancel job with status: ${currentJob?.status || 'UNKNOWN'}` },
        { status: 400 }
      );
    }

    // Fetch the updated job
    const updatedJob = await prisma.syncJob.findUnique({
      where: { id: trimmedJobId },
    });

    if (updatedJob) {
      console.log(`[Sync Cancel] Job ${trimmedJobId} cancelled by user`);
      return NextResponse.json({
        success: true,
        job: updatedJob,
      });
    }

    // Fallback (should not happen)
    return NextResponse.json(
      { error: 'Failed to cancel job' },
      { status: 500 }
    );
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to cancel sync';
    console.error('Cancel sync error:', error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

