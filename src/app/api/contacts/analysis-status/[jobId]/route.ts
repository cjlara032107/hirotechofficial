import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { getAnalysisJobStatus } from '@/lib/facebook/background-analysis';
import { validateSession } from '@/lib/api/validate-session';

interface RouteParams {
  params: Promise<{ jobId: string }>;
}

export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const { jobId } = await params;

    if (!jobId) {
      return NextResponse.json(
        { error: 'Job ID required' },
        { status: 400 }
      );
    }

    // Optimized: Single query with organization check
    const job = await prisma.analysisJob.findFirst({
      where: {
        id: jobId,
        organizationId: validatedSession.user.organizationId,
      },
      select: {
        id: true,
        status: true,
        totalContacts: true,
        analyzedContacts: true,
        failedContacts: true,
        errors: true,
        createdAt: true,
        startedAt: true,
        completedAt: true,
      },
    });

    if (!job) {
      return NextResponse.json(
        { error: 'Analysis job not found or unauthorized' },
        { status: 404 }
      );
    }

    return NextResponse.json(job);
  } catch (error) {
    console.error('Error fetching analysis status:', error);
    return NextResponse.json(
      { error: 'Failed to fetch analysis status' },
      { status: 500 }
    );
  }
}

