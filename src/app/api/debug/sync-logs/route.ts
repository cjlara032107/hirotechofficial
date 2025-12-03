import { NextRequest, NextResponse } from 'next/server';
import { prisma, connectPrisma } from '@/lib/db';
import { requireAuth } from '@/lib/api/validate-session';

/**
 * Debug endpoint to view recent sync logs
 * GET /api/debug/sync-logs?limit=10
 */
export async function GET(request: NextRequest) {
  try {
    // Validate session
    const authResult = await requireAuth();
    if ('error' in authResult) {
      return authResult.error;
    }
    const { session } = authResult;

    await connectPrisma();

    // Get limit from query params
    const searchParams = request.nextUrl.searchParams;
    const limit = parseInt(searchParams.get('limit') || '10', 10);

    // Get recent sync jobs
    const recentJobs = await prisma.syncJob.findMany({
      take: Math.min(limit, 50), // Max 50
      orderBy: {
        createdAt: 'desc',
      },
      include: {
        facebookPage: {
          select: {
            pageName: true,
            pageId: true,
            organizationId: true,
          },
        },
      },
      where: {
        facebookPage: {
          organizationId: session.user.organizationId,
        },
      },
    });

    // Format jobs for response
    const formattedJobs = recentJobs.map(job => {
      const createdAt = new Date(job.createdAt);
      const startedAt = job.startedAt ? new Date(job.startedAt) : null;
      const completedAt = job.completedAt ? new Date(job.completedAt) : null;
      
      const duration = startedAt && completedAt
        ? Math.round((completedAt.getTime() - startedAt.getTime()) / 1000)
        : startedAt
          ? Math.round((Date.now() - startedAt.getTime()) / 1000)
          : null;

      return {
        id: job.id,
        status: job.status,
        pageName: job.facebookPage?.pageName || 'Unknown',
        pageId: job.facebookPage?.pageId || 'N/A',
        syncedContacts: job.syncedContacts,
        failedContacts: job.failedContacts,
        totalContacts: job.totalContacts,
        tokenExpired: job.tokenExpired,
        createdAt: createdAt.toISOString(),
        startedAt: startedAt?.toISOString() || null,
        completedAt: completedAt?.toISOString() || null,
        duration: duration ? `${duration}s` : null,
        errors: job.errors,
        progress: job.totalContacts > 0 
          ? Math.round((job.syncedContacts / job.totalContacts) * 100)
          : 0,
      };
    });

    // Get summary
    const activeJobs = recentJobs.filter(j => 
      j.status === 'PENDING' || j.status === 'IN_PROGRESS'
    );
    const completed = recentJobs.filter(j => j.status === 'COMPLETED').length;
    const failed = recentJobs.filter(j => j.status === 'FAILED').length;

    return NextResponse.json({
      summary: {
        total: recentJobs.length,
        active: activeJobs.length,
        completed,
        failed,
      },
      jobs: formattedJobs,
    });
  } catch (error) {
    console.error('[Debug Sync Logs] Error:', error);
    return NextResponse.json(
      { 
        error: 'Failed to fetch sync logs',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}









