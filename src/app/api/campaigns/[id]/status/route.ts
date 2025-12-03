import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';

/**
 * Get detailed status for a campaign
 * Useful for UI polling to track progress
 */
export async function GET(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const multiDbEnabled = process.env.ENABLE_MULTI_DB === 'true';
    console.log('[Campaign Status API] Start', {
      campaignId: id,
      orgId: session.user.organizationId,
      multiDb: multiDbEnabled,
    });

    // Use multi-DB routing
    const db = getPrismaForOrg(session.user.organizationId);

    // Log routed database details
    if (multiDbEnabled) {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(session.user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        console.log('[Campaign Status API] Routed DB', {
          campaignId: id,
          organizationId: session.user.organizationId,
          dbIndex: dbConfig?.index,
          dbUrlHost: dbConfig ? new URL(dbConfig.url).hostname : 'unknown',
          dbHealth: dbConfig?.health,
        });
      } catch (err) {
        console.warn('[Campaign Status API] Could not log DB routing details:', err);
      }
    }

    // Get campaign with org validation
    const campaign = await db.campaign.findUnique({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        name: true,
        status: true,
        platform: true,
        totalRecipients: true,
        sentCount: true,
        deliveredCount: true,
        readCount: true,
        failedCount: true,
        repliedCount: true,
        startedAt: true,
        completedAt: true,
        scheduledAt: true,
        createdAt: true,
        updatedAt: true,
        organizationId: true,
        useAiPersonalization: true,
        mediaUrl: true,
        mediaType: true,
      },
    });

    if (!campaign) {
      console.error('[Campaign Status API] Campaign not found', {
        campaignId: id,
        orgId: session.user.organizationId,
        dbIndex: multiDbEnabled ? 'routed' : 'default',
      });
      return NextResponse.json({
        error: 'Campaign not found in routed database. Check multi-DB connectivity.'
      }, { status: 404 });
    }

    // Calculate real-time message status distribution
    const messageStatuses = await db.message.groupBy({
      by: ['status'],
      where: {
        campaignId: id,
      },
      _count: {
        status: true,
      },
    });

    // Build status distribution map
    const statusDistribution: Record<string, number> = {};
    let totalMessages = 0;
    for (const item of messageStatuses) {
      statusDistribution[item.status] = item._count.status;
      totalMessages += item._count.status;
    }

    // Calculate progress percentage
    const progress = campaign.totalRecipients > 0
      ? Math.round((totalMessages / campaign.totalRecipients) * 100)
      : 0;

    // Determine if campaign is still active
    const isActive = campaign.status === 'SCHEDULED';

    // Calculate estimated time remaining (if active)
    let estimatedTimeRemaining: number | null = null;
    if (isActive && campaign.startedAt && campaign.sentCount > 0) {
      const elapsedMs = Date.now() - campaign.startedAt.getTime();
      const avgTimePerMessage = elapsedMs / campaign.sentCount;
      const remainingMessages = campaign.totalRecipients - totalMessages;
      estimatedTimeRemaining = Math.round((avgTimePerMessage * remainingMessages) / 1000); // seconds
    }

    // Get recent errors (last 10)
    const recentErrors = await db.message.findMany({
      where: {
        campaignId: id,
        status: 'FAILED',
        errorMessage: {
          not: null,
        },
      },
      select: {
        id: true,
        errorMessage: true,
        failedAt: true,
        contactId: true,
        contact: {
          select: {
            firstName: true,
            lastName: true,
          },
        },
      },
      orderBy: {
        failedAt: 'desc',
      },
      take: 10,
    });

    // Build response
    const response = {
      campaign: {
        id: campaign.id,
        name: campaign.name,
        status: campaign.status,
        platform: campaign.platform,
        organizationId: campaign.organizationId,
        createdAt: campaign.createdAt.toISOString(),
        updatedAt: campaign.updatedAt.toISOString(),
        startedAt: campaign.startedAt?.toISOString() || null,
        completedAt: campaign.completedAt?.toISOString() || null,
        scheduledAt: campaign.scheduledAt?.toISOString() || null,
        useAiPersonalization: campaign.useAiPersonalization,
        hasMedia: !!(campaign.mediaUrl && campaign.mediaType),
        mediaType: campaign.mediaType,
      },
      metrics: {
        totalRecipients: campaign.totalRecipients,
        sent: campaign.sentCount,
        delivered: campaign.deliveredCount,
        read: campaign.readCount,
        failed: campaign.failedCount,
        replied: campaign.repliedCount,
        pending: Math.max(0, campaign.totalRecipients - totalMessages),
      },
      statusDistribution,
      progress: {
        percentage: progress,
        isActive,
        estimatedTimeRemaining,
      },
      recentErrors: recentErrors.map(e => ({
        id: e.id,
        message: e.errorMessage,
        failedAt: e.failedAt?.toISOString() || null,
        contactName: `${e.contact.firstName} ${e.contact.lastName || ''}`.trim(),
      })),
      timestamp: new Date().toISOString(),
    };

    console.log('[Campaign Status API] Success', {
      campaignId: id,
      status: campaign.status,
      progress: progress,
      sent: campaign.sentCount,
      total: campaign.totalRecipients,
    });

    return NextResponse.json(response);
  } catch (error) {
    const err = error as Error;
    console.error('[Campaign Status API] Error:', err);
    return NextResponse.json(
      { error: 'Failed to fetch campaign status', details: err.message },
      { status: 500 }
    );
  }
}

