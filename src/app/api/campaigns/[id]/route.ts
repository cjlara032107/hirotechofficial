import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { safePrismaOperation, handlePrismaError } from '@/lib/prisma-error-handler';

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
    console.log('[Campaign API GET by ID] Start', {
      campaignId: id,
      orgId: session.user.organizationId,
      multiDb: multiDbEnabled,
      strategy: process.env.DB_ROUTING_STRATEGY || 'hash',
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
        console.log('[Campaign API GET by ID] Routed DB', {
          campaignId: id,
          organizationId: session.user.organizationId,
          dbIndex: dbConfig?.index,
          dbUrlHost: dbConfig ? new URL(dbConfig.url).hostname : 'unknown',
          dbHealth: dbConfig?.health,
        });
      } catch (err) {
        console.warn('[Campaign API GET by ID] Could not log DB routing details:', err);
      }
    }

    const campaign = await safePrismaOperation(
      () => db.campaign.findUnique({
        where: { 
          id,
          organizationId: session.user.organizationId,
        },
        include: {
          template: true,
          facebookPage: {
            select: {
              pageName: true,
              pageId: true,
            },
          },
          _count: {
            select: { messages: true },
          },
        },
      }),
      { operationName: 'find campaign' }
    );

    if (!campaign) {
      console.error('[Campaign API GET by ID] Campaign not found', {
        campaignId: id,
        orgId: session.user.organizationId,
        dbIndex: multiDbEnabled ? 'routed' : 'default',
      });
      return NextResponse.json({ 
        error: 'Campaign not found in routed database. Check multi-DB connectivity and ensure data exists in correct database.' 
      }, { status: 404 });
    }

    // Recalculate metrics from actual message counts for accuracy
    // This ensures metrics are always accurate even if webhooks haven't updated yet
    const messageCounts = await safePrismaOperation(
      () => db.message.groupBy({
        by: ['status'],
        where: {
          campaignId: id,
        },
        _count: {
          status: true,
        },
      }),
      { operationName: 'group messages by status' }
    );

    // Calculate accurate counts
    // Sent = all messages that were attempted (SENT, DELIVERED, READ, FAILED)
    // This includes messages that were sent but may have failed
    const actualSentCount = messageCounts
      .filter(m => ['SENT', 'DELIVERED', 'READ', 'FAILED'].includes(m.status))
      .reduce((sum, m) => sum + m._count.status, 0);
    
    // Delivered = messages that reached the recipient (DELIVERED or READ)
    const actualDeliveredCount = messageCounts
      .filter(m => ['DELIVERED', 'READ'].includes(m.status))
      .reduce((sum, m) => sum + m._count.status, 0);
    
    // Read = messages that were read by the recipient
    const actualReadCount = messageCounts
      .filter(m => m.status === 'READ')
      .reduce((sum, m) => sum + m._count.status, 0);
    
    // Failed = messages that failed to send
    const actualFailedCount = messageCounts
      .filter(m => m.status === 'FAILED')
      .reduce((sum, m) => sum + m._count.status, 0);

    // Update campaign if counts are different (async, don't wait)
    if (
      campaign.sentCount !== actualSentCount ||
      campaign.deliveredCount !== actualDeliveredCount ||
      campaign.readCount !== actualReadCount ||
      campaign.failedCount !== actualFailedCount
    ) {
      db.campaign.update({
        where: { id },
        data: {
          sentCount: actualSentCount,
          deliveredCount: actualDeliveredCount,
          readCount: actualReadCount,
          failedCount: actualFailedCount,
        },
      }).catch(err => console.error('Error updating campaign metrics:', err));
    }

    // Return campaign with accurate counts
    return NextResponse.json({
      ...campaign,
      sentCount: actualSentCount,
      deliveredCount: actualDeliveredCount,
      readCount: actualReadCount,
      failedCount: actualFailedCount,
    });
  } catch (error) {
    console.error('Get campaign error:', error);
    const { message, status } = handlePrismaError(error, 'Failed to fetch campaign');
    return NextResponse.json(
      { error: message },
      { status }
    );
  }
}

export async function DELETE(
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
    console.log('[Campaign API DELETE] Start', {
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
        console.log('[Campaign API DELETE] Routed DB', {
          campaignId: id,
          organizationId: session.user.organizationId,
          dbIndex: dbConfig?.index,
          dbUrlHost: dbConfig ? new URL(dbConfig.url).hostname : 'unknown',
        });
      } catch (err) {
        console.warn('[Campaign API DELETE] Could not log DB routing details:', err);
      }
    }

    // Delete the campaign (messages will be cascade deleted)
    await safePrismaOperation(
      () => db.campaign.delete({
        where: { 
          id,
          organizationId: session.user.organizationId,
        },
      }),
      { operationName: 'delete campaign' }
    );

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete campaign error:', error);
    const { message, status } = handlePrismaError(error, 'Failed to delete campaign');
    return NextResponse.json(
      { error: message },
      { status }
    );
  }
}

