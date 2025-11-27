import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
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

    const campaign = await safePrismaOperation(
      () => prisma.campaign.findUnique({
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
      return NextResponse.json({ error: 'Campaign not found' }, { status: 404 });
    }

    // Recalculate metrics from actual message counts for accuracy
    // This ensures metrics are always accurate even if webhooks haven't updated yet
    const messageCounts = await safePrismaOperation(
      () => prisma.message.groupBy({
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
      prisma.campaign.update({
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

    // Delete the campaign (messages will be cascade deleted)
    await safePrismaOperation(
      () => prisma.campaign.delete({
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

