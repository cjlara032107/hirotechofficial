import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startCampaign } from '@/lib/campaigns/send';

/**
 * Send a scheduled campaign immediately (bypass schedule time)
 * This allows users to manually trigger campaigns that are scheduled for the future
 */
export async function POST(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id: campaignId } = await props.params;
    const session = await auth();
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    console.log(`[Send Now] Manual trigger for campaign ${campaignId}`);

    // Get campaign
    const campaign = await prisma.campaign.findUnique({
      where: { 
        id: campaignId,
        organizationId: session.user.organizationId,
      },
    });

    if (!campaign) {
      return NextResponse.json({ error: 'Campaign not found' }, { status: 404 });
    }

    // Only allow sending campaigns that are scheduled or draft
    if (campaign.status !== 'SCHEDULED' && campaign.status !== 'DRAFT') {
      return NextResponse.json(
        { 
          error: `Cannot send campaign with status: ${campaign.status}. Only SCHEDULED or DRAFT campaigns can be sent manually.` 
        },
        { status: 400 }
      );
    }

    console.log(`[Send Now] Campaign status: ${campaign.status}, clearing schedule and starting...`);

    // Clear scheduled time and start campaign immediately
    await prisma.campaign.update({
      where: { id: campaignId },
      data: {
        scheduledAt: null, // Remove schedule
        status: 'DRAFT', // Reset to draft so startCampaign can process it
      },
    });

    // Start campaign using existing logic
    const result = await startCampaign(campaignId);

    console.log(`[Send Now] ✅ Campaign ${campaignId} sent successfully`);

    return NextResponse.json({
      ...result,
      sentImmediately: true,
    });

  } catch (error) {
    const err = error as Error;
    console.error('[Send Now] Error:', err);
    
    return NextResponse.json(
      { error: err.message || 'Failed to send campaign' },
      { status: 500 }
    );
  }
}
