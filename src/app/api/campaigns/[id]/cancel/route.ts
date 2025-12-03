import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export async function POST(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Verify campaign belongs to user's organization and is in SENDING status
    const campaign = await prisma.campaign.findUnique({
      where: { 
        id,
        organizationId: session.user.organizationId,
      },
    });

    if (!campaign) {
      return NextResponse.json({ error: 'Campaign not found' }, { status: 404 });
    }

    if (campaign.status !== 'SENDING') {
      return NextResponse.json(
        { error: `Campaign cannot be cancelled. Current status: ${campaign.status}` }, 
        { status: 400 }
      );
    }

    console.log(`🛑 Cancelling campaign ${id}...`);

    // Get media info before updating
    const mediaUrl = (campaign as any).mediaUrl;
    const mediaType = (campaign as any).mediaType;
    
    // Update campaign status to CANCELLED
    const updatedCampaign = await prisma.campaign.update({
      where: { id },
      data: { 
        status: 'CANCELLED',
        completedAt: new Date(),
      },
    });
    
    // Delete media file after campaign cancellation
    if (mediaUrl && mediaType) {
      const { deleteCampaignMedia } = await import('@/lib/campaigns/delete-media');
      await deleteCampaignMedia(mediaUrl, mediaType);
    }

    console.log(`✅ Campaign ${id} cancelled successfully`);

    return NextResponse.json({
      success: true,
      message: 'Campaign cancelled successfully',
      campaign: updatedCampaign,
    });
  } catch (error) {
    const err = error as Error;
    console.error('❌ Cancel campaign error:', err);
    return NextResponse.json(
      { error: err.message || 'Failed to cancel campaign' },
      { status: 500 }
    );
  }
}

