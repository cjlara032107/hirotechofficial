import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { startCampaign } from '@/lib/campaigns/send';

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

    const multiDbEnabled = process.env.ENABLE_MULTI_DB === 'true';
    console.log('[Campaign API SEND] Start', {
      campaignId: id,
      orgId: session.user.organizationId,
      multiDb: multiDbEnabled,
      strategy: process.env.DB_ROUTING_STRATEGY || 'hash',
    });

    // Use multi-DB routing to verify campaign exists and belongs to org
    const db = getPrismaForOrg(session.user.organizationId);

    // Log routed database details
    if (multiDbEnabled) {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(session.user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        console.log('[Campaign API SEND] Routed DB', {
          campaignId: id,
          organizationId: session.user.organizationId,
          dbIndex: dbConfig?.index,
          dbUrlHost: dbConfig ? new URL(dbConfig.url).hostname : 'unknown',
          dbHealth: dbConfig?.health,
        });
      } catch (err) {
        console.warn('[Campaign API SEND] Could not log DB routing details:', err);
      }
    }

    // Verify campaign exists and belongs to org
    const campaign = await db.campaign.findUnique({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        name: true,
        status: true,
        organizationId: true,
      },
    });

    if (!campaign) {
      console.error('[Campaign API SEND] Campaign not found or access denied', {
        campaignId: id,
        orgId: session.user.organizationId,
        dbIndex: multiDbEnabled ? 'routed' : 'default',
      });
      return NextResponse.json({ 
        error: 'Campaign not found in routed database or you do not have access. Check multi-DB connectivity.' 
      }, { status: 404 });
    }

    console.log(`[Campaign API SEND] Starting campaign ${id} (${campaign.name}) for org ${campaign.organizationId}`);
    const result = await startCampaign(id, session.user.organizationId);
    console.log(`[Campaign API SEND] Campaign started successfully`, result);

    return NextResponse.json(result);
  } catch (error) {
    const err = error as Error;
    console.error('[Campaign API SEND] Error:', err);
    const { id } = await props.params;
    console.error('[Campaign API SEND] Error details:', {
      message: err.message,
      stack: err.stack,
      campaignId: id,
    });

    // Try to update campaign status to FAILED if it got stuck
    try {
      const session = await auth();
      if (session?.user) {
        const { getPrismaForOrg } = await import('@/lib/db/get-prisma-for-org');
        const db = getPrismaForOrg(session.user.organizationId);
        const campaign = await db.campaign.findUnique({
        where: { id },
        select: { mediaUrl: true, mediaType: true },
      });
      
        await db.campaign.update({
          where: { id },
          data: { 
            status: 'CANCELLED',
            completedAt: new Date(),
          },
        });
        
        // Delete media file after campaign cancellation
        if (campaign?.mediaUrl && campaign?.mediaType) {
          const { deleteCampaignMedia } = await import('@/lib/campaigns/delete-media');
          await deleteCampaignMedia(campaign.mediaUrl, campaign.mediaType);
        }
        
        console.log(`[Campaign API SEND] Campaign ${id} status updated to CANCELLED due to error`);
      }
    } catch (updateError) {
      console.error('[Campaign API SEND] Failed to update campaign status:', updateError);
    }

    return NextResponse.json(
      { error: err.message || 'Failed to start campaign' },
      { status: 500 }
    );
  }
}
