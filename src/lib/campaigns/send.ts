import { prisma } from '@/lib/db';
import { FacebookClient } from '@/lib/facebook/client';

/**
 * Send a single message directly
 */
async function sendMessageDirect(data: {
  campaignId: string;
  contactId: string;
  platform: string;
  content: string;
  messageTag?: string | null;
  pageAccessToken: string;
  recipientId: string | null;
}): Promise<{ success: boolean; error?: string }> {
  const {
    campaignId,
    contactId,
    platform,
    content,
    messageTag,
    pageAccessToken,
    recipientId,
  } = data;

  // Validate recipientId before attempting to send
  if (!recipientId) {
    const error = `No recipient ID (PSID) available for contact`;
    console.error(error, { contactId, platform });
    
    await prisma.message.create({
      data: {
        content,
        platform: platform as any,
        status: 'FAILED',
        messageTag: messageTag as any,
        contactId,
        campaignId,
        isFromBusiness: true,
        failedAt: new Date(),
        errorMessage: error,
      },
    });

    await prisma.campaign.update({
      where: { id: campaignId },
      data: { failedCount: { increment: 1 } },
    });

    return { success: false, error };
  }

  try {
    const client = new FacebookClient(pageAccessToken);

    let result;
    if (platform === 'MESSENGER') {
      result = await client.sendMessengerMessage({
        recipientId,
        message: content,
        messageTag: messageTag as any,
      });
    } else {
      result = await client.sendInstagramMessage(recipientId, content);
    }

    if (result.success) {
      await prisma.message.create({
        data: {
          content,
          platform: platform as any,
          status: 'SENT',
          messageTag: messageTag as any,
          facebookMessageId: result.data?.message_id,
          contactId,
          campaignId,
          isFromBusiness: true,
          sentAt: new Date(),
        },
      });

      await prisma.campaign.update({
        where: { id: campaignId },
        data: { sentCount: { increment: 1 } },
      });

      await prisma.contactActivity.create({
        data: {
          contactId,
          type: 'CAMPAIGN_SENT',
          title: 'Campaign message sent',
          description: content.substring(0, 100),
        },
      });

      return { success: true };
    } else {
      await prisma.message.create({
        data: {
          content,
          platform: platform as any,
          status: 'FAILED',
          messageTag: messageTag as any,
          contactId,
          campaignId,
          isFromBusiness: true,
          failedAt: new Date(),
          errorMessage: !result.success ? ('error' in result ? result.error : 'Failed to send message') : undefined,
        },
      });

      await prisma.campaign.update({
        where: { id: campaignId },
        data: { failedCount: { increment: 1 } },
      });

      return { success: false, error: 'error' in result ? result.error : 'Unknown error' };
    }
  } catch (error: any) {
    await prisma.message.create({
      data: {
        content,
        platform: platform as any,
        status: 'FAILED',
        messageTag: messageTag as any,
        contactId,
        campaignId,
        isFromBusiness: true,
        failedAt: new Date(),
        errorMessage: error.message,
      },
    });

    await prisma.campaign.update({
      where: { id: campaignId },
      data: { failedCount: { increment: 1 } },
    });

    return { success: false, error: error.message };
  }
}

/**
 * Send messages in parallel batches for maximum speed
 * No rate limiting - sends all messages as fast as possible
 */
async function sendMessagesInBackground(
  messages: Array<{
    campaignId: string;
    contactId: string;
    platform: string;
    content: string;
    messageTag?: string | null;
    pageAccessToken: string;
    recipientId: string | null;
  }>
): Promise<void> {
  if (!messages || messages.length === 0) {
    console.error('❌ No messages to send in background');
    return;
  }

  const campaignId = messages[0].campaignId;
  console.log(`🚀 Starting fast parallel sending for ${messages.length} messages (Campaign: ${campaignId})`);

  // Process messages asynchronously without blocking the API response
  Promise.resolve().then(async () => {
    const BATCH_SIZE = 50; // Send 50 messages in parallel at a time to avoid overwhelming the API
    let successCount = 0;
    let failCount = 0;

    try {
      // Split messages into batches
      for (let i = 0; i < messages.length; i += BATCH_SIZE) {
        // Check if campaign has been paused or cancelled before each batch
        const currentCampaign = await prisma.campaign.findUnique({
          where: { id: campaignId },
          select: { status: true },
        });

        if (currentCampaign?.status === 'PAUSED' || currentCampaign?.status === 'CANCELLED') {
          console.log(`⏸️  Campaign ${campaignId} has been ${currentCampaign.status.toLowerCase()}. Stopping sending.`);
          break;
        }

        const batch = messages.slice(i, i + BATCH_SIZE);
        console.log(`📤 Sending batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(messages.length / BATCH_SIZE)} (${batch.length} messages)...`);

        // Send all messages in the batch in parallel
        const results = await Promise.allSettled(
          batch.map(message => sendMessageDirect(message))
        );

        // Count successes and failures
        results.forEach((result, index) => {
          if (result.status === 'fulfilled' && result.value.success) {
            successCount++;
          } else {
            failCount++;
            if (result.status === 'rejected') {
              console.error(`❌ Message ${i + index + 1} failed:`, result.reason);
            } else if (result.status === 'fulfilled') {
              console.error(`❌ Message ${i + index + 1} failed:`, result.value.error);
            }
          }
        });

        console.log(`✅ Batch completed: ${successCount} total sent, ${failCount} total failed`);

        // Small delay between batches to avoid overwhelming the API (100ms)
        if (i + BATCH_SIZE < messages.length) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }

      console.log(`🎉 Campaign sending completed: ${successCount} sent, ${failCount} failed`);

      // Mark campaign as completed with better error handling
      try {
        const finalCampaign = await prisma.campaign.findUnique({
          where: { id: campaignId },
          select: { status: true, sentCount: true, totalRecipients: true, failedCount: true },
        });

        console.log(`📊 Final campaign state:`, {
          campaignId,
          status: finalCampaign?.status,
          sent: finalCampaign?.sentCount,
          failed: finalCampaign?.failedCount,
          total: finalCampaign?.totalRecipients,
          processedInBackground: successCount + failCount,
        });

        if (!finalCampaign) {
          console.error(`❌ CRITICAL: Campaign ${campaignId} not found during completion update`);
          return;
        }

        // Verify all messages have been processed
        const totalProcessed = (finalCampaign.sentCount || 0) + (finalCampaign.failedCount || 0);
        const allProcessed = totalProcessed >= (finalCampaign.totalRecipients || 0);
        
        if (finalCampaign.status === 'SENDING') {
          if (allProcessed || finalCampaign.totalRecipients === 0) {
            const updateResult = await prisma.campaign.update({
              where: { id: campaignId },
              data: { 
                status: 'COMPLETED',
                completedAt: new Date(),
              },
            });
            console.log(`✅ Campaign ${campaignId} marked as COMPLETED`, {
              sentCount: updateResult.sentCount,
              failedCount: updateResult.failedCount,
              totalRecipients: updateResult.totalRecipients,
              totalProcessed,
            });
          } else {
            console.warn(`⚠️ Campaign ${campaignId} not fully processed: ${totalProcessed}/${finalCampaign.totalRecipients}. Marking as completed anyway since background process finished.`);
            // Mark as completed anyway since background process is done
            const updateResult = await prisma.campaign.update({
              where: { id: campaignId },
              data: { 
                status: 'COMPLETED',
                completedAt: new Date(),
              },
            });
            console.log(`✅ Campaign ${campaignId} marked as COMPLETED (background finished)`, {
              sentCount: updateResult.sentCount,
              failedCount: updateResult.failedCount,
              totalRecipients: updateResult.totalRecipients,
            });
          }
        } else {
          console.warn(`⚠️ Campaign ${campaignId} status is ${finalCampaign.status}, skipping completion update`);
        }
      } catch (error) {
        console.error(`❌ CRITICAL: Failed to update campaign ${campaignId} status:`, error);
        // Retry once after a delay
        console.log(`🔄 Retrying status update for campaign ${campaignId} after 1 second...`);
        await new Promise(resolve => setTimeout(resolve, 1000));
        try {
          await prisma.campaign.update({
            where: { id: campaignId },
            data: { 
              status: 'COMPLETED',
              completedAt: new Date(),
            },
          });
          console.log(`✅ Campaign ${campaignId} marked as COMPLETED (retry successful)`);
        } catch (retryError) {
          console.error(`❌ FINAL ERROR: Cannot update campaign ${campaignId} status:`, retryError);
          console.error(`⚠️ Campaign ${campaignId} may be stuck in SENDING status. Manual intervention required.`);
        }
      }
    } catch (error) {
      console.error(`🔥 CRITICAL: Background processing crashed for campaign ${campaignId}:`, error);
      console.error(`📍 Error stack:`, error instanceof Error ? error.stack : 'No stack trace');
      
      try {
        const errorCampaign = await prisma.campaign.findUnique({
          where: { id: campaignId },
          select: { status: true, sentCount: true, totalRecipients: true },
        });

        console.log(`📊 Campaign state after crash:`, {
          campaignId,
          status: errorCampaign?.status,
          sent: errorCampaign?.sentCount,
          total: errorCampaign?.totalRecipients,
        });

        if (errorCampaign?.status === 'SENDING') {
          await prisma.campaign.update({
            where: { id: campaignId },
            data: { 
              status: 'COMPLETED',
              completedAt: new Date(),
            },
          });
          console.log(`✅ Campaign ${campaignId} marked as COMPLETED after error`);
        }
      } catch (updateError) {
        console.error('❌ Failed to update campaign status after crash:', updateError);
        console.error(`⚠️ Campaign ${campaignId} may be stuck in SENDING status. Manual intervention required.`);
      }
    }
  }).catch((error) => {
    console.error(`🔥 CRITICAL: Failed to start background processing for campaign ${campaignId}:`, error);
  });
}

export async function getTargetContacts(campaignId: string) {
  const campaign = await prisma.campaign.findUnique({
    where: { id: campaignId },
    include: {
      facebookPage: true,
      groups: {
        include: { contacts: true },
      },
    },
  });

  if (!campaign) throw new Error('Campaign not found');

  let contacts: any[] = [];

  switch (campaign.targetingType) {
    case 'CONTACT_GROUPS':
      contacts = campaign.groups.flatMap((g) => g.contacts);
      break;

    case 'TAGS':
      contacts = await prisma.contact.findMany({
        where: {
          organizationId: campaign.organizationId,
          facebookPageId: campaign.facebookPageId,
          tags: {
            hasSome: campaign.targetTags,
          },
        },
      });
      break;

    case 'PIPELINE_STAGES':
      contacts = await prisma.contact.findMany({
        where: {
          organizationId: campaign.organizationId,
          facebookPageId: campaign.facebookPageId,
          stageId: {
            in: campaign.targetStageIds,
          },
        },
      });
      break;

    case 'SPECIFIC_CONTACTS':
      contacts = await prisma.contact.findMany({
        where: {
          id: {
            in: campaign.targetContactIds,
          },
        },
      });
      break;

    case 'ALL_CONTACTS':
      contacts = await prisma.contact.findMany({
        where: {
          organizationId: campaign.organizationId,
          facebookPageId: campaign.facebookPageId,
        },
      });
      break;
  }

  const uniqueContacts = Array.from(
    new Map(contacts.map((c) => [c.id, c])).values()
  );

  const targetContacts = uniqueContacts.filter((contact) => {
    // Must have both the platform flag AND a valid recipient ID
    if (campaign.platform === 'MESSENGER') {
      return contact.hasMessenger && contact.messengerPSID;
    }
    if (campaign.platform === 'INSTAGRAM') {
      return contact.hasInstagram && contact.instagramSID;
    }
    return false;
  });

  return targetContacts;
}

export async function startCampaign(campaignId: string) {
  console.log(`🚀 Starting campaign ${campaignId}...`);
  
  const campaign = await prisma.campaign.findUnique({
    where: { id: campaignId },
    include: {
      facebookPage: true,
      template: true,
    },
  });

  if (!campaign) throw new Error('Campaign not found');
  console.log(`✅ Campaign found: ${campaign.name}`);

  const targetContacts = await getTargetContacts(campaignId);
  console.log(`📊 Target contacts found: ${targetContacts.length}`);

  if (targetContacts.length === 0) {
    await prisma.campaign.update({
      where: { id: campaignId },
      data: {
        status: 'COMPLETED',
        totalRecipients: 0,
        completedAt: new Date(),
      },
    });
    throw new Error('No target contacts found for this campaign. Make sure contacts have valid Messenger PSIDs or Instagram SIDs.');
  }

  console.log(`📝 Updating campaign status to SENDING...`);
  await prisma.campaign.update({
    where: { id: campaignId },
    data: {
      status: 'SENDING',
      startedAt: new Date(),
      totalRecipients: targetContacts.length,
    },
  });

  console.log('🚀 Using fast parallel sending mode - NO rate limiting');
  
  // Check if we have AI-generated messages to use
  const aiMessagesMap = (campaign as any).aiMessagesMap as Record<string, string> | null;
  const useAiMessages = (campaign as any).useAiPersonalization && aiMessagesMap;
  
  if (useAiMessages) {
    console.log(`📝 Using AI-personalized messages for ${Object.keys(aiMessagesMap).length} contacts`);
  }
  
  const messages = targetContacts.map((contact) => {
    let messageContent: string;
    
    // Use AI-generated message if available, otherwise use template
    if (useAiMessages && aiMessagesMap[contact.id]) {
      messageContent = aiMessagesMap[contact.id];
      console.log(`✨ Using AI message for ${contact.firstName}: "${messageContent.substring(0, 50)}..."`);
    } else {
      // Fallback to template with variable replacement
      messageContent = campaign.template?.content || '';
      messageContent = messageContent
        .replace(/\{firstName\}/g, contact.firstName)
        .replace(/\{lastName\}/g, contact.lastName || '')
        .replace(/\{name\}/g, `${contact.firstName} ${contact.lastName || ''}`.trim());
    }

    return {
      campaignId: campaign.id,
      contactId: contact.id,
      platform: campaign.platform as string,
      content: messageContent,
      messageTag: campaign.messageTag as string | null,
      pageAccessToken: campaign.facebookPage.pageAccessToken,
      recipientId:
        campaign.platform === 'MESSENGER'
          ? contact.messengerPSID
          : contact.instagramSID,
    };
  });

  console.log(`📋 Prepared ${messages.length} messages for fast parallel sending`);
  
  // Send messages in background without rate limiting
  sendMessagesInBackground(messages);

  console.log(`⚡ Campaign started! Messages are being sent in parallel batches.`);
  return { 
    success: true, 
    queued: targetContacts.length,
    mode: 'direct-fast',
    message: 'Messages are being sent as fast as possible in parallel batches!'
  };
}

