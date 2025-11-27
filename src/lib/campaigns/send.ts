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

    // Update failedCount atomically
    try {
      await prisma.campaign.update({
        where: { id: campaignId },
        data: { failedCount: { increment: 1 } },
      });
    } catch (updateError) {
      console.error(`Failed to update failedCount for campaign ${campaignId}:`, updateError);
    }

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

      // Update sentCount atomically
      try {
        await prisma.campaign.update({
          where: { id: campaignId },
          data: { sentCount: { increment: 1 } },
        });
      } catch (error) {
        // If update fails, log but don't fail the message send
        console.error(`Failed to update sentCount for campaign ${campaignId}:`, error);
      }

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
      const errorDetails = 'error' in result ? result.error : 'Failed to send message';
      const errorMessage = 'message' in result ? result.message : errorDetails;
      
      // Log detailed error for debugging
      console.error(`[Campaign Send] Message failed:`, {
        contactId,
        recipientId,
        platform,
        error: errorDetails,
        message: errorMessage,
        code: 'code' in result ? result.code : undefined,
      });
      
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
          errorMessage: errorMessage,
        },
      });

      // Update failedCount atomically
      try {
        await prisma.campaign.update({
          where: { id: campaignId },
          data: { failedCount: { increment: 1 } },
        });
      } catch (error) {
        console.error(`Failed to update failedCount for campaign ${campaignId}:`, error);
      }
    
      return { success: false, error: errorMessage };
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

    // Update failedCount atomically
    try {
      await prisma.campaign.update({
        where: { id: campaignId },
        data: { failedCount: { increment: 1 } },
      });
    } catch (updateError) {
      console.error(`Failed to update failedCount for campaign ${campaignId}:`, updateError);
    }

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
  // Use Promise.resolve().then() to ensure this runs asynchronously
  Promise.resolve().then(async () => {
    const BATCH_SIZE = 50; // Send 50 messages in parallel at a time to avoid overwhelming the API
    let successCount = 0;
    let failCount = 0;
    let processedCount = 0;
    const totalMessages = messages.length;

    console.log(`🚀 Background process started for ${totalMessages} messages`);

    try {
      // Split messages into batches
      for (let i = 0; i < messages.length; i += BATCH_SIZE) {
        const batchNumber = Math.floor(i / BATCH_SIZE) + 1;
        const totalBatches = Math.ceil(messages.length / BATCH_SIZE);
        
        // Check if campaign has been paused or cancelled before each batch
        const currentCampaign = await prisma.campaign.findUnique({
          where: { id: campaignId },
          select: { status: true },
        });

        if (currentCampaign?.status === 'PAUSED' || currentCampaign?.status === 'CANCELLED') {
          console.log(`⏸️  Campaign ${campaignId} has been ${currentCampaign.status.toLowerCase()}. Stopping sending at batch ${batchNumber}/${totalBatches}.`);
          break;
        }

        const batch = messages.slice(i, i + BATCH_SIZE);
        console.log(`📤 Sending batch ${batchNumber}/${totalBatches} (messages ${i + 1}-${Math.min(i + BATCH_SIZE, messages.length)} of ${totalMessages})...`);

        try {
          // Send all messages in the batch in parallel with timeout protection
          const batchPromise = Promise.allSettled(
            batch.map(message => sendMessageDirect(message))
          );
          
          // Add timeout for each batch (60 seconds per batch)
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error(`Batch ${batchNumber} timed out after 60 seconds`)), 60000);
          });

          const results = await Promise.race([batchPromise, timeoutPromise]);

          // Count successes and failures accurately
          results.forEach((result, index) => {
            processedCount++;
            if (result.status === 'fulfilled') {
              // Only count as failure if result.value.success is explicitly false
              if (result.value.success === true) {
                successCount++;
              } else {
                failCount++;
                console.error(`❌ Message ${i + index + 1}/${totalMessages} failed:`, result.value.error || 'Unknown error');
              }
            } else {
              // Promise was rejected
              failCount++;
              console.error(`❌ Message ${i + index + 1}/${totalMessages} rejected:`, result.reason);
            }
          });

          console.log(`✅ Batch ${batchNumber}/${totalBatches} completed: ${successCount} sent, ${failCount} failed, ${processedCount}/${totalMessages} processed`);
        } catch (batchError) {
          console.error(`❌ Batch ${batchNumber}/${totalBatches} error:`, batchError);
          // Mark all messages in this batch as failed
          failCount += batch.length;
          processedCount += batch.length;
          console.error(`⚠️ Marked ${batch.length} messages as failed due to batch error`);
        }

        // Small delay between batches to avoid overwhelming the API (100ms)
        if (i + BATCH_SIZE < messages.length) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }

      console.log(`🎉 All batches processed: ${processedCount}/${totalMessages} messages processed (${successCount} sent, ${failCount} failed)`);
      console.log(`🎉 Campaign sending completed: ${successCount} sent, ${failCount} failed, ${processedCount}/${totalMessages} total processed`);

      // Mark campaign as completed with better error handling
      // Always mark as completed if we've processed all messages or if background process finished
      let retryCount = 0;
      const maxRetries = 3;
      
      while (retryCount < maxRetries) {
        try {
          const finalCampaign = await prisma.campaign.findUnique({
            where: { id: campaignId },
            select: { status: true, sentCount: true, totalRecipients: true, failedCount: true },
          });

          console.log(`📊 Final campaign state (attempt ${retryCount + 1}):`, {
            campaignId,
            status: finalCampaign?.status,
            sent: finalCampaign?.sentCount,
            failed: finalCampaign?.failedCount,
            total: finalCampaign?.totalRecipients,
            processedInBackground: processedCount,
            expectedTotal: totalMessages,
          });

          if (!finalCampaign) {
            console.error(`❌ CRITICAL: Campaign ${campaignId} not found during completion update`);
            if (retryCount < maxRetries - 1) {
              await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)));
              retryCount++;
              continue;
            }
            return;
          }

          // Always mark as COMPLETED if background process finished, regardless of counts
          // This prevents campaigns from getting stuck
          if (finalCampaign.status === 'SENDING') {
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
              processedInBackground: processedCount,
              expectedTotal: totalMessages,
            });
            break; // Success, exit retry loop
          } else if (finalCampaign.status === 'COMPLETED' || finalCampaign.status === 'CANCELLED') {
            console.log(`ℹ️ Campaign ${campaignId} already in ${finalCampaign.status} status, no update needed`);
            break; // Already completed, exit retry loop
          } else {
            console.warn(`⚠️ Campaign ${campaignId} status is ${finalCampaign.status}, attempting to mark as COMPLETED anyway`);
            const updateResult = await prisma.campaign.update({
              where: { id: campaignId },
              data: { 
                status: 'COMPLETED',
                completedAt: new Date(),
              },
            });
            console.log(`✅ Campaign ${campaignId} marked as COMPLETED (forced)`, {
              sentCount: updateResult.sentCount,
              failedCount: updateResult.failedCount,
              totalRecipients: updateResult.totalRecipients,
            });
            break; // Success, exit retry loop
          }
        } catch (updateError) {
          retryCount++;
          if (retryCount >= maxRetries) {
            console.error(`❌ FINAL ERROR: Cannot update campaign ${campaignId} status after ${maxRetries} attempts:`, updateError);
            console.error(`⚠️ Campaign ${campaignId} may be stuck in SENDING status. Manual intervention required.`);
          } else {
            console.error(`❌ Failed to update campaign ${campaignId} status (attempt ${retryCount}/${maxRetries}):`, updateError);
            console.log(`🔄 Retrying status update for campaign ${campaignId} after ${retryCount} second(s)...`);
            await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
          }
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
  
  // Generate AI messages if personalization is enabled but messages haven't been generated yet
  let aiMessagesMap: Record<string, string> | null = null;
  
  // Parse aiMessagesMap from JSON if it exists
  if ((campaign as any).aiMessagesMap) {
    if (typeof (campaign as any).aiMessagesMap === 'string') {
      try {
        aiMessagesMap = JSON.parse((campaign as any).aiMessagesMap);
      } catch (e) {
        console.error('[AI Messages] Failed to parse aiMessagesMap from string:', e);
        aiMessagesMap = null;
      }
    } else if (typeof (campaign as any).aiMessagesMap === 'object') {
      aiMessagesMap = (campaign as any).aiMessagesMap as Record<string, string>;
    }
  }
  
  const useAiPersonalization = (campaign as any).useAiPersonalization;
  
  console.log(`[AI Messages] useAiPersonalization: ${useAiPersonalization}, aiMessagesMap exists: ${!!aiMessagesMap}, keys: ${aiMessagesMap ? Object.keys(aiMessagesMap).length : 0}`);
  
  if (useAiPersonalization && (!aiMessagesMap || Object.keys(aiMessagesMap).length === 0)) {
    console.log(`🤖 Generating AI-personalized messages for ${targetContacts.length} contacts...`);
    try {
      const { GoogleAIService } = await import('@/lib/ai/google-ai-service');
      const aiService = new GoogleAIService();
      
      // Concurrency limiter to utilize all 20 API keys in parallel
      class ConcurrencyLimiter {
        private queue: Array<{ fn: () => Promise<unknown>; resolve: (value: unknown) => void; reject: (error: unknown) => void }> = [];
        private running = 0;
        constructor(private limit: number) {}
        async execute<T>(fn: () => Promise<T>): Promise<T> {
          return new Promise<T>((resolve, reject) => {
            this.queue.push({ fn: fn as () => Promise<unknown>, resolve: resolve as (value: unknown) => void, reject: reject as (error: unknown) => void });
            this.process();
          });
        }
        private async process() {
          while (this.running < this.limit && this.queue.length > 0) {
            const task = this.queue.shift();
            if (!task) break;
            this.running++;
            task.fn().then(task.resolve).catch(task.reject).finally(() => {
              this.running--;
              this.process();
            });
          }
        }
      }
      
      const messageGenerationLimiter = new ConcurrencyLimiter(50); // Increased to 50 to utilize all 20 API keys
      aiMessagesMap = {};
      
      // Process all contacts in parallel with concurrency limit
      await Promise.all(
        targetContacts.map(async (contact) => {
          return messageGenerationLimiter.execute(async () => {
            try {
              // Fetch conversation history
              const messages = await prisma.message.findMany({
                where: { contactId: contact.id },
                orderBy: { createdAt: 'desc' },
                take: 10,
              });

              const conversationHistory = messages
                .reverse()
                .map((msg) => ({
                  from: msg.isFromBusiness ? 'Business' : contact.firstName,
                  message: msg.content,
                  timestamp: msg.createdAt.toISOString(),
                }));

              const templateContent = campaign.template?.content || 'Hello {firstName}!';
              const context = {
                contactName: contact.firstName,
                conversationHistory,
                templateMessage: templateContent,
                customInstructions: (campaign as any).aiCustomInstructions || undefined,
              };

              const personalizedMessage = await aiService.generatePersonalizedMessage(context);
              aiMessagesMap![contact.id] = personalizedMessage;
            } catch (error) {
              console.error(`[AI Generation] Failed for contact ${contact.id}:`, error);
              // Fallback to template
              const fallbackMessage = (campaign.template?.content || 'Hello!')
                .replace(/\{firstName\}/g, contact.firstName)
                .replace(/\{lastName\}/g, contact.lastName || '')
                .replace(/\{name\}/g, `${contact.firstName} ${contact.lastName || ''}`.trim());
              aiMessagesMap![contact.id] = fallbackMessage;
            }
          });
        })
      );
      
      // Save generated messages to campaign
      await prisma.campaign.update({
        where: { id: campaignId },
        data: { aiMessagesMap: aiMessagesMap as any },
      });
      
      console.log(`✅ Generated ${Object.keys(aiMessagesMap).length} AI-personalized messages`);
    } catch (error) {
      console.error('[AI Generation] Fatal error:', error);
      // Continue with template messages
      aiMessagesMap = null;
    }
  }
  
  const useAiMessages = useAiPersonalization && aiMessagesMap;
  
  if (useAiMessages && aiMessagesMap) {
    console.log(`📝 Using AI-personalized messages for ${Object.keys(aiMessagesMap).length} contacts`);
  }
  
  const messages = targetContacts.map((contact) => {
    let messageContent: string;
    
    // Use AI-generated message if available, otherwise use template
    if (useAiMessages && aiMessagesMap && aiMessagesMap[contact.id]) {
      messageContent = aiMessagesMap[contact.id];
      console.log(`✨ Using AI message for ${contact.firstName} (${contact.id}): "${messageContent.substring(0, 50)}..."`);
    } else {
      // Fallback to template with variable replacement
      if (useAiMessages && aiMessagesMap) {
        console.log(`⚠️ AI message not found for contact ${contact.id} (${contact.firstName}), using template. Available keys: ${Object.keys(aiMessagesMap).join(', ')}`);
      }
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
  console.log(`📊 Message preparation details:`, {
    campaignId: campaign.id,
    totalContacts: targetContacts.length,
    messagesPrepared: messages.length,
    platform: campaign.platform,
    hasValidRecipients: messages.filter(m => m.recipientId).length,
    missingRecipients: messages.filter(m => !m.recipientId).length,
  });
  
  // Validate that we have messages to send
  if (messages.length === 0) {
    console.error(`❌ No messages prepared for campaign ${campaign.id}`);
    await prisma.campaign.update({
      where: { id: campaign.id },
      data: {
        status: 'COMPLETED',
        totalRecipients: 0,
        completedAt: new Date(),
      },
    });
    throw new Error('No messages prepared for sending. Check that contacts have valid PSIDs/SIDs.');
  }
  
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

