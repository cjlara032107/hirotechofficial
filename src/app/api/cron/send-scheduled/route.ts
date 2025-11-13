import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { startCampaign, getTargetContacts } from '@/lib/campaigns/send';
import { analyzeConversation } from '@/lib/ai/google-ai-service';
import { FacebookClient } from '@/lib/facebook/client';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

/**
 * Cron job to check for and send scheduled campaigns
 * This endpoint is called by Vercel Cron every minute
 */
export async function GET(request: NextRequest) {
  try {
    // Security: Verify cron secret (optional)
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      console.log('[Cron Send Scheduled] Unauthorized access attempt');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const currentTime = new Date();
    console.log('[Cron Send Scheduled] Starting at', currentTime.toISOString());

    // Find all campaigns that are scheduled and due to be sent
    const dueCampaigns = await prisma.campaign.findMany({
      where: {
        status: 'SCHEDULED',
        scheduledAt: {
          lte: currentTime,
        },
      },
      include: {
        facebookPage: true,
        template: true,
      },
      orderBy: {
        scheduledAt: 'asc',
      },
      take: 10, // Process up to 10 campaigns per run to avoid timeout
    });

    if (dueCampaigns.length === 0) {
      console.log('[Cron Send Scheduled] No campaigns due');
      return NextResponse.json({
        success: true,
        dispatched: 0,
        message: 'No campaigns due',
      });
    }

    console.log(`[Cron Send Scheduled] Found ${dueCampaigns.length} due campaigns`);

    let dispatched = 0;
    let failed = 0;
    const results = [];

    for (const campaign of dueCampaigns) {
      try {
        console.log(`[Cron Send Scheduled] Processing campaign: ${campaign.id} - ${campaign.name}`);

        // STEP 1: Auto-fetch recipients if enabled (check if property exists for backward compatibility)
        if ('autoFetchEnabled' in campaign && campaign.autoFetchEnabled) {
          console.log('[Cron Send Scheduled] Auto-fetch enabled, fetching fresh recipients...');
          
          try {
            await autoFetchRecipients(campaign);
          } catch (autoFetchError) {
            console.error('[Cron Send Scheduled] Auto-fetch failed:', autoFetchError);
            // Continue with existing contacts if auto-fetch fails
          }
        }

        // STEP 2: Get target contacts
        const targetContacts = await getTargetContacts(campaign.id);
        console.log(`[Cron Send Scheduled] Target contacts: ${targetContacts.length}`);

        if (targetContacts.length === 0) {
          await prisma.campaign.update({
            where: { id: campaign.id },
            data: {
              status: 'COMPLETED',
              completedAt: new Date(),
            },
          });
          console.log(`[Cron Send Scheduled] Campaign ${campaign.id} has no recipients, marked as completed`);
          failed++;
          results.push({
            id: campaign.id,
            name: campaign.name,
            status: 'failed',
            error: 'No recipients found',
          });
          continue;
        }

        // STEP 3: AI Personalization if enabled
        let aiMessagesMap: Record<string, string> | null = null;
        
        if ('useAiPersonalization' in campaign && (campaign as any).useAiPersonalization && targetContacts.length > 0) {
          console.log(`[Cron Send Scheduled] AI personalization for ${targetContacts.length} contacts`);
          
          try {
            aiMessagesMap = await generateAIMessages(campaign, targetContacts);
            console.log(`[Cron Send Scheduled] Generated ${Object.keys(aiMessagesMap).length} AI messages`);
            
            // Update campaign with AI messages map
            await prisma.campaign.update({
              where: { id: campaign.id },
              data: {
                aiMessagesMap: aiMessagesMap,
              },
            });
          } catch (aiError) {
            console.error('[Cron Send Scheduled] AI generation error:', aiError);
            // Continue with standard template message
          }
        }

        // STEP 4: Update campaign total recipients
        await prisma.campaign.update({
          where: { id: campaign.id },
          data: {
            totalRecipients: targetContacts.length,
            lastFetchAt: ('autoFetchEnabled' in campaign && (campaign as any).autoFetchEnabled) ? new Date() : undefined,
            fetchCount: ('autoFetchEnabled' in campaign && (campaign as any).autoFetchEnabled) ? { increment: 1 } : undefined,
          },
        });

        // STEP 5: Start campaign (this will handle the actual sending)
        console.log(`[Cron Send Scheduled] Starting campaign ${campaign.id}...`);
        await startCampaign(campaign.id);
        
        dispatched++;
        results.push({
          id: campaign.id,
          name: campaign.name,
          status: 'started',
          recipients: targetContacts.length,
        });

        console.log(`[Cron Send Scheduled] ✅ Campaign ${campaign.id} started successfully`);

      } catch (error) {
        console.error(`[Cron Send Scheduled] Error processing campaign ${campaign.id}:`, error);
        
        // Mark campaign as failed
        try {
          await prisma.campaign.update({
            where: { id: campaign.id },
            data: {
              status: 'CANCELLED',
              completedAt: new Date(),
            },
          });
        } catch (updateError) {
          console.error(`[Cron Send Scheduled] Failed to update campaign status:`, updateError);
        }
        
        failed++;
        results.push({
          id: campaign.id,
          name: campaign.name,
          status: 'failed',
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    console.log(`[Cron Send Scheduled] Complete: ${dispatched} dispatched, ${failed} failed`);

    return NextResponse.json({
      success: true,
      dispatched,
      failed,
      results,
    });

  } catch (error) {
    console.error('[Cron Send Scheduled] Fatal error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Dispatch failed',
        success: false,
      },
      { status: 500 }
    );
  }
}

/**
 * Auto-fetch fresh recipients from Facebook and apply tag filters
 */
async function autoFetchRecipients(campaign: any) {
  console.log(`[Auto-Fetch] Starting for campaign ${campaign.id}`);
  
  const facebookPage = campaign.facebookPage;
  if (!facebookPage || !facebookPage.pageAccessToken) {
    throw new Error('Facebook page access token not found');
  }

  const client = new FacebookClient(facebookPage.pageAccessToken);

  // Fetch conversations from Facebook
  try {
    const conversations = await client.getConversations(facebookPage.pageId, 100);
    console.log(`[Auto-Fetch] Fetched ${conversations.length} conversations`);

    // Sync conversations to database
    for (const conv of conversations) {
      const participants = conv.participants?.data || [];
      
      for (const participant of participants) {
        if (participant.id === facebookPage.pageId) continue; // Skip page itself

        // Check if contact exists
        const existingContact = await prisma.contact.findFirst({
          where: {
            messengerPSID: participant.id,
            facebookPageId: facebookPage.id,
          },
        });

        if (!existingContact) {
          // Create new contact
          await prisma.contact.create({
            data: {
              firstName: participant.name || 'Facebook User',
              messengerPSID: participant.id,
              hasMessenger: true,
              organizationId: campaign.organizationId,
              facebookPageId: facebookPage.id,
              lastInteraction: new Date(),
            },
          });
        } else {
          // Update existing contact
          await prisma.contact.update({
            where: { id: existingContact.id },
            data: {
              lastInteraction: new Date(),
            },
          });
        }
      }
    }

    console.log(`[Auto-Fetch] Synced conversations to database`);

    // Apply tag filters
    let filteredContacts = await prisma.contact.findMany({
      where: {
        organizationId: campaign.organizationId,
        facebookPageId: campaign.facebookPageId,
        hasMessenger: campaign.platform === 'MESSENGER',
        hasInstagram: campaign.platform === 'INSTAGRAM',
      },
    });

    // Include tags filter
    if (campaign.includeTags && campaign.includeTags.length > 0) {
      filteredContacts = filteredContacts.filter((contact) => {
        return campaign.includeTags.every((tag: string) => contact.tags.includes(tag));
      });
    }

    // Exclude tags filter
    if (campaign.excludeTags && campaign.excludeTags.length > 0) {
      filteredContacts = filteredContacts.filter((contact) => {
        return !campaign.excludeTags.some((tag: string) => contact.tags.includes(tag));
      });
    }

    console.log(`[Auto-Fetch] After filters: ${filteredContacts.length} contacts`);

    // Update campaign with new target contacts
    await prisma.campaign.update({
      where: { id: campaign.id },
      data: {
        targetingType: 'SPECIFIC_CONTACTS',
        targetContactIds: filteredContacts.map((c) => c.id),
      },
    });

  } catch (error) {
    console.error('[Auto-Fetch] Error:', error);
    throw error;
  }
}

/**
 * Generate AI personalized messages for each contact
 */
async function generateAIMessages(campaign: any, contacts: any[]): Promise<Record<string, string>> {
  console.log(`[AI Generation] Starting for ${contacts.length} contacts`);
  
  const aiMessagesMap: Record<string, string> = {};
  const BATCH_SIZE = 5; // Process 5 contacts at a time

  try {
    for (let i = 0; i < contacts.length; i += BATCH_SIZE) {
      const batch = contacts.slice(i, i + BATCH_SIZE);
      console.log(`[AI Generation] Processing batch ${Math.floor(i / BATCH_SIZE) + 1}/${Math.ceil(contacts.length / BATCH_SIZE)}`);

      const batchPromises = batch.map(async (contact) => {
        try {
          // Fetch conversation history for context
          const messages = await prisma.message.findMany({
            where: {
              contactId: contact.id,
            },
            orderBy: {
              createdAt: 'desc',
            },
            take: 10, // Last 10 messages
          });

          const conversationHistory = messages.map((msg) => ({
            from: msg.isFromBusiness ? 'Business' : contact.firstName,
            message: msg.content,
            timestamp: msg.createdAt.toISOString(),
          }));

          // Generate personalized message using AI
          const templateContent = campaign.template?.content || 'Hello {firstName}!';
          const context = {
            contactName: contact.firstName,
            conversationHistory,
            templateMessage: templateContent,
            customInstructions: campaign.aiCustomInstructions || '',
          };

          // Generate personalized message using AI conversation analyzer
          const aiInsights = await analyzeConversation(
            conversationHistory.map(msg => ({
              from: msg.from,
              text: msg.message,
              timestamp: new Date(msg.timestamp)
            }))
          );
          
          // Create personalized message based on AI insights and template
          let personalizedMessage = templateContent
            .replace(/\{firstName\}/g, contact.firstName)
            .replace(/\{lastName\}/g, contact.lastName || '')
            .replace(/\{name\}/g, `${contact.firstName} ${contact.lastName || ''}`.trim());
          
          // Add AI-generated context if available
          if (aiInsights) {
            personalizedMessage = `${personalizedMessage}\n\n${aiInsights}`;
          }
          
          aiMessagesMap[contact.id] = personalizedMessage;
          
          console.log(`[AI Generation] ✅ Generated for ${contact.firstName}`);
        } catch (error) {
          console.error(`[AI Generation] Failed for contact ${contact.id}:`, error);
          // Fallback to template message
          const fallbackMessage = (campaign.template?.content || 'Hello!')
            .replace(/\{firstName\}/g, contact.firstName)
            .replace(/\{lastName\}/g, contact.lastName || '')
            .replace(/\{name\}/g, `${contact.firstName} ${contact.lastName || ''}`.trim());
          
          aiMessagesMap[contact.id] = fallbackMessage;
        }
      });

      await Promise.all(batchPromises);

      // Rate limit delay between batches
      if (i + BATCH_SIZE < contacts.length) {
        await new Promise((resolve) => setTimeout(resolve, 2000)); // 2 second delay
      }
    }

    console.log(`[AI Generation] Complete: ${Object.keys(aiMessagesMap).length} messages generated`);
    return aiMessagesMap;
    
  } catch (error) {
    console.error('[AI Generation] Fatal error:', error);
    throw error;
  }
}
