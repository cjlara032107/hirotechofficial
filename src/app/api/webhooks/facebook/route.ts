import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { prisma } from '@/lib/db';

// Webhook event types
interface WebhookMessage {
  mid: string;
  text?: string;
  attachments?: Array<{ type: string; payload: { url?: string } }>;
}

interface WebhookEvent {
  sender: { id: string };
  recipient: { id: string };
  timestamp: number;
  message?: WebhookMessage;
  read?: { watermark: number };
  delivery?: { mids: string[]; watermark: number };
  postback?: { title: string; payload: string };
}

// ⭐ AI AUTOMATION: Handle automation stops when user replies
async function handleAutomationStop(contactId: string, senderPSID: string) {
  try {
    // Find all active automation rules that have stopOnReply enabled
    const activeRules = await prisma.aIAutomationRule.findMany({
      where: {
        enabled: true,
        stopOnReply: true,
      },
    });

    if (activeRules.length === 0) {
      return;
    }

    // Check if any of these rules have sent messages to this contact
    const executions = await prisma.aIAutomationExecution.findMany({
      where: {
        contactId,
        ruleId: { in: activeRules.map(r => r.id) },
        status: 'sent',
      },
      distinct: ['ruleId'],
      orderBy: {
        executedAt: 'desc',
      },
    });

    if (executions.length === 0) {
      return;
    }

    console.log(`[Webhook] Contact ${contactId} replied - stopping ${executions.length} automation rules`);

    // Create stop records for each rule (prevents duplicates with unique constraint)
    for (const execution of executions) {
      try {
        const rule = activeRules.find(r => r.id === execution.ruleId);
        if (!rule) continue;

        // Check if stop record already exists
        const existingStop = await prisma.aIAutomationStop.findUnique({
          where: {
            ruleId_contactId: {
              ruleId: rule.id,
              contactId,
            },
          },
        });

        if (existingStop) {
          console.log(`[Webhook] Stop record already exists for rule ${rule.id} and contact ${contactId}`);
          continue;
        }

        // Create stop record
        const stop = await prisma.aIAutomationStop.create({
          data: {
            id: `stop_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            ruleId: rule.id,
            contactId,
            recipientPSID: senderPSID,
            stoppedReason: 'User replied to automated message',
            followUpsSent: 1, // At least one was sent
          },
        });

        console.log(`[Webhook] Created stop record for rule ${rule.name} (${rule.id})`);

        // Remove tag if configured
        if (rule.removeTagOnReply) {
          const contact = await prisma.contact.findUnique({
            where: { id: contactId },
            select: { tags: true },
          });

          if (contact && contact.tags.includes(rule.removeTagOnReply)) {
            await prisma.contact.update({
              where: { id: contactId },
              data: {
                tags: contact.tags.filter(tag => tag !== rule.removeTagOnReply),
              },
            });

            // Update stop record with removed tag
            await prisma.aIAutomationStop.update({
              where: { id: stop.id },
              data: {
                tagRemoved: rule.removeTagOnReply,
              },
            });

            console.log(`[Webhook] Removed tag "${rule.removeTagOnReply}" from contact ${contactId}`);
          }
        }
      } catch (error) {
        console.error(`[Webhook] Error creating stop record for rule ${execution.ruleId}:`, error);
      }
    }
  } catch (error) {
    console.error('[Webhook] Error handling automation stop:', error);
  }
}

// Webhook verification
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const mode = searchParams.get('hub.mode');
  const token = searchParams.get('hub.verify_token');
  const challenge = searchParams.get('hub.challenge');

  if (mode === 'subscribe' && token === process.env.FACEBOOK_WEBHOOK_VERIFY_TOKEN) {
    return new NextResponse(challenge, { status: 200 });
  }

  return new NextResponse('Forbidden', { status: 403 });
}

// Webhook events
export async function POST(request: NextRequest) {
  const body = await request.text();
  const signature = request.headers.get('x-hub-signature-256');

  // Verify signature
  const expectedSignature = crypto
    .createHmac('sha256', process.env.FACEBOOK_APP_SECRET!)
    .update(body)
    .digest('hex');

  if (`sha256=${expectedSignature}` !== signature) {
    return new NextResponse('Invalid signature', { status: 403 });
  }

  const data = JSON.parse(body);

  // Log webhook event
  await prisma.webhookEvent.create({
    data: {
      platform: 'MESSENGER',
      eventType: data.object || 'unknown',
      payload: data,
      processed: false,
    },
  });

  // Process webhook event
  try {
    for (const entry of data.entry || []) {
      // Messenger events
      if (entry.messaging) {
        for (const event of entry.messaging) {
          if (event.message && !event.message.is_echo) {
            await handleIncomingMessage(event);
          }
          if (event.delivery) {
            await handleDeliveryReceipt(event);
          }
          if (event.read) {
            await handleReadReceipt(event);
          }
        }
      }

      // Instagram/WhatsApp events
      if (entry.changes) {
        for (const change of entry.changes) {
          if (change.field === 'messages' && change.value) {
            await handleInstagramMessage(change.value);
          }
        }
      }
    }
  } catch (error) {
    console.error('Webhook processing error:', error);
  }

  return NextResponse.json({ success: true });
}

async function handleIncomingMessage(event: WebhookEvent) {
  try {
    const senderId = event.sender.id;
    const recipientId = event.recipient.id;
    const message = event.message;

    // Find the Facebook page
    const page = await prisma.facebookPage.findFirst({
      where: { pageId: recipientId },
    });

    if (!page) {
      console.error(`Page not found for pageId: ${recipientId}`);
      return;
    }

    // Find or create contact
    let contact = await prisma.contact.findFirst({
      where: { 
        messengerPSID: senderId,
        facebookPageId: page.id,
      },
    });

    // Auto-create contact if doesn't exist (webhook-based contact creation)
    if (!contact) {
      try {
        // Fetch profile from Graph API to enrich contact
        const { FacebookClient } = await import('@/lib/facebook/client');
        const client = new FacebookClient(page.pageAccessToken);
        const profile = await client.getMessengerProfile(senderId);

        contact = await prisma.contact.create({
          data: {
            messengerPSID: senderId,
            firstName: profile.first_name || 'Unknown',
            lastName: profile.last_name,
            profilePicUrl: profile.profile_pic,
            locale: profile.locale,
            timezone: profile.timezone,
            hasMessenger: true,
            organizationId: page.organizationId,
            facebookPageId: page.id,
            lastInteraction: new Date(),
          },
        });

        // Log new contact activity
        await prisma.contactActivity.create({
          data: {
            contactId: contact.id,
            type: 'MESSAGE_RECEIVED',
            title: 'New contact from webhook',
            description: 'Contact created automatically from incoming message',
          },
        });
      } catch (error) {
        console.error('Failed to create contact from webhook:', error);
        // Create minimal contact if profile fetch fails
        contact = await prisma.contact.create({
          data: {
            messengerPSID: senderId,
            firstName: 'Unknown',
            hasMessenger: true,
            organizationId: page.organizationId,
            facebookPageId: page.id,
            lastInteraction: new Date(),
          },
        });
      }
    }

    // Find or create conversation
    let conversation = await prisma.conversation.findFirst({
      where: {
        contactId: contact.id,
        platform: 'MESSENGER',
      },
    });

    if (!conversation) {
      conversation = await prisma.conversation.create({
        data: {
          contactId: contact.id,
          facebookPageId: page.id,
          platform: 'MESSENGER',
          status: 'OPEN',
          lastMessageAt: new Date(),
        },
      });
    }

    // Save message
    await prisma.message.create({
      data: {
        content: message?.text || '[Media]',
        platform: 'MESSENGER',
        status: 'DELIVERED',
        facebookMessageId: message?.mid,
        contactId: contact.id,
        conversationId: conversation.id,
        isFromBusiness: false,
        deliveredAt: new Date(),
      },
    });

    // Update conversation
    await prisma.conversation.update({
      where: { id: conversation.id },
      data: { 
        lastMessageAt: new Date(),
        status: 'OPEN',
      },
    });

    // Update contact last interaction
    await prisma.contact.update({
      where: { id: contact.id },
      data: { lastInteraction: new Date() },
    });

    // Log activity
    await prisma.contactActivity.create({
      data: {
        contactId: contact.id,
        type: 'MESSAGE_RECEIVED',
        title: 'Message received',
        description: message?.text?.substring(0, 100),
      },
    });

    // ⭐ AI AUTOMATION: Stop automations when user replies
    await handleAutomationStop(contact.id, senderId);
  } catch (error) {
    console.error('Error handling incoming message:', error);
  }
}

async function handleDeliveryReceipt(event: WebhookEvent) {
  try {
    if (!event.delivery) return;
    const mids = event.delivery.mids || [];

    // Update messages and get campaign IDs
    const updatedMessages = await prisma.message.findMany({
      where: {
        facebookMessageId: { in: mids },
        status: { not: 'DELIVERED' }, // Only update messages that aren't already delivered
      },
      select: {
        id: true,
        campaignId: true,
        status: true,
      },
    });

    if (updatedMessages.length === 0) return;

    // Update message statuses
    await prisma.message.updateMany({
      where: {
        facebookMessageId: { in: mids },
        status: { not: 'DELIVERED' },
      },
      data: {
        status: 'DELIVERED',
        deliveredAt: new Date(event.delivery.watermark),
      },
    });

    // Update campaign deliveredCount for each unique campaign
    const campaignIds = [...new Set(updatedMessages.map(m => m.campaignId).filter(Boolean))];
    
    for (const campaignId of campaignIds) {
      if (!campaignId) continue;
      
      // Count how many messages from this campaign were just delivered
      const campaignMessageCount = updatedMessages.filter(
        m => m.campaignId === campaignId && m.status !== 'DELIVERED'
      ).length;
      
      if (campaignMessageCount > 0) {
        try {
          await prisma.campaign.update({
            where: { id: campaignId },
            data: {
              deliveredCount: { increment: campaignMessageCount },
            },
          });
          console.log(`✅ Updated campaign ${campaignId}: +${campaignMessageCount} delivered`);
        } catch (error) {
          console.error(`Error updating campaign ${campaignId} deliveredCount:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error handling delivery receipt:', error);
  }
}

async function handleReadReceipt(event: WebhookEvent) {
  try {
    if (!event.read) return;
    const senderId = event.sender.id;

    // Find contact
    const contact = await prisma.contact.findFirst({
      where: { messengerPSID: senderId },
    });

    if (!contact) return;

    // Get messages that will be updated
    const messagesToUpdate = await prisma.message.findMany({
      where: {
        contactId: contact.id,
        isFromBusiness: true,
        sentAt: { lte: new Date(event.read.watermark) },
        status: { not: 'READ' },
      },
      select: {
        id: true,
        campaignId: true,
        status: true,
      },
    });

    if (messagesToUpdate.length === 0) return;

    // Update messages as read
    await prisma.message.updateMany({
      where: {
        contactId: contact.id,
        isFromBusiness: true,
        sentAt: { lte: new Date(event.read.watermark) },
        status: { not: 'READ' },
      },
      data: {
        status: 'READ',
        readAt: new Date(event.read.watermark),
      },
    });

    // Update campaign readCount for each unique campaign
    const campaignIds = [...new Set(messagesToUpdate.map(m => m.campaignId).filter(Boolean))];
    
    for (const campaignId of campaignIds) {
      if (!campaignId) continue;
      
      // Count how many messages from this campaign were just read
      const campaignMessageCount = messagesToUpdate.filter(
        m => m.campaignId === campaignId && m.status !== 'READ'
      ).length;
      
      if (campaignMessageCount > 0) {
        try {
          await prisma.campaign.update({
            where: { id: campaignId },
            data: {
              readCount: { increment: campaignMessageCount },
            },
          });
          console.log(`✅ Updated campaign ${campaignId}: +${campaignMessageCount} read`);
        } catch (error) {
          console.error(`Error updating campaign ${campaignId} readCount:`, error);
        }
      }
    }
  } catch (error) {
    console.error('Error handling read receipt:', error);
  }
}

async function handleInstagramMessage(value: WebhookEvent) {
  try {
    const senderId = value.sender?.id;
    const recipientId = value.recipient?.id;
    const message = value.message;

    if (!senderId || !recipientId || !message) {
      console.log('Incomplete Instagram message data:', value);
      return;
    }

    // Find the Facebook page by Instagram account
    const page = await prisma.facebookPage.findFirst({
      where: { instagramAccountId: recipientId },
    });

    if (!page) {
      console.error(`Page not found for Instagram account: ${recipientId}`);
      return;
    }

    // Find or create contact
    let contact = await prisma.contact.findFirst({
      where: { 
        instagramSID: senderId,
        facebookPageId: page.id,
      },
    });

    // Auto-create contact if doesn't exist (webhook-based contact creation)
    if (!contact) {
      try {
        // Fetch profile from Graph API to enrich contact
        const { FacebookClient } = await import('@/lib/facebook/client');
        const client = new FacebookClient(page.pageAccessToken);
        const profile = await client.getInstagramProfile(senderId);

        contact = await prisma.contact.create({
          data: {
            instagramSID: senderId,
            firstName: profile.name || profile.username || 'Unknown',
            profilePicUrl: profile.profile_picture_url,
            hasInstagram: true,
            organizationId: page.organizationId,
            facebookPageId: page.id,
            lastInteraction: new Date(),
          },
        });

        // Log new contact activity
        await prisma.contactActivity.create({
          data: {
            contactId: contact.id,
            type: 'MESSAGE_RECEIVED',
            title: 'New Instagram contact from webhook',
            description: 'Contact created automatically from incoming Instagram message',
          },
        });
      } catch (error) {
        console.error('Failed to create Instagram contact from webhook:', error);
        // Create minimal contact if profile fetch fails
        contact = await prisma.contact.create({
          data: {
            instagramSID: senderId,
            firstName: 'Unknown',
            hasInstagram: true,
            organizationId: page.organizationId,
            facebookPageId: page.id,
            lastInteraction: new Date(),
          },
        });
      }
    }

    // Find or create conversation
    let conversation = await prisma.conversation.findFirst({
      where: {
        contactId: contact.id,
        platform: 'INSTAGRAM',
      },
    });

    if (!conversation) {
      conversation = await prisma.conversation.create({
        data: {
          contactId: contact.id,
          facebookPageId: page.id,
          platform: 'INSTAGRAM',
          status: 'OPEN',
          lastMessageAt: new Date(),
        },
      });
    }

    // Save message
    await prisma.message.create({
      data: {
        content: message?.text || '[Media]',
        platform: 'INSTAGRAM',
        status: 'DELIVERED',
        facebookMessageId: message?.mid,
        contactId: contact.id,
        conversationId: conversation.id,
        isFromBusiness: false,
        deliveredAt: new Date(),
      },
    });

    // Update conversation
    await prisma.conversation.update({
      where: { id: conversation.id },
      data: { 
        lastMessageAt: new Date(),
        status: 'OPEN',
      },
    });

    // Update contact last interaction
    await prisma.contact.update({
      where: { id: contact.id },
      data: { lastInteraction: new Date() },
    });

    // Log activity
    await prisma.contactActivity.create({
      data: {
        contactId: contact.id,
        type: 'MESSAGE_RECEIVED',
        title: 'Instagram message received',
        description: message?.text?.substring(0, 100),
      },
    });

    // ⭐ AI AUTOMATION: Stop automations when user replies
    await handleAutomationStop(contact.id, senderId);
  } catch (error) {
    console.error('Error handling Instagram message:', error);
  }
}

