import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { prisma } from '@/lib/db';

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

interface WebhookEvent {
  sender: { id: string };
  recipient: { id: string };
  message?: {
    mid: string;
    text?: string;
    attachments?: Array<{
      type: string;
      payload: { url: string };
    }>;
  };
  delivery?: {
    mids?: string[];
    watermark: number;
  };
  read?: {
    watermark: number;
  };
}

async function handleIncomingMessage(event: WebhookEvent) {
  try {
    const senderId = event.sender.id;
    const recipientId = event.recipient.id;
    const message = event.message;

    if (!message) {
      console.error('No message data in event');
      return;
    }

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
        content: message.text || '[Media]',
        platform: 'MESSENGER',
        status: 'DELIVERED',
        facebookMessageId: message.mid,
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
        description: message.text?.substring(0, 100),
      },
    });
  } catch (error) {
    console.error('Error handling incoming message:', error);
  }
}

async function handleDeliveryReceipt(event: WebhookEvent) {
  try {
    if (!event.delivery) {
      console.error('No delivery data in event');
      return;
    }

    const mids = event.delivery.mids || [];

    await prisma.message.updateMany({
      where: {
        facebookMessageId: { in: mids },
      },
      data: {
        status: 'DELIVERED',
        deliveredAt: new Date(event.delivery.watermark),
      },
    });
  } catch (error) {
    console.error('Error handling delivery receipt:', error);
  }
}

async function handleReadReceipt(event: WebhookEvent) {
  try {
    if (!event.read) {
      console.error('No read data in event');
      return;
    }

    const senderId = event.sender.id;

    // Find contact
    const contact = await prisma.contact.findFirst({
      where: { messengerPSID: senderId },
    });

    if (!contact) return;

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
        content: message.text || '[Media]',
        platform: 'INSTAGRAM',
        status: 'DELIVERED',
        facebookMessageId: message.mid,
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
        description: message.text?.substring(0, 100),
      },
    });
  } catch (error) {
    console.error('Error handling Instagram message:', error);
  }
}

