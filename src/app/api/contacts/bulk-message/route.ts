import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { FacebookClient } from '@/lib/facebook/client';
import { validateSession } from '@/lib/api/validate-session';
import { RateLimitPresets } from '@/lib/api/rate-limit';
import { validateBodySize, BodySizeLimits } from '@/lib/api/validate-body-size';

export async function POST(request: NextRequest) {
  try {
    // Apply rate limiting
    const rateLimitResponse = await RateLimitPresets.standard(request);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    // Validate body size
    const bodySizeResponse = await validateBodySize(request, {
      maxSizeBytes: BodySizeLimits.LARGE,
    });
    if (bodySizeResponse) {
      return bodySizeResponse;
    }

    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const body = await request.json();
    const { contactIds, message, mediaUrl, mediaType, platform, messageTag } = body;

    if (!contactIds || !Array.isArray(contactIds) || contactIds.length === 0) {
      return NextResponse.json(
        { error: 'Contact IDs array is required' },
        { status: 400 }
      );
    }

    if (!message && !mediaUrl) {
      return NextResponse.json(
        { error: 'Either message text or media URL is required' },
        { status: 400 }
      );
    }

    if (mediaUrl && !mediaType) {
      return NextResponse.json(
        { error: 'Media type is required when media URL is provided' },
        { status: 400 }
      );
    }

    if (!platform) {
      return NextResponse.json(
        { error: 'Platform is required' },
        { status: 400 }
      );
    }

    // Validate contactIds array size
    if (contactIds.length > 1000) {
      return NextResponse.json(
        { error: 'Too many contact IDs. Maximum 1000 contacts per operation.' },
        { status: 400 }
      );
    }

    // Verify all contacts belong to user's organization
    const contacts = await prisma.contact.findMany({
      where: {
        id: { in: contactIds },
        organizationId: validatedSession.user.organizationId,
      },
      include: {
        facebookPage: {
          select: {
            id: true,
            pageAccessToken: true,
            pageName: true,
          },
        },
      },
    });

    if (contacts.length !== contactIds.length) {
      return NextResponse.json(
        { error: 'Some contacts not found or unauthorized' },
        { status: 404 }
      );
    }

    // Group contacts by Facebook page
    const contactsByPage = new Map<string, typeof contacts>();
    for (const contact of contacts) {
      if (!contact.facebookPage) {
        continue;
      }
      const pageId = contact.facebookPage.id;
      if (!contactsByPage.has(pageId)) {
        contactsByPage.set(pageId, []);
      }
      contactsByPage.get(pageId)!.push(contact);
    }

    let successCount = 0;
    let failCount = 0;
    const errors: Array<{ contactId: string; error: string }> = [];

    // Send messages in batches
    for (const [, pageContacts] of Array.from(contactsByPage.entries())) {
      const page = pageContacts[0].facebookPage!;
      const client = new FacebookClient(page.pageAccessToken);

      // Process contacts in batches of 10
      const BATCH_SIZE = 10;
      for (let i = 0; i < pageContacts.length; i += BATCH_SIZE) {
        const batch = pageContacts.slice(i, i + BATCH_SIZE);

        await Promise.all(
          batch.map(async (contact) => {
            try {
              const recipientId = platform === 'MESSENGER' 
                ? contact.messengerPSID 
                : contact.instagramSID;

              if (!recipientId) {
                throw new Error(`No recipient ID (PSID) available for contact`);
              }

              let result;
              if (mediaUrl) {
                // Send media message
                result = await client.sendMediaMessage({
                  recipientId,
                  message: message || undefined,
                  mediaUrl,
                  mediaType: mediaType as 'image' | 'video',
                  messageTag: messageTag || undefined,
                });
              } else {
                // Send text message
                if (platform === 'MESSENGER') {
                  result = await client.sendMessengerMessage({
                    recipientId,
                    message: message,
                    messageTag: messageTag || undefined,
                  });
                } else {
                  result = await client.sendInstagramMessage(recipientId, message);
                }
              }

              if (result.success) {
                // Get or create conversation
                let conversation = await prisma.conversation.findFirst({
                  where: {
                    contactId: contact.id,
                    platform: platform as 'MESSENGER' | 'INSTAGRAM',
                  },
                });

                if (!conversation) {
                  conversation = await prisma.conversation.create({
                    data: {
                      contactId: contact.id,
                      facebookPageId: page.id,
                      platform: platform as 'MESSENGER' | 'INSTAGRAM',
                      status: 'OPEN',
                      lastMessageAt: new Date(),
                      assignedToId: validatedSession.user.id,
                    },
                  });
                }

                // Create message record
                await prisma.message.create({
                  data: {
                    contactId: contact.id,
                    conversationId: conversation.id,
                    content: message || (mediaUrl ? `[${mediaType}]` : ''),
                    platform: platform as 'MESSENGER' | 'INSTAGRAM',
                    isFromBusiness: true,
                    messageTag: messageTag || null,
                    status: 'SENT',
                    facebookMessageId: result.data?.message_id,
                    sentAt: new Date(),
                    attachments: mediaUrl ? {
                      type: mediaType,
                      url: mediaUrl,
                    } : undefined,
                  },
                });

                // Update conversation
                await prisma.conversation.update({
                  where: { id: conversation.id },
                  data: { lastMessageAt: new Date() },
                });

                successCount++;
              } else {
                throw new Error(result.message || 'Failed to send message');
              }
            } catch (error: unknown) {
              failCount++;
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              errors.push({
                contactId: contact.id,
                error: errorMessage,
              });
            }
          })
        );

        // Small delay between batches to avoid rate limiting
        if (i + BATCH_SIZE < pageContacts.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
    }

    return NextResponse.json({
      success: true,
      sent: successCount,
      failed: failCount,
      total: contactIds.length,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error: unknown) {
    console.error('Bulk message error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to send bulk messages';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

