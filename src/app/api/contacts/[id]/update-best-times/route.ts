import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { computeAndStoreBestContactTimes } from '@/lib/contacts/compute-contact-times';
import { findNearestContactWithBestTimes } from '@/lib/contacts/find-nearest-contact-times';

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * POST /api/contacts/[id]/update-best-times
 * Manually trigger computation of best contact times for a specific contact
 */
export async function POST(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;

    // Verify contact exists and belongs to user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
      },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    // Get message count for better error messages
    // Messages are primarily linked via conversations, so check that way first (like the messages API does)
    const conversations = await prisma.conversation.findMany({
      where: { contactId: id },
      select: { id: true },
    });
    
    const conversationIds = conversations.map(c => c.id);
    const conversationCount = conversations.length;
    console.log(`[UpdateBestTimes] Contact ${id} has ${conversationCount} conversation(s)`);
    
    // Count messages via conversations (this is the correct way messages are linked)
    const messagesViaConversations = conversationIds.length > 0
      ? await prisma.message.count({
          where: { conversationId: { in: conversationIds } },
        })
      : 0;
    
    // Also check direct contactId count for data integrity detection
    const directMessageCount = await prisma.message.count({
      where: { contactId: id },
    });
    
    // Use the actual total message count (via conversations is the correct way)
    const messageCount = messagesViaConversations > 0 ? messagesViaConversations : directMessageCount;
    
    console.log(`[UpdateBestTimes] Contact ${id} (${contact.firstName} ${contact.lastName}) has ${messageCount} messages (direct: ${directMessageCount}, via conversations: ${messagesViaConversations})`);
    
    // Detect data integrity issues
    let hasDataIntegrityIssue = false;
    if (directMessageCount === 0 && messagesViaConversations > 0) {
      hasDataIntegrityIssue = true;
      console.error(`[UpdateBestTimes] DATA INTEGRITY ISSUE: Messages exist via conversations (${messagesViaConversations}) but not via contactId (${directMessageCount}). Messages may have incorrect contactId.`);
    }

    // Compute best contact times
    let result: Record<string, unknown> | null = null;
    try {
      result = await computeAndStoreBestContactTimes(id);
    } catch (error) {
      console.error('[UpdateBestTimes] Computation error:', error);
      return NextResponse.json(
        {
          success: false,
          error: error instanceof Error ? error.message : 'Failed to compute best contact times',
          details: error instanceof Error ? error.stack : undefined,
        },
        { status: 500 }
      );
    }

    if (!result) {
      // Try to find nearest contact with sufficient data
      const nearestContact = await findNearestContactWithBestTimes(id, session.user.organizationId);
      
      if (nearestContact) {
        // Use the nearest contact's best contact times
        // Mark it as borrowed from another contact
        const borrowedTimes = {
          ...nearestContact.bestContactTimes,
          borrowedFrom: nearestContact.contactId,
          borrowedSource: nearestContact.source,
          isBorrowed: true,
          originalContactId: id,
          originalMessageCount: messageCount,
        };

        // Store borrowed times in database
        await prisma.contact.update({
          where: { id },
          data: {
            bestContactTimes: borrowedTimes,
          },
        });

        return NextResponse.json(
          {
            success: true,
            message: messageCount === 0
              ? 'Contact has no messages. Using best contact times from a similar contact.'
              : `Insufficient message data (${messageCount} message${messageCount !== 1 ? 's' : ''} found, need at least 2). Using best contact times from a similar contact.`,
            data: borrowedTimes,
            isBorrowed: true,
            messageCount,
            source: nearestContact.source,
            guidance: messageCount === 0
              ? `To get personalized best contact times for this contact, ensure you have at least 2 messages. Currently using data from a similar contact (${nearestContact.source}).`
              : `To get personalized best contact times for this contact, ensure you have at least 2 messages. Currently using data from a similar contact (${nearestContact.source}).`,
          },
          { status: 200 }
        );
      }

      // If no similar contact found, return error with guidance
      let errorMessage: string;
      let guidance: string;
      
      if (messageCount === 0) {
        errorMessage = 'Contact has no messages. Please sync messages from Facebook or send/receive messages with this contact first.';
        guidance = 'To get best contact times, you need at least 2 messages with this contact. You can sync messages from Facebook or send/receive more messages.';
      } else {
        errorMessage = `Insufficient message data (${messageCount} message${messageCount !== 1 ? 's' : ''} found, need at least 2). No similar contacts with sufficient data were found.`;
        guidance = 'To get best contact times, ensure you have at least 2 messages with this contact. You can sync messages from Facebook or send/receive more messages. Once you have more contacts with message history, the system can use similar contacts\' data.';
      }
      
      // Add diagnostic information if data integrity issue detected
      if (hasDataIntegrityIssue && messagesViaConversations > 0) {
        errorMessage += ` Note: ${messagesViaConversations} message${messagesViaConversations !== 1 ? 's' : ''} found via conversations but not linked to contact. This may indicate a data integrity issue.`;
        guidance += ` The system detected ${messagesViaConversations} message${messagesViaConversations !== 1 ? 's' : ''} in conversations but they may not be properly linked to this contact. Please check your message sync or contact the administrator.`;
      }
      
      return NextResponse.json(
        {
          success: false,
          error: errorMessage,
          message: errorMessage,
          messageCount,
          messagesViaConversations: hasDataIntegrityIssue ? messagesViaConversations : undefined,
          hasDataIntegrityIssue,
          guidance,
        },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Best contact times updated successfully',
      data: result,
    });
  } catch (error) {
    console.error('[UpdateBestTimes] Error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update best contact times',
      },
      { status: 500 }
    );
  }
}





