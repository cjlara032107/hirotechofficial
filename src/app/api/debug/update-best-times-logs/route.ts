import { NextRequest, NextResponse } from 'next/server';
import { Prisma } from '@prisma/client';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * Debug endpoint to view recent UpdateBestTimes logs
 * GET /api/debug/update-best-times-logs?limit=20&contactId=xxx
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '20', 10);
    const contactId = searchParams.get('contactId');

    // Get recent contacts that were updated (check bestContactTimes updatedAt)
    const recentContacts = await prisma.contact.findMany({
      where: {
        organizationId: session.user.organizationId,
        ...(contactId && { id: contactId }),
        bestContactTimes: { not: Prisma.JsonNull },
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        bestContactTimes: true,
        updatedAt: true,
      },
      orderBy: {
        updatedAt: 'desc',
      },
      take: Math.min(limit, 50),
    });

    // Get message counts for these contacts
    const contactsWithMessageCounts = await Promise.all(
      recentContacts.map(async (contact) => {
        const messageCount = await prisma.message.count({
          where: { contactId: contact.id },
        });
        
        const conversationCount = await prisma.conversation.count({
          where: { contactId: contact.id },
        });

        // Check if messages exist via conversations
        let messagesViaConversations = 0;
        if (messageCount === 0 && conversationCount > 0) {
          const conversations = await prisma.conversation.findMany({
            where: { contactId: contact.id },
            select: { id: true },
          });
          messagesViaConversations = await prisma.message.count({
            where: {
              conversationId: { in: conversations.map(c => c.id) },
            },
          });
        }

        const bestTimes = contact.bestContactTimes as Record<string, unknown> | null;
        const isBorrowed = bestTimes?.isBorrowed === true;
        const totalMessagesAnalyzed = bestTimes?.totalMessagesAnalyzed as number | undefined;

        return {
          contactId: contact.id,
          name: `${contact.firstName} ${contact.lastName || ''}`.trim(),
          messageCount,
          conversationCount,
          messagesViaConversations,
          hasDataIntegrityIssue: messagesViaConversations > 0 && messageCount === 0,
          bestContactTimes: {
            isBorrowed,
            totalMessagesAnalyzed,
            hasBestTimes: !!bestTimes?.bestContactTimes,
            borrowedFrom: bestTimes?.borrowedFrom,
            source: bestTimes?.borrowedSource,
          },
          lastUpdated: contact.updatedAt.toISOString(),
        };
      })
    );

    return NextResponse.json({
      summary: {
        total: contactsWithMessageCounts.length,
        withMessages: contactsWithMessageCounts.filter(c => c.messageCount > 0).length,
        withoutMessages: contactsWithMessageCounts.filter(c => c.messageCount === 0).length,
        withDataIntegrityIssues: contactsWithMessageCounts.filter(c => c.hasDataIntegrityIssue).length,
        withBorrowedTimes: contactsWithMessageCounts.filter(c => c.bestContactTimes.isBorrowed).length,
      },
      contacts: contactsWithMessageCounts,
    });
  } catch (error) {
    console.error('[Debug UpdateBestTimes Logs] Error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Failed to fetch logs',
      },
      { status: 500 }
    );
  }
}

