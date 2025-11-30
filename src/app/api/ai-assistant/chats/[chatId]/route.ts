import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { logger } from '@/lib/utils/logger';

/**
 * GET /api/ai-assistant/chats/[chatId]
 * Get chat with all messages
 */
export async function GET(
  request: NextRequest,
  props: { params: Promise<{ chatId: string }> }
) {
  let chatId: string | undefined;
  try {
    const params = await props.params;
    chatId = params.chatId;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const chat = await prisma.assistantChat.findFirst({
      where: {
        id: chatId,
        userId: session.user.id,
        organizationId: session.user.organizationId,
      },
      include: {
        messages: {
          orderBy: { createdAt: 'asc' },
        },
      },
    });

    if (!chat) {
      return NextResponse.json({ error: 'Chat not found' }, { status: 404 });
    }

    return NextResponse.json(chat);
  } catch (error) {
    logger.error('Get chat error', error instanceof Error ? error : new Error(String(error)), chatId ? { chatId } : {});
    return NextResponse.json(
      { error: 'Failed to fetch chat' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/ai-assistant/chats/[chatId]
 * Delete a chat
 */
export async function DELETE(
  request: NextRequest,
  props: { params: Promise<{ chatId: string }> }
) {
  let chatId: string | undefined;
  try {
    const params = await props.params;
    chatId = params.chatId;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Verify chat belongs to user and organization before deleting
    const chat = await prisma.assistantChat.findFirst({
      where: {
        id: chatId,
        userId: session.user.id,
        organizationId: session.user.organizationId,
      },
    });

    if (!chat) {
      return NextResponse.json({ error: 'Chat not found' }, { status: 404 });
    }

    await prisma.assistantChat.delete({
      where: {
        id: chatId,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error('Delete chat error', error instanceof Error ? error : new Error(String(error)), chatId ? { chatId } : {});
    return NextResponse.json(
      { error: 'Failed to delete chat' },
      { status: 500 }
    );
  }
}







