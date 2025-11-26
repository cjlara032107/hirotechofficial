import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * GET /api/ai-assistant/chats/[chatId]
 * Get chat with all messages
 */
export async function GET(
  request: NextRequest,
  props: { params: Promise<{ chatId: string }> }
) {
  try {
    const { chatId } = await props.params;
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
    console.error('Get chat error:', error);
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
  try {
    const { chatId } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    await prisma.assistantChat.delete({
      where: {
        id: chatId,
        userId: session.user.id,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Delete chat error:', error);
    return NextResponse.json(
      { error: 'Failed to delete chat' },
      { status: 500 }
    );
  }
}

