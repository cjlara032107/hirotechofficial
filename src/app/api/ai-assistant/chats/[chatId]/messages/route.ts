import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { processAssistantMessage } from '@/lib/ai/assistant-service';

/**
 * POST /api/ai-assistant/chats/[chatId]/messages
 * Send a message and get AI response
 */
export async function POST(
  request: NextRequest,
  props: { params: Promise<{ chatId: string }> }
) {
  try {
    const { chatId } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { content } = body;

    if (!content || typeof content !== 'string') {
      return NextResponse.json(
        { error: 'Message content is required' },
        { status: 400 }
      );
    }

    // Verify chat belongs to user
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

    // Save user message
    const userMessage = await prisma.assistantMessage.create({
      data: {
        chatId,
        role: 'USER',
        content,
      },
    });

    // Build chat history for context
    const chatHistory = chat.messages.map((msg) => ({
      role: msg.role.toLowerCase() as 'user' | 'assistant',
      content: msg.content,
    }));

    // Get AI response
    const { response, sources } = await processAssistantMessage(
      content,
      session.user.organizationId!,
      session.user.id,
      chatHistory
    );

    // Save assistant response
    const assistantMessage = await prisma.assistantMessage.create({
      data: {
        chatId,
        role: 'ASSISTANT',
        content: response,
        metadata: sources ? { sources } : undefined,
      },
    });

    // Update chat title if it's the first message
    if (chat.messages.length === 0 && !chat.title) {
      const title = content.length > 50 ? content.substring(0, 50) + '...' : content;
      await prisma.assistantChat.update({
        where: { id: chatId },
        data: { title },
      });
    }

    // Update chat updatedAt
    await prisma.assistantChat.update({
      where: { id: chatId },
      data: { updatedAt: new Date() },
    });

    return NextResponse.json({
      userMessage,
      assistantMessage,
    });
  } catch (error) {
    console.error('Send message error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to send message' },
      { status: 500 }
    );
  }
}

