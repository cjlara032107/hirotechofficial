import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * GET /api/ai-assistant/chats
 * List all chats for the current user
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const chats = await prisma.assistantChat.findMany({
      where: {
        userId: session.user.id,
        organizationId: session.user.organizationId,
      },
      orderBy: { updatedAt: 'desc' },
      include: {
        messages: {
          take: 1,
          orderBy: { createdAt: 'asc' },
        },
        _count: {
          select: { messages: true },
        },
      },
    });

    return NextResponse.json(chats);
  } catch (error) {
    console.error('Get chats error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch chats' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/ai-assistant/chats
 * Create a new chat
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { title } = body;

    const chat = await prisma.assistantChat.create({
      data: {
        userId: session.user.id,
        organizationId: session.user.organizationId!,
        title: title || 'New Chat',
      },
    });

    return NextResponse.json(chat);
  } catch (error) {
    console.error('Create chat error:', error);
    return NextResponse.json(
      { error: 'Failed to create chat' },
      { status: 500 }
    );
  }
}



