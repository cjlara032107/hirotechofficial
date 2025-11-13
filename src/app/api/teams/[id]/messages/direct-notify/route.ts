import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/teams/[id]/messages/direct-notify
 * Send notification for one-on-one messages
 */
export async function POST(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id } = await params
    const body = await request.json()
    const { messageId, recipientId } = body

    if (!messageId || !recipientId) {
      return NextResponse.json(
        { error: 'MessageId and recipientId are required' },
        { status: 400 }
      )
    }

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      },
      include: {
        user: {
          select: {
            name: true,
            email: true
          }
        }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const message = await prisma.teamMessage.findUnique({
      where: { id: messageId },
      include: {
        thread: {
          select: {
            id: true,
            title: true,
            type: true,
            participantIds: true
          }
        }
      }
    })

    if (!message) {
      return NextResponse.json({ error: 'Message not found' }, { status: 404 })
    }

    // Verify it's a direct message (1-on-1)
    if (message.thread?.type !== 'DIRECT') {
      return NextResponse.json(
        { error: 'This is not a direct message' },
        { status: 400 }
      )
    }

    // Verify recipient is part of the conversation
    if (!message.thread.participantIds.includes(recipientId)) {
      return NextResponse.json(
        { error: 'Recipient is not part of this conversation' },
        { status: 400 }
      )
    }

    // Create notification
    const notification = await prisma.teamNotification.create({
      data: {
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        memberId: recipientId,
        type: 'MESSAGE_REPLY',
        title: 'New direct message',
        message: `${member.user.name || member.user.email}: ${message.content.substring(0, 100)}`,
        entityType: 'message',
        entityId: message.id,
        entityUrl: `/team?threadId=${message.threadId}`,
        isRead: false
      }
    })

    return NextResponse.json({ 
      success: true,
      notification 
    })
  } catch (error) {
    console.error('Error sending direct message notification:', error)
    return NextResponse.json(
      { error: 'Failed to send notification' },
      { status: 500 }
    )
  }
}

