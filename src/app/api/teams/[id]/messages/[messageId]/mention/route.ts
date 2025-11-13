import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { notifyMentioned } from '@/lib/teams/notifications'

interface RouteParams {
  params: Promise<{ id: string; messageId: string }>
}

/**
 * POST /api/teams/[id]/messages/[messageId]/mention
 * Add mentions to a message and send notifications
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

    const { id, messageId } = await params

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
      where: { id: messageId }
    })

    if (!message) {
      return NextResponse.json({ error: 'Message not found' }, { status: 404 })
    }

    // Only the message sender can update mentions
    if (message.senderId !== member.id) {
      return NextResponse.json(
        { error: 'You can only update mentions in your own messages' },
        { status: 403 }
      )
    }

    const body = await request.json()
    const { mentions } = body

    if (!mentions || !Array.isArray(mentions)) {
      return NextResponse.json(
        { error: 'Mentions array is required' },
        { status: 400 }
      )
    }

    // Validate all mentioned users are team members
    const mentionedMembers = await prisma.teamMember.findMany({
      where: {
        id: { in: mentions },
        teamId: id,
        status: 'ACTIVE'
      }
    })

    if (mentionedMembers.length !== mentions.length) {
      return NextResponse.json(
        { error: 'Some mentioned users are not valid team members' },
        { status: 400 }
      )
    }

    // Update message with mentions
    const updatedMessage = await prisma.teamMessage.update({
      where: { id: messageId },
      data: { mentions },
      include: {
        sender: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                image: true
              }
            }
          }
        },
        thread: {
          select: {
            id: true,
            title: true,
            type: true
          }
        }
      }
    })

    // Send notifications to mentioned users (excluding self)
    const mentionsToNotify = mentions.filter(m => m !== member.id)
    if (mentionsToNotify.length > 0) {
      const senderName = member.user?.name || member.user?.email || 'Someone'
      
      await notifyMentioned({
        messageId: message.id,
        threadId: message.threadId || '',
        mentionedMemberIds: mentionsToNotify,
        senderName,
        messagePreview: message.content,
        teamId: id
      }).catch(err => console.error('Failed to send mention notifications:', err))
    }

    return NextResponse.json({ message: updatedMessage })
  } catch (error) {
    console.error('Error updating mentions:', error)
    return NextResponse.json(
      { error: 'Failed to update mentions' },
      { status: 500 }
    )
  }
}

/**
 * GET /api/teams/[id]/messages/[messageId]/mention
 * Get all mentions for a message
 */
export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id, messageId } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const message = await prisma.teamMessage.findUnique({
      where: { id: messageId },
      select: {
        id: true,
        mentions: true
      }
    })

    if (!message) {
      return NextResponse.json({ error: 'Message not found' }, { status: 404 })
    }

    // Get details of mentioned members
    const mentionedMembers = await prisma.teamMember.findMany({
      where: {
        id: { in: message.mentions }
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true
          }
        }
      }
    })

    return NextResponse.json({ 
      mentions: message.mentions,
      mentionedMembers 
    })
  } catch (error) {
    console.error('Error fetching mentions:', error)
    return NextResponse.json(
      { error: 'Failed to fetch mentions' },
      { status: 500 }
    )
  }
}

