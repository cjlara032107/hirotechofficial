import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'

interface RouteParams {
  params: Promise<{ id: string; messageId: string }>
}

/**
 * DELETE /api/teams/[id]/messages/[messageId]/remove-reaction
 * Remove a specific reaction from a message
 */
export async function DELETE(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id, messageId } = await params
    const { searchParams } = new URL(request.url)
    const emoji = searchParams.get('emoji')

    if (!emoji) {
      return NextResponse.json(
        { error: 'Emoji parameter is required' },
        { status: 400 }
      )
    }

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
      where: { id: messageId }
    })

    if (!message) {
      return NextResponse.json({ error: 'Message not found' }, { status: 404 })
    }

    // Get current reactions
    const reactions = (message.reactions as Record<string, string[]>) || {}

    // Remove user's reaction
    if (reactions[emoji]) {
      reactions[emoji] = reactions[emoji].filter(id => id !== member.id)
      if (reactions[emoji].length === 0) {
        delete reactions[emoji]
      }
    }

    const updatedMessage = await prisma.teamMessage.update({
      where: { id: messageId },
      data: { reactions },
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
        }
      }
    })

    return NextResponse.json({ message: updatedMessage })
  } catch (error) {
    console.error('Error removing reaction:', error)
    return NextResponse.json(
      { error: 'Failed to remove reaction' },
      { status: 500 }
    )
  }
}

