import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; messageId: string }>
}

/**
 * POST /api/teams/[id]/messages/[messageId]/pin
 * Pin or unpin a message (admin only)
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
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Check if user is admin or owner (required to pin messages)
    const isAdmin = await isTeamAdmin(session.user.id, id)
    if (!isAdmin) {
      return NextResponse.json(
        { error: 'Only team admins can pin/unpin messages' },
        { status: 403 }
      )
    }

    const message = await prisma.teamMessage.findUnique({
      where: { id: messageId }
    })

    if (!message) {
      return NextResponse.json({ error: 'Message not found' }, { status: 404 })
    }

    if (message.teamId !== id) {
      return NextResponse.json(
        { error: 'Message does not belong to this team' },
        { status: 400 }
      )
    }

    const body = await request.json()
    const { pin } = body

    const isPinned = pin ?? !message.isPinned

    const updatedMessage = await prisma.teamMessage.update({
      where: { id: messageId },
      data: {
        isPinned,
        pinnedAt: isPinned ? new Date() : null,
        pinnedById: isPinned ? member.id : null
      },
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

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'EDIT_ENTITY',
      action: isPinned ? 'Pinned a message' : 'Unpinned a message',
      entityType: 'message',
      entityId: messageId,
      metadata: { messagePreview: message.content.substring(0, 50), action: isPinned ? 'pin' : 'unpin' }
    })

    return NextResponse.json({ message: updatedMessage })
  } catch (error) {
    console.error('Error pinning/unpinning message:', error)
    return NextResponse.json(
      { error: 'Failed to pin/unpin message' },
      { status: 500 }
    )
  }
}

