import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; threadId: string }>
}

/**
 * GET /api/teams/[id]/threads/[threadId]
 * Get thread details
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

    const { id, threadId } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const thread = await prisma.teamThread.findUnique({
      where: { id: threadId },
      include: {
        messages: {
          take: 50,
          orderBy: { createdAt: 'desc' },
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
        },
        _count: {
          select: {
            messages: true
          }
        }
      }
    })

    if (!thread) {
      return NextResponse.json({ error: 'Thread not found' }, { status: 404 })
    }

    if (thread.teamId !== id) {
      return NextResponse.json(
        { error: 'Thread does not belong to this team' },
        { status: 400 }
      )
    }

    // Get participant details
    const participants = await prisma.teamMember.findMany({
      where: {
        id: { in: thread.participantIds }
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            image: true
          }
        }
      }
    })

    return NextResponse.json({ 
      thread: {
        ...thread,
        participants
      }
    })
  } catch (error) {
    console.error('Error fetching thread:', error)
    return NextResponse.json(
      { error: 'Failed to fetch thread' },
      { status: 500 }
    )
  }
}

/**
 * PATCH /api/teams/[id]/threads/[threadId]
 * Update thread details (title, description, etc.)
 */
export async function PATCH(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id, threadId } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const thread = await prisma.teamThread.findUnique({
      where: { id: threadId }
    })

    if (!thread) {
      return NextResponse.json({ error: 'Thread not found' }, { status: 404 })
    }

    if (thread.teamId !== id) {
      return NextResponse.json(
        { error: 'Thread does not belong to this team' },
        { status: 400 }
      )
    }

    const body = await request.json()
    const { title, description, groupName, groupAvatar, avatar } = body

    // For channels, only admins can edit
    if (thread.isChannel) {
      const isAdmin = await isTeamAdmin(session.user.id, id)
      if (!isAdmin) {
        return NextResponse.json(
          { error: 'Only admins can edit channels' },
          { status: 403 }
        )
      }
    }

    // For group chats, only participants can edit
    if (thread.type === 'GROUP' && !thread.participantIds.includes(member.id)) {
      return NextResponse.json(
        { error: 'Only participants can edit this thread' },
        { status: 403 }
      )
    }

    const updateData: {
      title?: string
      description?: string | null
      groupName?: string
      groupAvatar?: string | null
      avatar?: string | null
    } = {}

    if (title !== undefined) updateData.title = title.trim()
    if (description !== undefined) updateData.description = description?.trim()
    if (groupName !== undefined) updateData.groupName = groupName.trim()
    if (groupAvatar !== undefined) updateData.groupAvatar = groupAvatar
    if (avatar !== undefined) updateData.avatar = avatar

    const updatedThread = await prisma.teamThread.update({
      where: { id: threadId },
      data: updateData,
      include: {
        _count: {
          select: {
            messages: true
          }
        }
      }
    })

    // Get participant details
    const participants = await prisma.teamMember.findMany({
      where: {
        id: { in: updatedThread.participantIds }
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            image: true
          }
        }
      }
    })

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'EDIT_ENTITY',
      action: 'Updated thread details',
      entityType: 'thread',
      entityId: threadId,
      entityName: updatedThread.title || updatedThread.groupName || 'Unnamed thread'
    })

    return NextResponse.json({ 
      thread: {
        ...updatedThread,
        participants
      }
    })
  } catch (error) {
    console.error('Error updating thread:', error)
    return NextResponse.json(
      { error: 'Failed to update thread' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/teams/[id]/threads/[threadId]
 * Delete a thread (admin only for channels, participants for group chats)
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

    const { id, threadId } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const thread = await prisma.teamThread.findUnique({
      where: { id: threadId }
    })

    if (!thread) {
      return NextResponse.json({ error: 'Thread not found' }, { status: 404 })
    }

    if (thread.teamId !== id) {
      return NextResponse.json(
        { error: 'Thread does not belong to this team' },
        { status: 400 }
      )
    }

    // For channels and discussion threads, only admins can delete
    if (thread.isChannel || thread.type === 'DISCUSSION') {
      const isAdmin = await isTeamAdmin(session.user.id, id)
      if (!isAdmin) {
        return NextResponse.json(
          { error: 'Only admins can delete channels' },
          { status: 403 }
        )
      }
    }

    // For group chats, only participants can delete
    if (thread.type === 'GROUP' && !thread.participantIds.includes(member.id)) {
      return NextResponse.json(
        { error: 'Only participants can delete this thread' },
        { status: 403 }
      )
    }

    // Delete the thread (cascade will delete messages)
    await prisma.teamThread.delete({
      where: { id: threadId }
    })

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'DELETE_ENTITY',
      action: 'Deleted thread',
      entityType: 'thread',
      entityId: threadId,
      entityName: thread.title || thread.groupName || 'Unnamed thread'
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error deleting thread:', error)
    return NextResponse.json(
      { error: 'Failed to delete thread' },
      { status: 500 }
    )
  }
}

