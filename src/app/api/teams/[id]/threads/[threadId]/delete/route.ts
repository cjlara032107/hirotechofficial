import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; threadId: string }>
}

/**
 * DELETE /api/teams/[id]/threads/[threadId]/delete
 * Delete a thread/conversation (soft delete with option for hard delete)
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
    const { searchParams } = new URL(request.url)
    const permanent = searchParams.get('permanent') === 'true'

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
        _count: {
          select: { messages: true }
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

    // Permission check
    const isAdmin = await isTeamAdmin(session.user.id, id)
    const isParticipant = thread.participantIds.includes(member.id)
    const isChannelOrDiscussion = thread.isChannel || thread.type === 'DISCUSSION'

    if (isChannelOrDiscussion && !isAdmin) {
      return NextResponse.json(
        { error: 'Only admins can delete channels' },
        { status: 403 }
      )
    }

    if (!isChannelOrDiscussion && !isParticipant && !isAdmin) {
      return NextResponse.json(
        { error: 'You do not have permission to delete this conversation' },
        { status: 403 }
      )
    }

    if (permanent) {
      // Hard delete (admin only for important threads)
      if (!isAdmin && thread._count.messages > 10) {
        return NextResponse.json(
          { error: 'Only admins can permanently delete threads with messages' },
          { status: 403 }
        )
      }

      await prisma.teamThread.delete({
        where: { id: threadId }
      })

      // Log activity
      await logActivity({
        teamId: id,
        memberId: member.id,
        type: 'DELETE_ENTITY',
        action: 'Permanently deleted conversation',
        entityType: 'thread',
        entityId: threadId,
        entityName: thread.title || thread.groupName || 'Unnamed'
      })

      return NextResponse.json({ 
        success: true, 
        message: 'Conversation permanently deleted' 
      })
    } else {
      // Soft delete - remove user from participants
      const updatedParticipants = thread.participantIds.filter(id => id !== member.id)

      if (updatedParticipants.length === 0) {
        // If no participants left, delete the thread
        await prisma.teamThread.delete({
          where: { id: threadId }
        })
      } else {
        // Just remove the user from participants
        await prisma.teamThread.update({
          where: { id: threadId },
          data: { participantIds: updatedParticipants }
        })
      }

      // Log activity
      await logActivity({
        teamId: id,
        memberId: member.id,
        type: 'DELETE_ENTITY',
        action: 'Left conversation',
        entityType: 'thread',
        entityId: threadId,
        entityName: thread.title || thread.groupName || 'Unnamed'
      })

      return NextResponse.json({ 
        success: true, 
        message: 'Left conversation successfully' 
      })
    }
  } catch (error) {
    console.error('Error deleting thread:', error)
    return NextResponse.json(
      { error: 'Failed to delete conversation' },
      { status: 500 }
    )
  }
}

