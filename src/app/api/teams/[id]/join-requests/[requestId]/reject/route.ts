import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; requestId: string }>
}

/**
 * POST /api/teams/[id]/join-requests/[requestId]/reject
 * Reject a join request
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

    const { id, requestId } = await params

    // Check if user is admin
    const admin = await isTeamAdmin(session.user.id, id)
    if (!admin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const body = await request.json()
    const { notes } = body

    // Get the join request
    const joinRequest = await prisma.teamJoinRequest.findUnique({
      where: { id: requestId },
      include: {
        user: true,
        invite: true
      }
    })

    if (!joinRequest) {
      return NextResponse.json(
        { error: 'Join request not found' },
        { status: 404 }
      )
    }

    if (joinRequest.invite.teamId !== id) {
      return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
    }

    if (joinRequest.status !== 'PENDING') {
      return NextResponse.json(
        { error: 'Join request already processed' },
        { status: 400 }
      )
    }

    // Update join request
    await prisma.teamJoinRequest.update({
      where: { id: requestId },
      data: {
        status: 'REJECTED',
        reviewedById: session.user.id,
        reviewedAt: new Date(),
        reviewNotes: notes
      }
    })

    // Update team member status to REMOVED
    await prisma.teamMember.update({
      where: {
        userId_teamId: { userId: joinRequest.userId, teamId: id }
      },
      data: {
        status: 'REMOVED'
      }
    })

    // Log activity for the admin who rejected
    const loggerMember = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (loggerMember) {
      await logActivity({
        teamId: id,
        memberId: loggerMember.id,
        type: 'PERMISSION_CHANGED',
        action: `Rejected join request from ${joinRequest.user.name}`,
        metadata: { rejectedUserId: joinRequest.userId }
      })
    }

    return NextResponse.json({
      success: true,
      message: 'Join request rejected'
    })
  } catch (error) {
    console.error('Error rejecting join request:', error)
    return NextResponse.json(
      { error: 'Failed to reject join request' },
      { status: 500 }
    )
  }
}

