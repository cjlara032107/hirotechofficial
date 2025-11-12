import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { createDefaultPermissions } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; requestId: string }>
}

/**
 * POST /api/teams/[id]/join-requests/[requestId]/approve
 * Approve a join request
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
        status: 'APPROVED',
        reviewedById: session.user.id,
        reviewedAt: new Date(),
        reviewNotes: notes
      }
    })

    // Update team member status
    const member = await prisma.teamMember.update({
      where: {
        userId_teamId: { userId: joinRequest.userId, teamId: id }
      },
      data: {
        status: 'ACTIVE'
      }
    })

    // Create default permissions
    await createDefaultPermissions(member.id, 'MEMBER')

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'JOIN_TEAM',
      action: 'Joined team',
      metadata: { approvedBy: session.user.id }
    })

    return NextResponse.json({
      success: true,
      message: 'Join request approved'
    })
  } catch (error) {
    console.error('Error approving join request:', error)
    return NextResponse.json(
      { error: 'Failed to approve join request' },
      { status: 500 }
    )
  }
}