import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; memberId: string }>
}

/**
 * PATCH /api/teams/[id]/members/[memberId]/nickname
 * Update member's nickname/display name
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

    const { id, memberId } = await params

    // Check if user is a member
    const currentMember = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!currentMember || currentMember.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Users can only edit their own nickname, or admins can edit any nickname
    if (currentMember.id !== memberId && currentMember.role !== 'OWNER' && currentMember.role !== 'ADMIN') {
      return NextResponse.json(
        { error: 'You can only edit your own nickname' },
        { status: 403 }
      )
    }

    const member = await prisma.teamMember.findUnique({
      where: { id: memberId },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true
          }
        }
      }
    })

    if (!member) {
      return NextResponse.json({ error: 'Member not found' }, { status: 404 })
    }

    if (member.teamId !== id) {
      return NextResponse.json(
        { error: 'Member does not belong to this team' },
        { status: 400 }
      )
    }

    const body = await request.json()
    const { displayName, bio, avatar } = body

    const updateData: {
      displayName?: string | null
      bio?: string | null
      avatar?: string | null
    } = {}

    if (displayName !== undefined) {
      updateData.displayName = displayName?.trim() || null
    }
    if (bio !== undefined) {
      updateData.bio = bio?.trim() || null
    }
    if (avatar !== undefined) {
      updateData.avatar = avatar
    }

    const updatedMember = await prisma.teamMember.update({
      where: { id: memberId },
      data: updateData,
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

    // Log activity
    await logActivity({
      teamId: id,
      memberId: currentMember.id,
      type: 'EDIT_ENTITY',
      action: currentMember.id === memberId ? 'Updated profile' : `Updated ${member.user.name || member.user.email}'s profile`,
      entityType: 'member',
      entityId: memberId,
      entityName: updatedMember.displayName || updatedMember.user.name || updatedMember.user.email
    })

    return NextResponse.json({ member: updatedMember })
  } catch (error) {
    console.error('Error updating member nickname:', error)
    return NextResponse.json(
      { error: 'Failed to update member nickname' },
      { status: 500 }
    )
  }
}

