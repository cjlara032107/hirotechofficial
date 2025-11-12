import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin, isTeamOwner } from '@/lib/teams/permissions'
import { TeamRole, TeamMemberStatus } from '@prisma/client'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string; memberId: string }>
}

/**
 * PATCH /api/teams/[id]/members/[memberId]
 * Update team member (role, permissions, status)
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

    // Check if user is admin
    const admin = await isTeamAdmin(session.user.id, id)
    if (!admin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const body = await request.json()
    const { role, displayName, bio, status, suspendedUntil, suspendedReason } = body

    const updateData: {
      displayName?: string;
      bio?: string | null;
      role?: TeamRole;
      status?: TeamMemberStatus;
      suspendedAt?: Date | null;
      suspendedUntil?: Date | null;
      suspendedReason?: string | null;
    } = {}
    
    if (displayName !== undefined) updateData.displayName = displayName
    if (bio !== undefined) updateData.bio = bio

    // Role changes require owner permission (except promoting to ADMIN)
    if (role !== undefined) {
      const roleEnum = role as TeamRole
      
      updateData.role = roleEnum
      
      if (roleEnum === 'OWNER') {
        // Only owner can transfer ownership
        const owner = await isTeamOwner(session.user.id, id)
        if (!owner) {
          return NextResponse.json(
            { error: 'Only owner can transfer ownership' },
            { status: 403 }
          )
        }

        // Transfer ownership
        const member = await prisma.teamMember.findUnique({
          where: { id: memberId }
        })

        if (!member) {
          return NextResponse.json(
            { error: 'Member not found' },
            { status: 404 }
          )
        }

        // Update team owner
        await prisma.team.update({
          where: { id },
          data: { ownerId: member.userId }
        })

        // Update new owner's role
        await prisma.teamMember.update({
          where: { id: memberId },
          data: { role: 'OWNER' }
        })

        // Demote old owner to ADMIN
        await prisma.teamMember.update({
          where: {
            userId_teamId: { userId: session.user.id, teamId: id }
          },
          data: { role: 'ADMIN' }
        })

        return NextResponse.json({
          success: true,
          message: 'Ownership transferred successfully'
        })
      }
    }

    // Status changes
    if (status !== undefined) {
      const statusEnum = status as TeamMemberStatus
      updateData.status = statusEnum
      
      if (statusEnum === 'SUSPENDED') {
        updateData.suspendedAt = new Date()
        if (suspendedUntil) updateData.suspendedUntil = new Date(suspendedUntil)
        if (suspendedReason) updateData.suspendedReason = suspendedReason
      } else if (statusEnum === 'ACTIVE') {
        updateData.suspendedAt = null
        updateData.suspendedUntil = null
        updateData.suspendedReason = null
      }
    }

    const member = await prisma.teamMember.update({
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
        action: `Updated member: ${member.user.name}`,
        metadata: { changes: updateData }
      })
    }

    return NextResponse.json({ member })
  } catch (error) {
    console.error('Error updating team member:', error)
    return NextResponse.json(
      { error: 'Failed to update team member' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/teams/[id]/members/[memberId]
 * Remove team member
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

    const { id, memberId } = await params

    // Check if user is admin
    const admin = await isTeamAdmin(session.user.id, id)
    if (!admin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const member = await prisma.teamMember.findUnique({
      where: { id: memberId },
      include: {
        user: {
          select: {
            id: true,
            name: true
          }
        }
      }
    })

    if (!member) {
      return NextResponse.json({ error: 'Member not found' }, { status: 404 })
    }

    // Cannot remove owner
    if (member.role === 'OWNER') {
      return NextResponse.json(
        { error: 'Cannot remove team owner. Transfer ownership first.' },
        { status: 400 }
      )
    }

    // Update member status to REMOVED
    await prisma.teamMember.update({
      where: { id: memberId },
      data: { status: 'REMOVED' }
    })

    // Log activity
    const loggerMember = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (loggerMember) {
      await logActivity({
        teamId: id,
        memberId: loggerMember.id,
        type: 'LEAVE_TEAM',
        action: `Removed member: ${member.user.name}`,
        metadata: { removedMemberId: memberId }
      })
    }

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error removing team member:', error)
    return NextResponse.json(
      { error: 'Failed to remove team member' },
      { status: 500 }
    )
  }
}

