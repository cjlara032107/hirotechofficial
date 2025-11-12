import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin, isTeamOwner } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'
import { TeamStatus } from '@prisma/client'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]
 * Get team details
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

    const { id } = await params

    const team = await prisma.team.findUnique({
      where: { id },
      include: {
        owner: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true
          }
        },
        members: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true
              }
            },
            permissions: {
              include: {
                facebookPage: {
                  select: {
                    id: true,
                    pageName: true,
                    pageId: true
                  }
                }
              }
            }
          },
          orderBy: { joinedAt: 'asc' }
        },
        _count: {
          select: {
            members: true,
            tasks: true,
            messages: true,
            activities: true
          }
        }
      }
    })

    if (!team) {
      return NextResponse.json({ error: 'Team not found' }, { status: 404 })
    }

    // Check if user is a member
    const isMember = team.members.some(m => 
      m.userId === session.user.id && m.status === 'ACTIVE'
    )

    if (!isMember && team.ownerId !== session.user.id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    return NextResponse.json({ team })
  } catch (error) {
    console.error('Error fetching team:', error)
    return NextResponse.json(
      { error: 'Failed to fetch team' },
      { status: 500 }
    )
  }
}

/**
 * PATCH /api/teams/[id]
 * Update team details
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

    const { id } = await params

    // Check if user is admin
    const admin = await isTeamAdmin(session.user.id, id)
    if (!admin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const body = await request.json()
    const { name, description, avatar, status } = body

    const updateData: {
      name?: string;
      description?: string | null;
      avatar?: string | null;
      status?: TeamStatus;
      archivedAt?: Date;
    } = {}
    if (name !== undefined) updateData.name = name.trim()
    if (description !== undefined) updateData.description = description?.trim()
    if (avatar !== undefined) updateData.avatar = avatar
    
    // Only owner can change status
    if (status !== undefined) {
      const owner = await isTeamOwner(session.user.id, id)
      if (owner) {
        const statusEnum = status as TeamStatus
        updateData.status = statusEnum
        if (statusEnum === 'ARCHIVED') {
          updateData.archivedAt = new Date()
        }
      }
    }

    const team = await prisma.team.update({
      where: { id },
      data: updateData
    })

    // Get member for logging
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (member) {
      await logActivity({
        teamId: id,
        memberId: member.id,
        type: 'EDIT_ENTITY',
        action: 'Updated team details',
        entityType: 'team',
        entityId: id,
        entityName: team.name
      })
    }

    return NextResponse.json({ team })
  } catch (error) {
    console.error('Error updating team:', error)
    return NextResponse.json(
      { error: 'Failed to update team' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/teams/[id]
 * Delete a team (owner only)
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

    const { id } = await params

    // Check if user is owner
    const owner = await isTeamOwner(session.user.id, id)
    if (!owner) {
      return NextResponse.json(
        { error: 'Only team owner can delete the team' },
        { status: 403 }
      )
    }

    // Delete team (cascade will handle related records)
    await prisma.team.delete({
      where: { id }
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error deleting team:', error)
    return NextResponse.json(
      { error: 'Failed to delete team' },
      { status: 500 }
    )
  }
}

