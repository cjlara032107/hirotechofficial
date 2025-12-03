import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { bulkMemberUpdateSchema } from '@/lib/teams/validation'
import { logActivity } from '@/lib/teams/activity'
import { notifyRoleChanged } from '@/lib/teams/notifications'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/teams/[id]/members/bulk-update
 * Bulk update team members (role change, suspend, activate)
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

    const { id: teamId } = await params

    // Check if user is admin
    const isAdmin = await isTeamAdmin(session.user.id, teamId)
    if (!isAdmin) {
      return NextResponse.json({ error: 'Forbidden - Admin access required' }, { status: 403 })
    }

    const body = await request.json()
    
    // Validate input
    const validation = bulkMemberUpdateSchema.safeParse(body)
    if (!validation.success) {
      return NextResponse.json(
        { error: 'Validation failed', details: validation.error.issues },
        { status: 400 }
      )
    }

    const { memberIds, action, newRole, reason } = validation.data

    // Get current member for logging
    const currentMember = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId }
      }
    })

    if (!currentMember) {
      return NextResponse.json({ error: 'Member not found' }, { status: 404 })
    }

    // Verify all members belong to this team
    const members = await prisma.teamMember.findMany({
      where: {
        id: { in: memberIds },
        teamId
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

    if (members.length !== memberIds.length) {
      return NextResponse.json(
        { error: 'Some members not found or do not belong to this team' },
        { status: 400 }
      )
    }

    // Prevent modifying owners
    const ownerMembers = members.filter(m => m.role === 'OWNER')
    if (ownerMembers.length > 0) {
      return NextResponse.json(
        { error: 'Cannot modify team owners' },
        { status: 403 }
      )
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let result: any

    switch (action) {
      case 'CHANGE_ROLE':
        if (!newRole) {
          return NextResponse.json({ error: 'Role is required' }, { status: 400 })
        }

        result = await prisma.teamMember.updateMany({
          where: {
            id: { in: memberIds },
            teamId
          },
          data: {
            role: newRole
          }
        })

        // Send notifications
        for (const member of members) {
          await notifyRoleChanged({
            memberId: member.id,
            oldRole: member.role,
            newRole,
            changedBy: currentMember.id,
            teamId
          }).catch(err => console.error('Failed to send role change notification:', err))
        }

        // Log activity
        await logActivity({
          teamId,
          memberId: currentMember.id,
          type: 'PERMISSION_CHANGED',
          action: `Changed role for ${result.count} members to ${newRole}`,
          metadata: { memberIds, newRole, reason }
        })

        break

      case 'SUSPEND':
        result = await prisma.teamMember.updateMany({
          where: {
            id: { in: memberIds },
            teamId
          },
          data: {
            status: 'SUSPENDED',
            suspendedAt: new Date(),
            suspendedReason: reason
          }
        })

        // Log activity
        await logActivity({
          teamId,
          memberId: currentMember.id,
          type: 'PERMISSION_CHANGED',
          action: `Suspended ${result.count} members`,
          metadata: { memberIds, reason }
        })

        break

      case 'ACTIVATE':
        result = await prisma.teamMember.updateMany({
          where: {
            id: { in: memberIds },
            teamId
          },
          data: {
            status: 'ACTIVE',
            suspendedAt: null,
            suspendedReason: null
          }
        })

        // Log activity
        await logActivity({
          teamId,
          memberId: currentMember.id,
          type: 'PERMISSION_CHANGED',
          action: `Activated ${result.count} members`,
          metadata: { memberIds }
        })

        break

      case 'REMOVE':
        // This is handled by the bulk-delete endpoint
        return NextResponse.json(
          { error: 'Use bulk-delete endpoint for removal' },
          { status: 400 }
        )

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }

    return NextResponse.json({
      success: true,
      count: result.count,
      message: `Successfully updated ${result.count} members`
    })
  } catch (error) {
    console.error('Error in bulk member update:', error)
    return NextResponse.json(
      { error: 'Failed to update members' },
      { status: 500 }
    )
  }
}

