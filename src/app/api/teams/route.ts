import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { generateUniqueJoinCode, getJoinCodeExpiration } from '@/lib/teams/join-codes'
import { createDefaultPermissions } from '@/lib/teams/permissions'
import { logActivity } from '@/lib/teams/activity'

/**
 * GET /api/teams
 * Get all teams for the current user
 */
export async function GET() {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const teams = await prisma.team.findMany({
      where: {
        members: {
          some: {
            userId: session.user.id,
            status: { in: ['ACTIVE', 'PENDING'] }
          }
        }
      },
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
          where: { status: 'ACTIVE' },
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
        },
        _count: {
          select: {
            members: true,
            tasks: true,
            messages: true
          }
        }
      },
      orderBy: { createdAt: 'desc' }
    })

    // Get the user's role in each team
    const teamsWithRole = teams.map(team => {
      const member = team.members.find(m => m.userId === session.user.id)
      return {
        ...team,
        userRole: member?.role,
        userStatus: member?.status
      }
    })

    return NextResponse.json({ teams: teamsWithRole })
  } catch (error) {
    console.error('Error fetching teams:', error)
    return NextResponse.json(
      { error: 'Failed to fetch teams' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/teams
 * Create a new team
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { name, description, avatar } = body

    if (!name || name.trim().length === 0) {
      return NextResponse.json(
        { error: 'Team name is required' },
        { status: 400 }
      )
    }

    // Get user's organization
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true }
    })

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 })
    }

    // Generate join code
    const joinCode = await generateUniqueJoinCode()
    const joinCodeExpiresAt = getJoinCodeExpiration()

    // Create team
    const team = await prisma.team.create({
      data: {
        name: name.trim(),
        description: description?.trim(),
        avatar,
        organizationId: user.organizationId,
        ownerId: session.user.id,
        joinCode,
        joinCodeExpiresAt,
        status: 'ACTIVE'
      }
    })

    // Add creator as owner member
    const member = await prisma.teamMember.create({
      data: {
        userId: session.user.id,
        teamId: team.id,
        role: 'OWNER',
        status: 'ACTIVE',
        displayName: session.user.name || undefined
      }
    })

    // Create default permissions for owner
    await createDefaultPermissions(member.id, 'OWNER')

    // Log activity
    await logActivity({
      teamId: team.id,
      memberId: member.id,
      type: 'CREATE_ENTITY',
      action: 'Created team',
      entityType: 'team',
      entityId: team.id,
      entityName: team.name
    })

    return NextResponse.json({ team }, { status: 201 })
  } catch (error) {
    console.error('Error creating team:', error)
    return NextResponse.json(
      { error: 'Failed to create team' },
      { status: 500 }
    )
  }
}

