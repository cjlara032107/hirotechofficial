import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { ThreadType } from '@prisma/client'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/threads
 * Get team threads
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
    const { searchParams } = new URL(request.url)
    const type = searchParams.get('type')

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const where: {
      teamId: string;
      type?: ThreadType;
      participantIds?: { has: string };
    } = { teamId: id }
    if (type) where.type = type as ThreadType

    // For direct and group chats, only show threads user is part of
    if (type === 'DIRECT' || type === 'GROUP') {
      where.participantIds = { has: member.id }
    }

    const threads = await prisma.teamThread.findMany({
      where,
      include: {
        messages: {
          take: 1,
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
      },
      orderBy: [
        { isPinned: 'desc' },
        { lastMessageAt: 'desc' }
      ]
    })

    // Get participant details for each thread
    const threadsWithParticipants = await Promise.all(
      threads.map(async (thread) => {
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

        return {
          ...thread,
          participants
        }
      })
    )

    return NextResponse.json({ threads: threadsWithParticipants })
  } catch (error) {
    console.error('Error fetching team threads:', error)
    return NextResponse.json(
      { error: 'Failed to fetch team threads' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/teams/[id]/threads
 * Create a new thread (group chat)
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

    const { id } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const body = await request.json()
    const { title, type, participantIds, isChannel, groupName, groupAvatar } = body

    // For channels, only admins can create
    if (isChannel || type === 'DISCUSSION') {
      const isAdmin = member.role === 'ADMIN' || member.role === 'OWNER'
      if (!isAdmin) {
        return NextResponse.json(
          { error: 'Only admins can create channels' },
          { status: 403 }
        )
      }
    }

    // For group chats, validate participants
    if (type === 'GROUP' || (type !== 'DISCUSSION' && !isChannel)) {
      if (!participantIds || !Array.isArray(participantIds) || participantIds.length === 0) {
        return NextResponse.json(
          { error: 'Participants are required for group chats' },
          { status: 400 }
        )
      }

      // Validate all participant IDs exist in the team
      const validMembers = await prisma.teamMember.findMany({
        where: {
          id: { in: participantIds },
          teamId: id,
          status: 'ACTIVE'
        }
      })

      if (validMembers.length !== participantIds.length) {
        return NextResponse.json(
          { error: 'Some participants are not valid team members' },
          { status: 400 }
        )
      }
    }

    // Add creator to participants (for group chats)
    const allParticipants = type === 'GROUP' 
      ? Array.from(new Set([member.id, ...(participantIds || [])]))
      : (participantIds || [])

    // Determine thread type
    let threadType = type || 'GROUP'
    if (threadType === 'GROUP' && allParticipants.length === 2) {
      threadType = 'DIRECT'
      
      // ALLOW MULTIPLE DIRECT CONVERSATIONS
      // Duplicate check removed - users can create multiple direct conversations
      // This allows for separate conversation topics/threads between same two users
    }

    const thread = await prisma.teamThread.create({
      data: {
        teamId: id,
        title: title?.trim(),
        type: threadType,
        participantIds: allParticipants,
        isChannel: isChannel ?? (type === 'DISCUSSION'),
        isGroupChat: type === 'GROUP',
        groupName: groupName?.trim(),
        groupAvatar,
        createdById: member.id
      },
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
        id: { in: allParticipants }
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
      type: 'CREATE_ENTITY',
      action: `Created ${threadType.toLowerCase()} thread${title ? `: ${title}` : ''}`,
      entityType: 'thread',
      entityId: thread.id,
      entityName: title || 'Unnamed thread'
    })

    return NextResponse.json({ thread: { ...thread, participants } }, { status: 201 })
  } catch (error) {
    console.error('Error creating team thread:', error)
    return NextResponse.json(
      { error: 'Failed to create team thread' },
      { status: 500 }
    )
  }
}

