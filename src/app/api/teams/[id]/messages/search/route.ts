import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/messages/search
 * Search messages in team threads
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
    
    const query = searchParams.get('q') || ''
    const threadId = searchParams.get('threadId')
    // Reduced default page size for better performance
    const limit = parseInt(searchParams.get('limit') || '25')
    const offset = parseInt(searchParams.get('offset') || '0')

    if (!query || query.length < 2) {
      return NextResponse.json(
        { error: 'Search query must be at least 2 characters' },
        { status: 400 }
      )
    }

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Build where clause
    const where: {
      teamId: string
      isDeleted: boolean
      content: { contains: string; mode: 'insensitive' }
      threadId?: string
    } = {
      teamId: id,
      isDeleted: false,
      content: {
        contains: query,
        mode: 'insensitive'
      }
    }

    if (threadId) {
      // Verify user has access to this thread
      const thread = await prisma.teamThread.findUnique({
        where: { id: threadId },
        select: { participantIds: true, type: true, isChannel: true }
      })

      if (!thread) {
        return NextResponse.json({ error: 'Thread not found' }, { status: 404 })
      }

      // Check access
      const hasAccess = thread.isChannel || 
                       thread.type === 'DISCUSSION' || 
                       thread.participantIds.includes(member.id)

      if (!hasAccess) {
        return NextResponse.json({ error: 'No access to this thread' }, { status: 403 })
      }

      where.threadId = threadId
    }

    // Search messages
    const [messages, total] = await Promise.all([
      prisma.teamMessage.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        include: {
          sender: {
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
          thread: {
            select: {
              id: true,
              title: true,
              type: true,
              groupName: true
            }
          }
        }
      }),
      prisma.teamMessage.count({ where })
    ])

    return NextResponse.json({
      messages,
      total,
      query,
      limit,
      offset,
      hasMore: total > offset + limit
    })
  } catch (error) {
    console.error('Error searching messages:', error)
    return NextResponse.json(
      { error: 'Failed to search messages' },
      { status: 500 }
    )
  }
}
