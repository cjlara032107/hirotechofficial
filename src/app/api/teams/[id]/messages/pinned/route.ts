import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/messages/pinned
 * Get paginated pinned messages for a team
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
    
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '20')
    const threadId = searchParams.get('threadId')
    const cursor = searchParams.get('cursor')

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
      isPinned: boolean
      isDeleted: boolean
      threadId?: string
      pinnedAt?: { lt: Date }
    } = {
      teamId: id,
      isPinned: true,
      isDeleted: false
    }

    if (threadId) {
      where.threadId = threadId
    }

    // Cursor-based pagination
    if (cursor) {
      where.pinnedAt = { lt: new Date(cursor) }
    }

    const skip = cursor ? 0 : (page - 1) * limit

    // Fetch pinned messages
    const [messages, total] = await Promise.all([
      prisma.teamMessage.findMany({
        where,
        orderBy: { pinnedAt: 'desc' },
        take: limit,
        skip,
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
      cursor ? Promise.resolve(0) : prisma.teamMessage.count({ where })
    ])

    const hasMore = messages.length === limit
    const nextCursor = messages.length > 0 && messages[messages.length - 1].pinnedAt
      ? messages[messages.length - 1].pinnedAt?.toISOString()
      : null

    return NextResponse.json({
      messages,
      total: total || messages.length,
      page: cursor ? undefined : page,
      limit,
      hasMore,
      nextCursor,
      totalPages: cursor ? undefined : Math.ceil((total || 0) / limit)
    })
  } catch (error) {
    console.error('Error fetching pinned messages:', error)
    return NextResponse.json(
      { error: 'Failed to fetch pinned messages' },
      { status: 500 }
    )
  }
}

