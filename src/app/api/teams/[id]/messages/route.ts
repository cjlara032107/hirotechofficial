import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { logActivity } from '@/lib/teams/activity'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/messages
 * Get team messages
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
    const threadId = searchParams.get('threadId')
    const limit = parseInt(searchParams.get('limit') || '50')
    const offset = parseInt(searchParams.get('offset') || '0')

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
      isDeleted: boolean;
      threadId?: string;
    } = { teamId: id, isDeleted: false }
    if (threadId) where.threadId = threadId

    const [messages, total] = await Promise.all([
      prisma.teamMessage.findMany({
        where,
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
              type: true
            }
          },
          replyTo: {
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
              replies: true
            }
          }
        },
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset
      }),
      prisma.teamMessage.count({ where })
    ])

    return NextResponse.json({ messages, total })
  } catch (error) {
    console.error('Error fetching team messages:', error)
    return NextResponse.json(
      { error: 'Failed to fetch team messages' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/teams/[id]/messages
 * Send a message
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
    const { content, threadId, replyToId, mentions, attachments } = body

    if (!content || content.trim().length === 0) {
      return NextResponse.json(
        { error: 'Message content is required' },
        { status: 400 }
      )
    }

    const message = await prisma.teamMessage.create({
      data: {
        teamId: id,
        senderId: member.id,
        content: content.trim(),
        threadId: threadId || null,
        replyToId: replyToId || null,
        mentions: mentions || [],
        attachments: attachments || null
      },
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
            type: true
          }
        }
      }
    })

    // Update thread last message time
    if (threadId) {
      await prisma.teamThread.update({
        where: { id: threadId },
        data: { lastMessageAt: new Date() }
      })
    }

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'SEND_MESSAGE',
      action: 'Sent a message',
      metadata: { messageId: message.id, threadId }
    })

    // TODO: Send notifications to mentioned users

    return NextResponse.json({ message }, { status: 201 })
  } catch (error) {
    console.error('Error sending team message:', error)
    return NextResponse.json(
      { error: 'Failed to send team message' },
      { status: 500 }
    )
  }
}

