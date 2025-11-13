import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/contacts/[id]/messages
 * Get paginated messages for a contact's conversation
 */
export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id: contactId } = await params
    const { searchParams } = new URL(request.url)
    
    // Pagination parameters
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '50')
    const cursor = searchParams.get('cursor') // For cursor-based pagination
    const platform = searchParams.get('platform') // Filter by platform
    
    // Calculate offset for offset-based pagination
    const skip = (page - 1) * limit

    // Verify contact belongs to user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
        organizationId: session.user.organizationId,
      },
      select: { id: true }
    })

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 })
    }

    // Get conversation for this contact
    const conversations = await prisma.conversation.findMany({
      where: {
        contactId,
        ...(platform && { platform: platform as 'MESSENGER' | 'INSTAGRAM' })
      },
      select: { id: true }
    })

    const conversationIds = conversations.map(c => c.id)

    if (conversationIds.length === 0) {
      return NextResponse.json({
        messages: [],
        total: 0,
        page,
        limit,
        totalPages: 0,
        hasMore: false
      })
    }

    // Build where clause
    const where: {
      conversationId: { in: string[] }
      createdAt?: { lt: Date }
    } = {
      conversationId: { in: conversationIds }
    }

    // Cursor-based pagination (for infinite scroll)
    if (cursor) {
      where.createdAt = { lt: new Date(cursor) }
    }

    // Fetch messages with pagination
    const [messages, total] = await Promise.all([
      prisma.message.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: cursor ? 0 : skip, // Skip only for offset pagination
        include: {
          conversation: {
            select: {
              platform: true,
              facebookPage: {
                select: {
                  pageName: true
                }
              }
            }
          }
        }
      }),
      // Get total count (only if not using cursor pagination)
      cursor ? Promise.resolve(0) : prisma.message.count({ where: { conversationId: { in: conversationIds } } })
    ])

    const totalPages = cursor ? 0 : Math.ceil(total / limit)
    const hasMore = messages.length === limit

    // Get the last message timestamp for cursor
    const nextCursor = messages.length > 0 
      ? messages[messages.length - 1].createdAt.toISOString()
      : null

    return NextResponse.json({
      messages,
      total: total || messages.length,
      page: cursor ? undefined : page,
      limit,
      totalPages: cursor ? undefined : totalPages,
      hasMore,
      nextCursor,
      conversationIds
    })
  } catch (error) {
    console.error('Error fetching messages:', error)
    return NextResponse.json(
      { error: 'Failed to fetch messages' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/contacts/[id]/messages
 * Send a message to the contact
 */
export async function POST(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id: contactId } = await params
    const body = await request.json()
    const { content, platform, messageTag } = body

    if (!content || !platform) {
      return NextResponse.json(
        { error: 'Content and platform are required' },
        { status: 400 }
      )
    }

    // Verify contact
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
        organizationId: session.user.organizationId,
      },
      include: {
        facebookPage: true
      }
    })

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 })
    }

    // Get or create conversation
    let conversation = await prisma.conversation.findFirst({
      where: {
        contactId,
        platform,
      }
    })

    if (!conversation) {
      conversation = await prisma.conversation.create({
        data: {
          contactId,
          facebookPageId: contact.facebookPageId,
          platform,
          status: 'OPEN',
          lastMessageAt: new Date(),
          assignedToId: session.user.id
        }
      })
    }

    // Create message
    const message = await prisma.message.create({
      data: {
        contactId,
        conversationId: conversation.id,
        content,
        platform,
        isFromBusiness: true,
        messageTag: messageTag || null,
        status: 'PENDING'
      },
      include: {
        conversation: {
          select: {
            platform: true,
            facebookPage: {
              select: {
                pageName: true
              }
            }
          }
        }
      }
    })

    // Update conversation last message time
    await prisma.conversation.update({
      where: { id: conversation.id },
      data: { lastMessageAt: new Date() }
    })

    return NextResponse.json({ message }, { status: 201 })
  } catch (error) {
    console.error('Error sending message:', error)
    return NextResponse.json(
      { error: 'Failed to send message' },
      { status: 500 }
    )
  }
}

