import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import {
  getCachedChunk,
  setCachedChunk,
  clearCacheForConversations,
  getMaxMessagesPerConversation,
  getChunkSize,
} from '@/lib/cache/message-cache'

interface RouteParams {
  params: Promise<{ id: string }>
}

const MAX_MESSAGES = getMaxMessagesPerConversation()
const CHUNK_SIZE = getChunkSize()

/**
 * GET /api/contacts/[id]/messages
 * Get paginated messages for a contact's conversation
 * - Limits to last 200 messages per conversation
 * - Uses chunked fetching for better performance
 * - Implements caching for message chunks
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
    const limit = Math.min(parseInt(searchParams.get('limit') || String(CHUNK_SIZE)), CHUNK_SIZE)
    const cursor = searchParams.get('cursor') // For cursor-based pagination
    const platform = searchParams.get('platform') // Filter by platform
    const chunkIndex = parseInt(searchParams.get('chunkIndex') || '0')
    
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
        hasMore: false,
        maxMessages: MAX_MESSAGES
      })
    }

    // Check cache first (for both initial load and cursor-based pagination)
    const cached = getCachedChunk(conversationIds, chunkIndex, cursor || null)
    if (cached) {
      return NextResponse.json({
        messages: cached.messages,
        total: cached.messages.length,
        limit,
        hasMore: cached.hasMore,
        nextCursor: cached.cursor,
        conversationIds,
        cached: true,
        maxMessages: MAX_MESSAGES
      })
    }

    // Optimize for very large conversations (10,000+ messages)
    // Build where clause - limit to last MAX_MESSAGES messages
    // For performance, we'll use a more efficient approach:
    // 1. Get total message count first (lightweight)
    // 2. Only fetch oldest message timestamp if we're near the limit
    
    // Check total message count to determine if we need to limit
    const totalMessageCount = await prisma.message.count({
      where: {
        conversationId: { in: conversationIds }
      }
    })
    
    // Only fetch oldest message timestamp if we have more than MAX_MESSAGES
    // This avoids unnecessary queries for smaller conversations
    let oldestMessage: { createdAt: Date } | null = null
    if (totalMessageCount > MAX_MESSAGES) {
      oldestMessage = await prisma.message.findFirst({
        where: {
          conversationId: { in: conversationIds }
        },
        orderBy: { createdAt: 'desc' },
        skip: MAX_MESSAGES - 1,
        select: { createdAt: true }
      })
    }

    const where: {
      conversationId: { in: string[] }
      createdAt?: { gte?: Date; lt?: Date }
    } = {
      conversationId: { in: conversationIds }
    }

    // Only fetch messages within the last MAX_MESSAGES
    // This ensures we never fetch more than MAX_MESSAGES total
    if (oldestMessage) {
      where.createdAt = { gte: oldestMessage.createdAt }
    }

    // Cursor-based pagination (for infinite scroll)
    // When using cursor, we still respect the MAX_MESSAGES limit
    if (cursor) {
      const cursorDate = new Date(cursor)
      // Ensure cursor is within the MAX_MESSAGES range
      if (oldestMessage && cursorDate < oldestMessage.createdAt) {
        // Cursor is outside the MAX_MESSAGES range, return empty
        return NextResponse.json({
          messages: [],
          total: 0,
          limit,
          hasMore: false,
          nextCursor: null,
          conversationIds,
          maxMessages: MAX_MESSAGES,
          cached: false
        })
      }
      where.createdAt = {
        ...where.createdAt,
        lt: cursorDate
      }
    }

    // Fetch messages with pagination (chunked)
    const [messages, totalCount] = await Promise.all([
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
      cursor ? Promise.resolve(0) : prisma.message.count({ where })
    ])

    // Cap total count to MAX_MESSAGES
    const total = Math.min(totalCount, MAX_MESSAGES)
    const totalPages = cursor ? 0 : Math.ceil(total / limit)
    
    // Determine if there are more messages (considering the MAX_MESSAGES limit)
    // For cursor pagination: check if we got a full chunk and haven't exceeded MAX_MESSAGES
    // For offset pagination: check if there are more pages within MAX_MESSAGES
    let hasMore = false
    if (cursor) {
      // With cursor, we need to check if there are more messages within the MAX_MESSAGES range
      // If we got a full chunk, there might be more (unless we've hit the oldestMessage limit)
      hasMore = messages.length === limit
      // Also check if the last message is still within our range
      // If oldestMessage is null, it means we have fewer than MAX_MESSAGES total, so check normally
      if (hasMore && messages.length > 0) {
        if (oldestMessage) {
          const lastMessageDate = messages[messages.length - 1].createdAt
          hasMore = lastMessageDate > oldestMessage.createdAt
        }
        // If oldestMessage is null, we have < MAX_MESSAGES total, so hasMore is already set correctly above
      }
    } else {
      // For offset pagination, check if we haven't exceeded MAX_MESSAGES
      hasMore = messages.length === limit && (page * limit) < MAX_MESSAGES
    }

    // Get the last message timestamp for cursor
    const nextCursor = messages.length > 0 
      ? messages[messages.length - 1].createdAt.toISOString()
      : null

    // Cache the chunk (both initial load and cursor-based pagination)
    if (messages.length > 0) {
      // Transform messages to match expected type (convert null conversation to undefined)
      const transformedMessages = messages.map(msg => ({
        ...msg,
        conversation: msg.conversation ? {
          platform: msg.conversation.platform,
          facebookPage: msg.conversation.facebookPage
        } : undefined
      }));
      
      setCachedChunk(conversationIds, chunkIndex, {
        conversationId: conversationIds[0], // Primary conversation ID
        chunkIndex,
        messages: transformedMessages,
        cursor: nextCursor,
        hasMore,
      }, cursor ? undefined : 60) // Shorter TTL for initial loads (1 minute), default for cursor pagination (5 minutes)
    }

    return NextResponse.json({
      messages,
      total: total || messages.length,
      page: cursor ? undefined : page,
      limit,
      totalPages: cursor ? undefined : totalPages,
      hasMore,
      nextCursor,
      conversationIds,
      maxMessages: MAX_MESSAGES,
      // Indicate if there are more messages beyond the limit (for very large conversations)
      // Only include if total count exceeds the max limit we're showing
      ...(totalMessageCount > MAX_MESSAGES && { totalMessageCount }),
      cached: false
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

    // Clear cache for this conversation since we added a new message
    clearCacheForConversations([conversation.id])

    return NextResponse.json({ message }, { status: 201 })
  } catch (error) {
    console.error('Error sending message:', error)
    return NextResponse.json(
      { error: 'Failed to send message' },
      { status: 500 }
    )
  }
}

