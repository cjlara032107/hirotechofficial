import { NextRequest } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { getMaxMessagesPerConversation, getChunkSize } from '@/lib/cache/message-cache'

interface RouteParams {
  params: Promise<{ id: string }>
}

const MAX_MESSAGES = getMaxMessagesPerConversation()
const CHUNK_SIZE = getChunkSize()

/**
 * GET /api/contacts/[id]/messages/stream
 * Stream messages for a contact's conversation using Server-Sent Events (SSE)
 * - Streams messages in chunks for better performance
 * - Limits to last 200 messages per conversation
 */
export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user) {
      return new Response('Unauthorized', { status: 401 })
    }

    const { id: contactId } = await params
    const { searchParams } = new URL(request.url)
    const platform = searchParams.get('platform') // Filter by platform

    // Verify contact belongs to user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
        organizationId: session.user.organizationId,
      },
      select: { id: true }
    })

    if (!contact) {
      return new Response('Contact not found', { status: 404 })
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
      // Return empty stream
      const encoder = new TextEncoder()
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: 'complete', messages: [], total: 0 })}\n\n`))
          controller.close()
        }
      })
      return new Response(stream, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      })
    }

    // Create a readable stream for SSE
    const encoder = new TextEncoder()
    const stream = new ReadableStream({
      async start(controller) {
        try {
          // Get the oldest message timestamp we should consider (for MAX_MESSAGES limit)
          const oldestMessage = await prisma.message.findFirst({
            where: {
              conversationId: { in: conversationIds }
            },
            orderBy: { createdAt: 'desc' },
            skip: MAX_MESSAGES - 1,
            select: { createdAt: true }
          })

          const where: {
            conversationId: { in: string[] }
            createdAt?: { gte: Date }
          } = {
            conversationId: { in: conversationIds }
          }

          // Only fetch messages within the last MAX_MESSAGES
          if (oldestMessage) {
            where.createdAt = { gte: oldestMessage.createdAt }
          }

          // Get total count (capped to MAX_MESSAGES)
          const totalCount = await prisma.message.count({ where })
          const total = Math.min(totalCount, MAX_MESSAGES)

          // Send initial metadata
          controller.enqueue(
            encoder.encode(
              `data: ${JSON.stringify({ type: 'metadata', total, maxMessages: MAX_MESSAGES })}\n\n`
            )
          )

          // Stream messages in chunks
          let cursor: Date | null = null
          let fetchedCount = 0
          let chunkIndex = 0

          while (fetchedCount < MAX_MESSAGES) {
            const chunkWhere: {
              conversationId: { in: string[] }
              createdAt?: { gte?: Date; lt?: Date }
            } = {
              conversationId: { in: conversationIds }
            }

            // Apply MAX_MESSAGES limit
            if (oldestMessage) {
              chunkWhere.createdAt = { gte: oldestMessage.createdAt }
            }

            // Apply cursor for pagination
            if (cursor) {
              chunkWhere.createdAt = {
                ...chunkWhere.createdAt,
                lt: cursor
              }
            }

            const messages = await prisma.message.findMany({
              where: chunkWhere,
              orderBy: { createdAt: 'desc' },
              take: CHUNK_SIZE,
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

            if (messages.length === 0) {
              break
            }

            // Send chunk
            controller.enqueue(
              encoder.encode(
                `data: ${JSON.stringify({
                  type: 'chunk',
                  chunkIndex,
                  messages,
                  hasMore: messages.length === CHUNK_SIZE && (fetchedCount + messages.length) < MAX_MESSAGES
                })}\n\n`
              )
            )

            fetchedCount += messages.length
            chunkIndex++

            // Update cursor for next chunk
            cursor = messages[messages.length - 1].createdAt

            // If we got fewer messages than requested, we're done
            if (messages.length < CHUNK_SIZE) {
              break
            }

            // Prevent infinite loops
            if (fetchedCount >= MAX_MESSAGES) {
              break
            }
          }

          // Send completion signal
          controller.enqueue(
            encoder.encode(
              `data: ${JSON.stringify({ type: 'complete', totalFetched: fetchedCount })}\n\n`
            )
          )
          controller.close()
        } catch (error) {
          console.error('Error streaming messages:', error)
          controller.enqueue(
            encoder.encode(
              `data: ${JSON.stringify({ type: 'error', error: 'Failed to stream messages' })}\n\n`
            )
          )
          controller.close()
        }
      }
    })

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      },
    })
  } catch (error) {
    console.error('Error setting up message stream:', error)
    return new Response('Failed to setup message stream', { status: 500 })
  }
}

