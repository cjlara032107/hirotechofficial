import { createHash } from 'crypto'

// Optimized for large conversations (10,000+ messages)
// Chunk size: balance between performance and memory
const MESSAGE_CHUNK_SIZE = 50
// Maximum messages to fetch per conversation
// For very large conversations, we'll fetch the most recent messages
// Users can paginate backwards through history
const MAX_MESSAGES_PER_CONVERSATION = 200
const CACHE_TTL_SECONDS = 300 // 5 minutes

interface MessageChunk {
  conversationId: string
  chunkIndex: number
  messages: Array<{
    id: string
    content: string
    platform: string
    isFromBusiness: boolean
    status: string
    createdAt: string | Date
    sentAt?: string | Date | null
    deliveredAt?: string | Date | null
    readAt?: string | Date | null
    conversation?: {
      platform: string
      facebookPage: {
        pageName: string
      }
    }
  }>
  cursor: string | null
  hasMore: boolean
  cachedAt: Date
  expiresAt: Date
}

// In-memory cache (for production, consider Redis)
const messageCache = new Map<string, MessageChunk>()

/**
 * Generate cache key for a message chunk
 */
function getCacheKey(conversationIds: string[], chunkIndex: number, cursor?: string | null): string {
  const key = `${conversationIds.sort().join(',')}:${chunkIndex}:${cursor || 'initial'}`
  return createHash('sha256').update(key).digest('hex')
}

/**
 * Get cached message chunk
 */
export function getCachedChunk(
  conversationIds: string[],
  chunkIndex: number,
  cursor?: string | null
): MessageChunk | null {
  const cacheKey = getCacheKey(conversationIds, chunkIndex, cursor)
  const cached = messageCache.get(cacheKey)

  if (!cached) {
    return null
  }

  // Check if cache is expired
  if (cached.expiresAt < new Date()) {
    messageCache.delete(cacheKey)
    return null
  }

  return cached
}

/**
 * Cache a message chunk
 */
export function setCachedChunk(
  conversationIds: string[],
  chunkIndex: number,
  chunk: Omit<MessageChunk, 'cachedAt' | 'expiresAt'>,
  ttlSeconds: number = CACHE_TTL_SECONDS
): void {
  const cacheKey = getCacheKey(conversationIds, chunkIndex, chunk.cursor)
  const now = new Date()
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000)

  messageCache.set(cacheKey, {
    ...chunk,
    cachedAt: now,
    expiresAt,
  })

  // Clean up expired entries periodically (keep cache size manageable)
  if (messageCache.size > 1000) {
    const now = new Date()
    for (const [key, value] of messageCache.entries()) {
      if (value.expiresAt < now) {
        messageCache.delete(key)
      }
    }
  }
}

/**
 * Clear cache for specific conversations
 */
export function clearCacheForConversations(conversationIds: string[]): void {
  const keysToDelete: string[] = []
  for (const [key, value] of messageCache.entries()) {
    if (conversationIds.some(id => value.conversationId === id)) {
      keysToDelete.push(key)
    }
  }
  keysToDelete.forEach(key => messageCache.delete(key))
}

/**
 * Get the maximum number of messages to fetch per conversation
 */
export function getMaxMessagesPerConversation(): number {
  return MAX_MESSAGES_PER_CONVERSATION
}

/**
 * Get the chunk size for message fetching
 */
export function getChunkSize(): number {
  return MESSAGE_CHUNK_SIZE
}

