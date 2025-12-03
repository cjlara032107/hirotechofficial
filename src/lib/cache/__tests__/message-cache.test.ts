import {
  getCachedChunk,
  setCachedChunk,
  clearCacheForConversations,
  getMaxMessagesPerConversation,
  getChunkSize,
} from '../message-cache'

describe('Message Cache', () => {
  beforeEach(() => {
    // Clear cache before each test
    clearCacheForConversations(['conv1', 'conv2'])
  })

  describe('getCachedChunk', () => {
    it('should return null for non-existent cache', () => {
      const result = getCachedChunk(['conv1'], 0)
      expect(result).toBeNull()
    })

    it('should return cached chunk when it exists', () => {
      const chunk = {
        conversationId: 'conv1',
        chunkIndex: 0,
        messages: [{ id: 'msg1', content: 'Test', platform: 'MESSENGER', isFromBusiness: true, status: 'SENT', createdAt: new Date() }],
        cursor: null,
        hasMore: false,
      }

      setCachedChunk(['conv1'], 0, chunk, 60)
      const result = getCachedChunk(['conv1'], 0)

      expect(result).not.toBeNull()
      expect(result?.messages).toEqual(chunk.messages)
      expect(result?.hasMore).toBe(false)
    })

    it('should return null for expired cache', async () => {
      const chunk = {
        conversationId: 'conv1',
        chunkIndex: 0,
        messages: [{ id: 'msg1', content: 'Test', platform: 'MESSENGER', isFromBusiness: true, status: 'SENT', createdAt: new Date() }],
        cursor: null,
        hasMore: false,
      }

      setCachedChunk(['conv1'], 0, chunk, 0.001) // Very short TTL (1ms)
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10))
      
      const result = getCachedChunk(['conv1'], 0)
      expect(result).toBeNull()
    })
  })

  describe('setCachedChunk', () => {
    it('should cache a chunk successfully', () => {
      const chunk = {
        conversationId: 'conv1',
        chunkIndex: 0,
        messages: [{ id: 'msg1', content: 'Test', platform: 'MESSENGER', isFromBusiness: true, status: 'SENT', createdAt: new Date() }],
        cursor: 'cursor1',
        hasMore: true,
      }

      setCachedChunk(['conv1'], 0, chunk, 60)
      const result = getCachedChunk(['conv1'], 0, 'cursor1')

      expect(result).not.toBeNull()
      expect(result?.messages).toEqual(chunk.messages)
      expect(result?.hasMore).toBe(true)
    })

    it('should handle different chunk indices', () => {
      const chunk1 = {
        conversationId: 'conv1',
        chunkIndex: 0,
        messages: [{ id: 'msg1', content: 'Test 1', platform: 'MESSENGER', isFromBusiness: true, status: 'SENT', createdAt: new Date() }],
        cursor: 'cursor1',
        hasMore: true,
      }

      const chunk2 = {
        conversationId: 'conv1',
        chunkIndex: 1,
        messages: [{ id: 'msg2', content: 'Test 2', platform: 'MESSENGER', isFromBusiness: true, status: 'SENT', createdAt: new Date() }],
        cursor: 'cursor2',
        hasMore: false,
      }

      setCachedChunk(['conv1'], 0, chunk1, 60)
      setCachedChunk(['conv1'], 1, chunk2, 60)

      const result1 = getCachedChunk(['conv1'], 0, 'cursor1')
      const result2 = getCachedChunk(['conv1'], 1, 'cursor2')

      expect(result1?.messages[0].content).toBe('Test 1')
      expect(result2?.messages[0].content).toBe('Test 2')
    })
  })

  describe('clearCacheForConversations', () => {
    it('should clear cache for specific conversations', () => {
      const chunk = {
        conversationId: 'conv1',
        chunkIndex: 0,
        messages: [{ id: 'msg1', content: 'Test', platform: 'MESSENGER', isFromBusiness: true, status: 'SENT', createdAt: new Date() }],
        cursor: null,
        hasMore: false,
      }

      setCachedChunk(['conv1'], 0, chunk, 60)
      expect(getCachedChunk(['conv1'], 0)).not.toBeNull()

      clearCacheForConversations(['conv1'])
      expect(getCachedChunk(['conv1'], 0)).toBeNull()
    })
  })

  describe('getMaxMessagesPerConversation', () => {
    it('should return 200', () => {
      expect(getMaxMessagesPerConversation()).toBe(200)
    })
  })

  describe('getChunkSize', () => {
    it('should return 50', () => {
      expect(getChunkSize()).toBe(50)
    })
  })
})









