import { GET } from '../route'
import { NextRequest } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { getCachedChunk, setCachedChunk } from '@/lib/cache/message-cache'

jest.mock('@/auth')
jest.mock('@/lib/db')
jest.mock('@/lib/cache/message-cache')

const mockAuth = auth as jest.MockedFunction<typeof auth>
const mockPrisma = prisma as jest.Mocked<typeof prisma>
const mockGetCachedChunk = getCachedChunk as jest.MockedFunction<typeof getCachedChunk>
const mockSetCachedChunk = setCachedChunk as jest.MockedFunction<typeof setCachedChunk>

describe('GET /api/contacts/[id]/messages', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockAuth.mockResolvedValue({
      user: {
        id: 'user1',
        email: 'test@example.com',
        organizationId: 'org1',
      },
    } as any)
  })

  it('should return 401 if not authenticated', async () => {
    mockAuth.mockResolvedValue(null)

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(401)
    expect(data.error).toBe('Unauthorized')
  })

  it('should return 404 if contact not found', async () => {
    mockPrisma.contact.findFirst = jest.fn().mockResolvedValue(null)

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(404)
    expect(data.error).toBe('Contact not found')
  })

  it('should return empty messages if no conversations exist', async () => {
    mockPrisma.contact.findFirst = jest.fn().mockResolvedValue({ id: 'contact1' })
    mockPrisma.conversation.findMany = jest.fn().mockResolvedValue([])

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.messages).toEqual([])
    expect(data.total).toBe(0)
    expect(data.hasMore).toBe(false)
    expect(data.maxMessages).toBe(200)
  })

  it('should return cached messages when available', async () => {
    mockPrisma.contact.findFirst = jest.fn().mockResolvedValue({ id: 'contact1' })
    mockPrisma.conversation.findMany = jest.fn().mockResolvedValue([{ id: 'conv1' }])

    const cachedChunk = {
      conversationId: 'conv1',
      chunkIndex: 0,
      messages: [
        {
          id: 'msg1',
          content: 'Test message',
          platform: 'MESSENGER',
          isFromBusiness: true,
          status: 'SENT',
          createdAt: new Date(),
        },
      ],
      cursor: null,
      hasMore: false,
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + 300000),
    }

    mockGetCachedChunk.mockReturnValue(cachedChunk)

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages?cursor=2024-01-01T00:00:00Z')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.messages).toEqual(cachedChunk.messages)
    expect(data.cached).toBe(true)
    expect(mockPrisma.message.findMany).not.toHaveBeenCalled()
  })

  it('should fetch messages from database when cache miss', async () => {
    mockPrisma.contact.findFirst = jest.fn().mockResolvedValue({ id: 'contact1' })
    mockPrisma.conversation.findMany = jest.fn().mockResolvedValue([{ id: 'conv1' }])
    mockGetCachedChunk.mockReturnValue(null)
    mockPrisma.message.findFirst = jest.fn().mockResolvedValue(null)
    mockPrisma.message.findMany = jest.fn().mockResolvedValue([
      {
        id: 'msg1',
        content: 'Test message',
        platform: 'MESSENGER',
        isFromBusiness: true,
        status: 'SENT',
        createdAt: new Date(),
        conversation: {
          platform: 'MESSENGER',
          facebookPage: {
            pageName: 'Test Page',
          },
        },
      },
    ])
    mockPrisma.message.count = jest.fn().mockResolvedValue(1)

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.messages).toHaveLength(1)
    expect(data.maxMessages).toBe(200)
    expect(mockPrisma.message.findMany).toHaveBeenCalled()
  })

  it('should limit messages to MAX_MESSAGES (200)', async () => {
    mockPrisma.contact.findFirst = jest.fn().mockResolvedValue({ id: 'contact1' })
    mockPrisma.conversation.findMany = jest.fn().mockResolvedValue([{ id: 'conv1' }])
    mockGetCachedChunk.mockReturnValue(null)

    // Simulate 300 messages, but should only return 200
    const oldestMessage = {
      createdAt: new Date('2024-01-01'),
    }
    mockPrisma.message.findFirst = jest.fn().mockResolvedValue(oldestMessage)

    const messages = Array.from({ length: 50 }, (_, i) => ({
      id: `msg${i}`,
      content: `Message ${i}`,
      platform: 'MESSENGER',
      isFromBusiness: true,
      status: 'SENT',
      createdAt: new Date(),
      conversation: {
        platform: 'MESSENGER',
        facebookPage: {
          pageName: 'Test Page',
        },
      },
    }))

    mockPrisma.message.findMany = jest.fn().mockResolvedValue(messages)
    mockPrisma.message.count = jest.fn().mockResolvedValue(300) // More than MAX_MESSAGES

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.total).toBeLessThanOrEqual(200)
    expect(data.maxMessages).toBe(200)
  })

  it('should cache messages when using cursor pagination', async () => {
    mockPrisma.contact.findFirst = jest.fn().mockResolvedValue({ id: 'contact1' })
    mockPrisma.conversation.findMany = jest.fn().mockResolvedValue([{ id: 'conv1' }])
    mockGetCachedChunk.mockReturnValue(null)
    mockPrisma.message.findFirst = jest.fn().mockResolvedValue(null)

    const messages = [
      {
        id: 'msg1',
        content: 'Test message',
        platform: 'MESSENGER',
        isFromBusiness: true,
        status: 'SENT',
        createdAt: new Date(),
        conversation: {
          platform: 'MESSENGER',
          facebookPage: {
            pageName: 'Test Page',
          },
        },
      },
    ]

    mockPrisma.message.findMany = jest.fn().mockResolvedValue(messages)
    mockPrisma.message.count = jest.fn().mockResolvedValue(1)

    const request = new NextRequest('http://localhost/api/contacts/contact1/messages?cursor=2024-01-01T00:00:00Z&chunkIndex=0')
    const params = Promise.resolve({ id: 'contact1' })

    const response = await GET(request, { params })
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(mockSetCachedChunk).toHaveBeenCalled()
  })
})









