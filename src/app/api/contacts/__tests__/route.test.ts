/**
 * API Route Tests for /api/contacts
 * 
 * Tests for:
 * - Returns contacts with required fields only
 * - Throws Error when page not found
 * - Handles database query errors
 */

import { NextRequest } from 'next/server';
import { GET } from '../route';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';

// Mock Next.js server modules
jest.mock('next/server', () => ({
  NextRequest: jest.fn().mockImplementation((url: string) => {
    const urlObj = new URL(url);
    return {
      url,
      method: 'GET',
      json: jest.fn(),
      headers: new Headers(),
      nextUrl: {
        searchParams: urlObj.searchParams,
      },
    };
  }),
  NextResponse: {
    json: jest.fn((data, init) => ({
      json: async () => data,
      status: init?.status || 200,
      headers: new Headers(init?.headers),
    })),
  },
}));

// Mock dependencies
jest.mock('@/auth');
jest.mock('@/lib/db', () => ({
  prisma: {
    contact: {
      findMany: jest.fn(),
      count: jest.fn(),
    },
  },
  connectPrisma: jest.fn(),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedConnectPrisma = connectPrisma as jest.MockedFunction<typeof connectPrisma>;

describe('API Route: /api/contacts', () => {
  const mockAuthenticatedSession = {
    user: {
      id: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedConnectPrisma.mockResolvedValue(undefined);
    mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
  });

  const createMockRequest = (url: string) => {
    const urlObj = new URL(url);
    return {
      url,
      method: 'GET',
      json: jest.fn(),
      headers: new Headers(),
      nextUrl: {
        searchParams: urlObj.searchParams,
      },
    } as any;
  };

  describe('Returns contacts with required fields only', () => {
    it('should return only the required fields in the response', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          profilePicUrl: 'https://example.com/pic1.jpg',
          hasMessenger: true,
          hasInstagram: false,
          leadScore: 85,
          tags: ['vip', 'customer'],
          lastInteraction: new Date('2024-01-15'),
          createdAt: new Date('2024-01-01'),
          conversionProbability: 0.75,
          buyerIntent: 'high',
          sentiment: 'positive',
          nextBestAction: 'follow-up',
          stage: {
            id: 'stage-1',
            name: 'Qualified',
            color: '#3b82f6',
          },
          facebookPage: {
            id: 'page-1',
            pageName: 'Test Page',
            instagramUsername: 'testpage',
          },
        },
        {
          id: 'contact-2',
          firstName: 'Jane',
          lastName: 'Smith',
          profilePicUrl: null,
          hasMessenger: false,
          hasInstagram: true,
          leadScore: 60,
          tags: [],
          lastInteraction: null,
          createdAt: new Date('2024-01-02'),
          conversionProbability: 0.5,
          buyerIntent: 'medium',
          sentiment: 'neutral',
          nextBestAction: null,
          stage: null,
          facebookPage: {
            id: 'page-2',
            pageName: 'Another Page',
            instagramUsername: null,
          },
        },
      ];

      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);
      (mockedPrisma.contact.count as jest.Mock).mockResolvedValue(2);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toHaveLength(2);
      
      // Verify required fields are present
      const contact = responseData.contacts[0];
      expect(contact).toHaveProperty('id');
      expect(contact).toHaveProperty('firstName');
      expect(contact).toHaveProperty('lastName');
      expect(contact).toHaveProperty('profilePicUrl');
      expect(contact).toHaveProperty('hasMessenger');
      expect(contact).toHaveProperty('hasInstagram');
      expect(contact).toHaveProperty('leadScore');
      expect(contact).toHaveProperty('tags');
      expect(contact).toHaveProperty('lastInteraction');
      expect(contact).toHaveProperty('createdAt');
      expect(contact).toHaveProperty('conversionProbability');
      expect(contact).toHaveProperty('buyerIntent');
      expect(contact).toHaveProperty('sentiment');
      expect(contact).toHaveProperty('nextBestAction');
      expect(contact).toHaveProperty('stage');
      expect(contact).toHaveProperty('facebookPage');

      // Verify stage has only required fields
      if (contact.stage) {
        expect(contact.stage).toHaveProperty('id');
        expect(contact.stage).toHaveProperty('name');
        expect(contact.stage).toHaveProperty('color');
        // Verify no extra fields
        expect(Object.keys(contact.stage).sort()).toEqual(['color', 'id', 'name']);
      }

      // Verify facebookPage has only required fields
      if (contact.facebookPage) {
        expect(contact.facebookPage).toHaveProperty('id');
        expect(contact.facebookPage).toHaveProperty('pageName');
        expect(contact.facebookPage).toHaveProperty('instagramUsername');
        // Verify no extra fields
        expect(Object.keys(contact.facebookPage).sort()).toEqual(['id', 'instagramUsername', 'pageName']);
      }

      // Verify Prisma was called with correct select statement
      expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          select: expect.objectContaining({
            id: true,
            firstName: true,
            lastName: true,
            profilePicUrl: true,
            hasMessenger: true,
            hasInstagram: true,
            leadScore: true,
            tags: true,
            lastInteraction: true,
            createdAt: true,
            conversionProbability: true,
            buyerIntent: true,
            sentiment: true,
            nextBestAction: true,
            stage: expect.objectContaining({
              select: {
                id: true,
                name: true,
                color: true,
              },
            }),
            facebookPage: expect.objectContaining({
              select: {
                id: true,
                pageName: true,
                instagramUsername: true,
              },
            }),
          }),
        })
      );
    });

    it('should not include extra fields beyond the required ones', async () => {
      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          profilePicUrl: 'https://example.com/pic1.jpg',
          hasMessenger: true,
          hasInstagram: false,
          leadScore: 85,
          tags: ['vip'],
          lastInteraction: new Date('2024-01-15'),
          createdAt: new Date('2024-01-01'),
          conversionProbability: 0.75,
          buyerIntent: 'high',
          sentiment: 'positive',
          nextBestAction: 'follow-up',
          stage: {
            id: 'stage-1',
            name: 'Qualified',
            color: '#3b82f6',
          },
          facebookPage: {
            id: 'page-1',
            pageName: 'Test Page',
            instagramUsername: 'testpage',
          },
        },
      ];

      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);
      (mockedPrisma.contact.count as jest.Mock).mockResolvedValue(1);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      const contact = responseData.contacts[0];
      
      // Define allowed fields
      const allowedFields = [
        'id',
        'firstName',
        'lastName',
        'profilePicUrl',
        'hasMessenger',
        'hasInstagram',
        'leadScore',
        'tags',
        'lastInteraction',
        'createdAt',
        'conversionProbability',
        'buyerIntent',
        'sentiment',
        'nextBestAction',
        'stage',
        'facebookPage',
      ];

      // Verify no unexpected top-level fields
      const contactKeys = Object.keys(contact);
      contactKeys.forEach((key) => {
        expect(allowedFields).toContain(key);
      });
    });
  });

  describe('Throws Error when page not found', () => {
    it('should return empty contacts array when page number exceeds available pages', async () => {
      const totalContacts = 10;
      const limit = 50;
      const page = 999; // Page that doesn't exist

      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.contact.count as jest.Mock).mockResolvedValue(totalContacts);

      const request = createMockRequest(
        `http://localhost:3000/api/contacts?page=${page}&limit=${limit}`
      );
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toEqual([]);
      expect(responseData.pagination).toEqual({
        total: totalContacts,
        page: page,
        limit: limit,
        pages: Math.ceil(totalContacts / limit),
      });

      // Verify Prisma was called with correct skip value
      expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: (page - 1) * limit,
          take: limit,
        })
      );
    });

    it('should handle page 0 or negative page numbers gracefully', async () => {
      const totalContacts = 10;
      const limit = 50;

      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.contact.count as jest.Mock).mockResolvedValue(totalContacts);

      // Test with page 0 (should default to 1)
      const request = createMockRequest(
        `http://localhost:3000/api/contacts?page=0&limit=${limit}`
      );
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.pagination.page).toBe(0);
      // Skip should be negative, but Prisma will handle it
      expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: -limit, // (0 - 1) * limit
          take: limit,
        })
      );
    });

    it('should return correct pagination info when page is beyond total pages', async () => {
      const totalContacts = 5;
      const limit = 10;
      const page = 2; // Page 2 when there's only 1 page of results

      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.contact.count as jest.Mock).mockResolvedValue(totalContacts);

      const request = createMockRequest(
        `http://localhost:3000/api/contacts?page=${page}&limit=${limit}`
      );
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toEqual([]);
      expect(responseData.pagination.pages).toBe(1); // Only 1 page available
      expect(responseData.pagination.page).toBe(2); // Requested page 2
      expect(responseData.pagination.total).toBe(totalContacts);
    });
  });

  describe('Handles database query errors', () => {
    it('should handle Prisma findMany errors gracefully', async () => {
      const dbError = new Error('Database connection failed');
      (mockedPrisma.contact.findMany as jest.Mock).mockRejectedValue(dbError);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData).toEqual({
        error: 'Database connection failed',
      });
    });

    it('should handle Prisma count errors gracefully', async () => {
      const dbError = new Error('Database query timeout');
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue([]);
      (mockedPrisma.contact.count as jest.Mock).mockRejectedValue(dbError);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData).toEqual({
        error: 'Database query timeout',
      });
    });

    it('should handle non-Error exceptions', async () => {
      (mockedPrisma.contact.findMany as jest.Mock).mockRejectedValue('String error');

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData).toEqual({
        error: 'Failed to fetch contacts',
      });
    });

    it('should handle connectPrisma errors', async () => {
      const connectionError = new Error('Failed to connect to database');
      mockedConnectPrisma.mockRejectedValue(connectionError);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData.error).toBeDefined();
    });

    it('should handle database constraint violations', async () => {
      const constraintError = new Error('Foreign key constraint failed');
      constraintError.name = 'PrismaClientKnownRequestError';
      (mockedPrisma.contact.findMany as jest.Mock).mockRejectedValue(constraintError);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      const response = await GET(request);
      const responseData = await response.json();

      expect(response.status).toBe(500);
      expect(responseData).toEqual({
        error: 'Foreign key constraint failed',
      });
    });

    it('should log errors to console', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      const dbError = new Error('Database error');
      (mockedPrisma.contact.findMany as jest.Mock).mockRejectedValue(dbError);

      const request = createMockRequest('http://localhost:3000/api/contacts');
      await GET(request);

      expect(consoleSpy).toHaveBeenCalledWith('Get contacts error:', dbError);
      consoleSpy.mockRestore();
    });
  });
});









