/**
 * API Route Tests for /api/campaigns/preview-contacts
 * 
 * Tests for:
 * - Filters out contacts without Messenger/Instagram IDs
 * - Handles page with no contacts (returns empty array)
 * - Handles page with no pipeline configured
 */

import { NextRequest, NextResponse } from 'next/server';
import { POST } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';

// Mock Next.js server modules
jest.mock('next/server', () => ({
  NextRequest: jest.fn().mockImplementation((url, init) => ({
    url,
    method: init?.method || 'POST',
    json: jest.fn(),
    headers: new Headers(init?.headers),
  })),
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
    },
    facebookPage: {
      findFirst: jest.fn(),
    },
  },
}));

jest.mock('@/lib/api/validate-session', () => ({
  validateSession: jest.fn(),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedValidateSession = validateSession as jest.MockedFunction<typeof validateSession>;

describe('API Route: /api/campaigns/preview-contacts', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  const mockAuthenticatedSession = {
    user: {
      id: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
    },
  };

  describe('Filters out contacts without Messenger/Instagram IDs', () => {
    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession as any,
      });
    });

    it('should filter out contacts without messengerPSID when platform is MESSENGER', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
      };

      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          hasMessenger: true,
          messengerPSID: 'psid-123', // Has ID
          hasInstagram: false,
          instagramSID: null,
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
        {
          id: 'contact-2',
          firstName: 'Jane',
          lastName: 'Smith',
          hasMessenger: true,
          messengerPSID: null, // Missing ID - should be filtered out
          hasInstagram: false,
          instagramSID: null,
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
        {
          id: 'contact-3',
          firstName: 'Bob',
          lastName: 'Johnson',
          hasMessenger: false,
          messengerPSID: null,
          hasInstagram: false,
          instagramSID: null,
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
      ];

      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          facebookPageId: 'page-123',
          platform: 'MESSENGER',
          targetingType: 'ALL_CONTACTS',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toHaveLength(1);
      expect(responseData.contacts[0].id).toBe('contact-1');
      expect(responseData.contacts[0].hasMessenger).toBe(true);
      expect(responseData.total).toBe(1);
    });

    it('should filter out contacts without instagramSID when platform is INSTAGRAM', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
      };

      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          hasMessenger: false,
          messengerPSID: null,
          hasInstagram: true,
          instagramSID: 'ig-sid-123', // Has ID
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
        {
          id: 'contact-2',
          firstName: 'Jane',
          lastName: 'Smith',
          hasMessenger: false,
          messengerPSID: null,
          hasInstagram: true,
          instagramSID: null, // Missing ID - should be filtered out
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
      ];

      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          facebookPageId: 'page-123',
          platform: 'INSTAGRAM',
          targetingType: 'ALL_CONTACTS',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toHaveLength(1);
      expect(responseData.contacts[0].id).toBe('contact-1');
      expect(responseData.contacts[0].hasInstagram).toBe(true);
      expect(responseData.total).toBe(1);
    });

    it('should not filter by IDs for SPECIFIC_CONTACTS targeting type', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
      };

      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          hasMessenger: true,
          messengerPSID: null, // Missing ID but should still be included
          hasInstagram: false,
          instagramSID: null,
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
      ];

      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          targetingType: 'SPECIFIC_CONTACTS',
          targetContactIds: ['contact-1'],
          platform: 'MESSENGER',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toHaveLength(1);
      expect(responseData.contacts[0].id).toBe('contact-1');
      expect(responseData.total).toBe(1);
    });
  });

  describe('Handles page with no contacts (returns empty array)', () => {
    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession as any,
      });
    });

    it('should return empty array when page has no contacts', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
      };

      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue([]);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          facebookPageId: 'page-123',
          platform: 'MESSENGER',
          targetingType: 'ALL_CONTACTS',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toEqual([]);
      expect(responseData.total).toBe(0);
      expect(Array.isArray(responseData.contacts)).toBe(true);
    });

    it('should return empty array when page has contacts but all are filtered out', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
      };

      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          hasMessenger: true,
          messengerPSID: null, // Missing ID - will be filtered out
          hasInstagram: false,
          instagramSID: null,
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
      ];

      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          facebookPageId: 'page-123',
          platform: 'MESSENGER',
          targetingType: 'ALL_CONTACTS',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.contacts).toEqual([]);
      expect(responseData.total).toBe(0);
    });
  });

  describe('Handles page with no pipeline configured', () => {
    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession as any,
      });
    });

    it('should handle page with no pipeline configured (autoPipelineId is null)', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
        autoPipelineId: null, // No pipeline configured
      };

      const mockContacts = [
        {
          id: 'contact-1',
          firstName: 'John',
          lastName: 'Doe',
          hasMessenger: true,
          messengerPSID: 'psid-123',
          hasInstagram: false,
          instagramSID: null,
          organizationId: 'org-123',
          facebookPageId: 'page-123',
          tags: [],
          email: null,
          phone: null,
          aiContext: null,
          lastInteraction: null,
          facebookPage: mockPage,
        },
      ];

      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          facebookPageId: 'page-123',
          platform: 'MESSENGER',
          targetingType: 'ALL_CONTACTS',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      // Should work correctly even without pipeline configured
      expect(response.status).toBe(200);
      expect(responseData.contacts).toHaveLength(1);
      expect(responseData.contacts[0].id).toBe('contact-1');
      expect(responseData.total).toBe(1);
    });

    it('should handle page with no pipeline configured and no contacts', async () => {
      const mockPage = {
        id: 'page-123',
        pageName: 'Test Page',
        organizationId: 'org-123',
        autoPipelineId: null, // No pipeline configured
      };

      (mockedPrisma.facebookPage.findFirst as jest.Mock).mockResolvedValue(mockPage);
      (mockedPrisma.contact.findMany as jest.Mock).mockResolvedValue([]);

      const request = {
        url: 'http://localhost:3000/api/campaigns/preview-contacts',
        method: 'POST',
        json: jest.fn().mockResolvedValue({
          facebookPageId: 'page-123',
          platform: 'MESSENGER',
          targetingType: 'ALL_CONTACTS',
        }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      // Should return empty array without errors
      expect(response.status).toBe(200);
      expect(responseData.contacts).toEqual([]);
      expect(responseData.total).toBe(0);
    });
  });
});

