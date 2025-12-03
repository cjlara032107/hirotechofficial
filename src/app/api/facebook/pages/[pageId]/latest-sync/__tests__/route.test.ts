/**
 * Tests for /api/facebook/pages/[pageId]/latest-sync endpoint
 * 
 * Test cases:
 * 1. Returns 404 when page doesn't exist
 * 2. Returns 403 when user doesn't own page
 * 3. Returns 200 with jobId for valid request
 */

import { GET } from '../route';
import { NextRequest } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { getLatestSyncJob } from '@/lib/facebook/background-sync';

// Mock dependencies
jest.mock('@/auth');
jest.mock('@/lib/db', () => ({
  prisma: {
    facebookPage: {
      findUnique: jest.fn(),
    },
  },
}));
jest.mock('@/lib/facebook/background-sync', () => ({
  getLatestSyncJob: jest.fn(),
}));

const mockAuth = auth as jest.MockedFunction<typeof auth>;
const mockPrisma = prisma as jest.Mocked<typeof prisma>;
const mockGetLatestSyncJob = getLatestSyncJob as jest.MockedFunction<typeof getLatestSyncJob>;

describe('GET /api/facebook/pages/[pageId]/latest-sync', () => {
  const mockPageId = 'test-page-id';
  const mockOrganizationId = 'test-org-id';
  const mockOtherOrganizationId = 'other-org-id';
  const mockUserId = 'test-user-id';

  const mockSession = {
    user: {
      id: mockUserId,
      organizationId: mockOrganizationId,
    },
  };

  const createMockRequest = (pageId: string) => {
    return new NextRequest(`http://localhost:3000/api/facebook/pages/${pageId}/latest-sync`);
  };

  const createMockParams = (pageId: string) => {
    return Promise.resolve({ pageId });
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Test: Returns 404 when page does not exist', () => {
    it('should return 404 when page is not found', async () => {
      // Arrange
      mockAuth.mockResolvedValue(mockSession);
      mockPrisma.facebookPage.findUnique.mockResolvedValue(null);

      const request = createMockRequest(mockPageId);
      const params = createMockParams(mockPageId);

      // Act
      const response = await GET(request, { params });
      const responseData = await response.json();

      // Assert
      expect(response.status).toBe(404);
      expect(responseData).toEqual({ error: 'Page not found' });
      expect(mockPrisma.facebookPage.findUnique).toHaveBeenCalledWith({
        where: { id: mockPageId },
      });
      expect(mockGetLatestSyncJob).not.toHaveBeenCalled();
    });
  });

  describe('Test: Returns 403 when user does not own page', () => {
    it('should return 403 when page exists but belongs to different organization', async () => {
      // Arrange
      const pageFromOtherOrg = {
        id: mockPageId,
        organizationId: mockOtherOrganizationId,
        pageName: 'Test Page',
        pageId: 'fb-page-id',
        accessToken: 'encrypted-token',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockAuth.mockResolvedValue(mockSession);
      mockPrisma.facebookPage.findUnique.mockResolvedValue(pageFromOtherOrg);

      const request = createMockRequest(mockPageId);
      const params = createMockParams(mockPageId);

      // Act
      const response = await GET(request, { params });
      const responseData = await response.json();

      // Assert
      expect(response.status).toBe(403);
      expect(responseData).toEqual({
        error: 'Forbidden: You do not have access to this page',
      });
      expect(mockPrisma.facebookPage.findUnique).toHaveBeenCalledWith({
        where: { id: mockPageId },
      });
      expect(mockGetLatestSyncJob).not.toHaveBeenCalled();
    });
  });

  describe('Test: Returns 200 with jobId for valid request', () => {
    it('should return 200 with job data when page exists and user owns it', async () => {
      // Arrange
      const ownedPage = {
        id: mockPageId,
        organizationId: mockOrganizationId,
        pageName: 'Test Page',
        pageId: 'fb-page-id',
        accessToken: 'encrypted-token',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const mockJob = {
        id: 'test-job-id',
        status: 'COMPLETED',
        syncedContacts: 100,
        failedContacts: 5,
        totalContacts: 105,
        tokenExpired: false,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:05:00Z'),
        createdAt: new Date('2024-01-01T10:00:00Z'),
        facebookPageId: mockPageId,
        organizationId: mockOrganizationId,
      };

      mockAuth.mockResolvedValue(mockSession);
      mockPrisma.facebookPage.findUnique.mockResolvedValue(ownedPage);
      mockGetLatestSyncJob.mockResolvedValue(mockJob);

      const request = createMockRequest(mockPageId);
      const params = createMockParams(mockPageId);

      // Act
      const response = await GET(request, { params });
      const responseData = await response.json();

      // Assert
      expect(response.status).toBe(200);
      expect(responseData).toEqual({
        job: {
          id: mockJob.id,
          status: mockJob.status,
          syncedContacts: mockJob.syncedContacts,
          failedContacts: mockJob.failedContacts,
          totalContacts: mockJob.totalContacts,
          tokenExpired: mockJob.tokenExpired,
          startedAt: mockJob.startedAt,
          completedAt: mockJob.completedAt,
          createdAt: mockJob.createdAt,
        },
      });
      expect(mockPrisma.facebookPage.findUnique).toHaveBeenCalledWith({
        where: { id: mockPageId },
      });
      expect(mockGetLatestSyncJob).toHaveBeenCalledWith(mockPageId);
    });

    it('should return 200 with null job when page exists but no sync job found', async () => {
      // Arrange
      const ownedPage = {
        id: mockPageId,
        organizationId: mockOrganizationId,
        pageName: 'Test Page',
        pageId: 'fb-page-id',
        accessToken: 'encrypted-token',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockAuth.mockResolvedValue(mockSession);
      mockPrisma.facebookPage.findUnique.mockResolvedValue(ownedPage);
      mockGetLatestSyncJob.mockResolvedValue(null);

      const request = createMockRequest(mockPageId);
      const params = createMockParams(mockPageId);

      // Act
      const response = await GET(request, { params });
      const responseData = await response.json();

      // Assert
      expect(response.status).toBe(200);
      expect(responseData).toEqual({ job: null });
      expect(mockPrisma.facebookPage.findUnique).toHaveBeenCalledWith({
        where: { id: mockPageId },
      });
      expect(mockGetLatestSyncJob).toHaveBeenCalledWith(mockPageId);
    });
  });

  describe('Edge cases', () => {
    it('should return 401 when user is not authenticated', async () => {
      // Arrange
      mockAuth.mockResolvedValue(null);

      const request = createMockRequest(mockPageId);
      const params = createMockParams(mockPageId);

      // Act
      const response = await GET(request, { params });
      const responseData = await response.json();

      // Assert
      expect(response.status).toBe(401);
      expect(responseData).toEqual({ error: 'Unauthorized' });
      expect(mockPrisma.facebookPage.findUnique).not.toHaveBeenCalled();
    });

    it('should return 500 when database error occurs', async () => {
      // Arrange
      mockAuth.mockResolvedValue(mockSession);
      mockPrisma.facebookPage.findUnique.mockRejectedValue(
        new Error('Database connection error')
      );

      const request = createMockRequest(mockPageId);
      const params = createMockParams(mockPageId);

      // Act
      const response = await GET(request, { params });
      const responseData = await response.json();

      // Assert
      expect(response.status).toBe(500);
      expect(responseData).toEqual({
        error: 'Failed to fetch latest sync job',
      });
    });
  });
});









