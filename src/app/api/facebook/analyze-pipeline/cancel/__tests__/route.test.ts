/**
 * API Route Tests for /api/facebook/analyze-pipeline/cancel
 * 
 * Tests for:
 * - Returns 409 when job is already COMPLETED
 * - Returns 409 when job is already FAILED
 * - Returns 200 and updates status to CANCELLED
 */

import { NextRequest } from 'next/server';
import { POST } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { SyncJobStatus } from '@prisma/client';

// Mock dependencies
jest.mock('@/auth');
jest.mock('@/lib/db', () => ({
  prisma: {
    syncJob: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    facebookPage: {
      findFirst: jest.fn(),
    },
  },
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('API Route: /api/facebook/analyze-pipeline/cancel', () => {
  const mockAuthenticatedSession = {
    user: {
      id: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
    },
  };

  const mockFacebookPage = {
    id: 'page-123',
    organizationId: 'org-123',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
  });

  describe('Test: Returns 409 when job is already COMPLETED', () => {
    it('should return 409 when job status is COMPLETED', async () => {
      const mockJob = {
        id: 'job-123',
        facebookPageId: 'page-123',
        status: 'COMPLETED' as SyncJobStatus,
        totalContacts: 100,
        syncedContacts: 100,
        failedContacts: 0,
        errors: null,
        tokenExpired: false,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        createdAt: new Date('2024-01-01T10:00:00Z'),
        updatedAt: new Date('2024-01-01T10:30:00Z'),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockFacebookPage);

      const requestBody = { jobId: 'job-123' };
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline/cancel', {
        method: 'POST',
        body: JSON.stringify(requestBody),
      });
      // Mock the json method
      request.json = jest.fn().mockResolvedValue(requestBody);

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(409);
      expect(responseData.error).toBe('Cannot cancel job with status: COMPLETED');
      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: 'job-123' },
      });
      expect(mockedPrisma.syncJob.update).not.toHaveBeenCalled();
    });
  });

  describe('Test: Returns 409 when job is already FAILED', () => {
    it('should return 409 when job status is FAILED', async () => {
      const mockJob = {
        id: 'job-123',
        facebookPageId: 'page-123',
        status: 'FAILED' as SyncJobStatus,
        totalContacts: 100,
        syncedContacts: 50,
        failedContacts: 50,
        errors: [{ message: 'Sync failed' }],
        tokenExpired: false,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:15:00Z'),
        createdAt: new Date('2024-01-01T10:00:00Z'),
        updatedAt: new Date('2024-01-01T10:15:00Z'),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockFacebookPage);

      const requestBody = { jobId: 'job-123' };
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline/cancel', {
        method: 'POST',
        body: JSON.stringify(requestBody),
      });
      // Mock the json method
      request.json = jest.fn().mockResolvedValue(requestBody);

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(409);
      expect(responseData.error).toBe('Cannot cancel job with status: FAILED');
      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: 'job-123' },
      });
      expect(mockedPrisma.syncJob.update).not.toHaveBeenCalled();
    });
  });

  describe('Test: Returns 200 and updates status to CANCELLED', () => {
    it('should return 200 and update status to CANCELLED when job is PENDING', async () => {
      const mockJob = {
        id: 'job-123',
        facebookPageId: 'page-123',
        status: 'PENDING' as SyncJobStatus,
        totalContacts: 100,
        syncedContacts: 0,
        failedContacts: 0,
        errors: null,
        tokenExpired: false,
        startedAt: null,
        completedAt: null,
        createdAt: new Date('2024-01-01T10:00:00Z'),
        updatedAt: new Date('2024-01-01T10:00:00Z'),
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as SyncJobStatus,
        completedAt: new Date('2024-01-01T10:05:00Z'),
        updatedAt: new Date('2024-01-01T10:05:00Z'),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockFacebookPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const requestBody = { jobId: 'job-123' };
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline/cancel', {
        method: 'POST',
        body: JSON.stringify(requestBody),
      });
      // Mock the json method
      request.json = jest.fn().mockResolvedValue(requestBody);

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(responseData.job.status).toBe('CANCELLED');
      expect(responseData.job.completedAt).not.toBeNull();
      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: 'job-123' },
      });
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledWith({
        where: { id: 'job-123' },
        data: {
          status: 'CANCELLED',
          completedAt: expect.any(Date),
        },
      });
    });

    it('should return 200 and update status to CANCELLED when job is IN_PROGRESS', async () => {
      const mockJob = {
        id: 'job-456',
        facebookPageId: 'page-123',
        status: 'IN_PROGRESS' as SyncJobStatus,
        totalContacts: 100,
        syncedContacts: 50,
        failedContacts: 0,
        errors: null,
        tokenExpired: false,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        createdAt: new Date('2024-01-01T10:00:00Z'),
        updatedAt: new Date('2024-01-01T10:02:00Z'),
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as SyncJobStatus,
        completedAt: new Date('2024-01-01T10:05:00Z'),
        updatedAt: new Date('2024-01-01T10:05:00Z'),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockFacebookPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const requestBody = { jobId: 'job-456' };
      const request = new NextRequest('http://localhost:3000/api/facebook/analyze-pipeline/cancel', {
        method: 'POST',
        body: JSON.stringify(requestBody),
      });
      // Mock the json method
      request.json = jest.fn().mockResolvedValue(requestBody);

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(responseData.job.status).toBe('CANCELLED');
      expect(responseData.job.completedAt).not.toBeNull();
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledWith({
        where: { id: 'job-456' },
        data: {
          status: 'CANCELLED',
          completedAt: expect.any(Date),
        },
      });
    });
  });
});

