/**
 * API Route Tests for /api/facebook/sync-status/[jobId]
 * 
 * Tests for:
 * - Returns 401 for unauthenticated requests
 * - Returns 404 when job doesn't exist
 * - Returns 403 when user doesn't own job's page
 * - Returns 400 for invalid UUID format
 * - Returns 200 with complete job status
 * - Returns correct status for PENDING jobs
 * - Returns correct status for IN_PROGRESS jobs
 * - Returns correct status for COMPLETED jobs
 * - Returns correct status for FAILED jobs
 * - Returns correct status for CANCELLED jobs
 * - Returns progress counts (analyzed, failed, total)
 * - Returns errors array when present
 * - Handles null progress counts gracefully
 */

import { NextRequest, NextResponse } from 'next/server';
import { GET } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

// Mock Next.js server modules
jest.mock('next/server', () => ({
  NextRequest: jest.fn().mockImplementation((url, init) => ({
    url,
    method: init?.method || 'GET',
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
    syncJob: {
      findUnique: jest.fn(),
    },
  },
}));

jest.mock('@/lib/api/validate-session', () => ({
  validateSession: jest.fn(),
}));

jest.mock('@/lib/api/validate-uuid', () => ({
  validateUUID: jest.fn(),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedValidateSession = validateSession as jest.MockedFunction<typeof validateSession>;
const mockedValidateUUID = validateUUID as jest.MockedFunction<typeof validateUUID>;

describe('API Route: /api/facebook/sync-status/[jobId]', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Returns 401 for unauthenticated requests', () => {
    it('should return 401 when user is not authenticated', async () => {
      // Mock unauthenticated session
      mockedAuth.mockResolvedValue(null);
      const errorResponse = NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      mockedValidateSession.mockReturnValue({
        error: errorResponse,
      });
      // Mock UUID validation to pass (so we get to auth check)
      mockedValidateUUID.mockReturnValue(null);

      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(401);
      expect(responseData).toEqual({ error: 'Unauthorized' });
      expect(mockedAuth).toHaveBeenCalled();
      expect(mockedValidateSession).toHaveBeenCalledWith(null);
      expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
    });

    it('should return 401 when session exists but user is missing', async () => {
      // Mock session without user
      mockedAuth.mockResolvedValue({} as any);
      const errorResponse = NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
      mockedValidateSession.mockReturnValue({
        error: errorResponse,
      });
      // Mock UUID validation to pass (so we get to auth check)
      mockedValidateUUID.mockReturnValue(null);

      const validUuid = '123e4567-e89b-12d3-a456-426614174001';
      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(401);
      expect(responseData).toEqual({ error: 'Unauthorized' });
      expect(mockedAuth).toHaveBeenCalled();
      expect(mockedValidateSession).toHaveBeenCalledWith({});
      expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
    });
  });

  describe('Returns 404 when job doesn\'t exist', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 404 when job does not exist', async () => {
      // Mock job not found
      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(null);

      const validUuid = '123e4567-e89b-12d3-a456-426614174002';
      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(404);
      expect(responseData).toEqual({ error: 'Sync job not found' });
      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: validUuid },
        include: {
          facebookPage: {
            select: {
              organizationId: true,
            },
          },
        },
      });
    });

    it('should return 404 when job exists but facebookPage is missing', async () => {
      // Mock job found but without facebookPage
      const validUuid = '123e4567-e89b-12d3-a456-426614174003';
      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue({
        id: validUuid,
        status: 'completed',
        facebookPage: null,
      });

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(404);
      expect(responseData).toEqual({ error: 'Facebook page not found for this sync job' });
    });
  });

  describe('Returns 403 when user doesn\'t own job\'s page', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 403 when job belongs to a different organization', async () => {
      // Mock job belonging to a different organization
      const validUuid = '123e4567-e89b-12d3-a456-426614174004';
      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue({
        id: validUuid,
        status: 'completed',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 10,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: new Date('2024-01-01'),
        facebookPage: {
          organizationId: 'org-456', // Different organization
        },
      });

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(403);
      expect(responseData).toEqual({ error: 'Unauthorized access to sync job' });
      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: validUuid },
        include: {
          facebookPage: {
            select: {
              organizationId: true,
            },
          },
        },
      });
    });

    it('should return 200 when job belongs to user\'s organization', async () => {
      // Mock job belonging to user's organization
      const validUuid = '123e4567-e89b-12d3-a456-426614174005';
      const mockJob = {
        id: validUuid,
        status: 'completed',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 10,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: new Date('2024-01-01'),
        facebookPage: {
          organizationId: 'org-123', // Same organization
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData).toEqual({
        id: validUuid,
        status: 'completed',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 10,
        tokenExpired: false,
        errors: null,
        startedAt: mockJob.startedAt,
        completedAt: mockJob.completedAt,
      });
    });
  });

  describe('Returns 400 for invalid UUID format', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      // Default: valid UUID passes validation
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 400 for invalid UUID format', async () => {
      // Mock invalid UUID validation
      mockedValidateUUID.mockReturnValue({
        error: {
          message: 'Invalid UUID format',
          status: 400,
        },
      });

      const invalidJobIds = [
        'not-a-uuid',
        'invalid-uuid-format',
        '123',
        'job-123',
        '123e4567-e89b-12d3-a456', // Incomplete UUID
      ];

      for (const invalidJobId of invalidJobIds) {
        const request = {
          url: `http://localhost:3000/api/facebook/sync-status/${invalidJobId}`,
          json: jest.fn(),
        } as any;
        const params = Promise.resolve({ jobId: invalidJobId });

        const response = await GET(request, { params });
        const responseData = await response.json();

        expect(response.status).toBe(400);
        expect(responseData).toEqual({ error: 'Invalid UUID format' });
        expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
      }
    });

    it('should accept valid UUID format', async () => {
      // Mock valid UUID validation
      mockedValidateUUID.mockReturnValue(null);

      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 10,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: new Date('2024-01-01'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(mockedValidateUUID).toHaveBeenCalledWith(validUuid);
    });
  });

  describe('Returns 200 with complete job status', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 200 with complete job status information', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 150,
        failedContacts: 5,
        totalContacts: 155,
        tokenExpired: false,
        errors: [{ message: 'Some error', contactId: 'contact-1' }],
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData).toEqual({
        id: validUuid,
        status: 'COMPLETED',
        syncedContacts: 150,
        failedContacts: 5,
        totalContacts: 155,
        tokenExpired: false,
        errors: [{ message: 'Some error', contactId: 'contact-1' }],
        startedAt: mockJob.startedAt,
        completedAt: mockJob.completedAt,
      });
      expect(responseData).toHaveProperty('id');
      expect(responseData).toHaveProperty('status');
      expect(responseData).toHaveProperty('syncedContacts');
      expect(responseData).toHaveProperty('failedContacts');
      expect(responseData).toHaveProperty('totalContacts');
      expect(responseData).toHaveProperty('tokenExpired');
      expect(responseData).toHaveProperty('errors');
      expect(responseData).toHaveProperty('startedAt');
      expect(responseData).toHaveProperty('completedAt');
    });

    it('should return 200 with complete job status when some fields are null', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174001';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        syncedContacts: 50,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData).toEqual({
        id: validUuid,
        status: 'IN_PROGRESS',
        syncedContacts: 50,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: mockJob.startedAt,
        completedAt: null,
      });
    });
  });

  describe('Returns correct status for PENDING jobs', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 200 with PENDING status', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174002';
      const mockJob = {
        id: validUuid,
        status: 'PENDING' as const,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        tokenExpired: false,
        errors: null,
        startedAt: null,
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('PENDING');
      expect(responseData).toEqual({
        id: validUuid,
        status: 'PENDING',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        tokenExpired: false,
        errors: null,
        startedAt: null,
        completedAt: null,
      });
    });

    it('should return correct status for PENDING job with initial values', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174003';
      const mockJob = {
        id: validUuid,
        status: 'PENDING' as const,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 100, // Job knows total but hasn't started
        tokenExpired: false,
        errors: null,
        startedAt: null, // Not started yet
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('PENDING');
      expect(responseData.totalContacts).toBe(100);
      expect(responseData.syncedContacts).toBe(0);
      expect(responseData.startedAt).toBeNull();
      expect(responseData.completedAt).toBeNull();
    });
  });

  describe('Returns correct status for IN_PROGRESS jobs', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 200 with IN_PROGRESS status', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174004';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        syncedContacts: 50,
        failedContacts: 2,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('IN_PROGRESS');
      expect(responseData).toEqual({
        id: validUuid,
        status: 'IN_PROGRESS',
        syncedContacts: 50,
        failedContacts: 2,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: mockJob.startedAt,
        completedAt: null,
      });
    });

    it('should return correct status for IN_PROGRESS job with partial progress', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174005';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        syncedContacts: 75,
        failedContacts: 0,
        totalContacts: 200,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('IN_PROGRESS');
      expect(responseData.syncedContacts).toBe(75);
      expect(responseData.totalContacts).toBe(200);
      expect(responseData.failedContacts).toBe(0);
      expect(responseData.startedAt).not.toBeNull();
      expect(responseData.completedAt).toBeNull();
    });
  });

  describe('Returns correct status for COMPLETED jobs', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 200 with COMPLETED status', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174006';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 100,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('COMPLETED');
      expect(responseData).toEqual({
        id: validUuid,
        status: 'COMPLETED',
        syncedContacts: 100,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: mockJob.startedAt,
        completedAt: mockJob.completedAt,
      });
    });

    it('should return correct status for COMPLETED job with some failures', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174007';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 95,
        failedContacts: 5,
        totalContacts: 100,
        tokenExpired: false,
        errors: [{ message: 'Failed to sync contact', contactId: 'contact-1' }],
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('COMPLETED');
      expect(responseData.syncedContacts).toBe(95);
      expect(responseData.failedContacts).toBe(5);
      expect(responseData.totalContacts).toBe(100);
      expect(responseData.completedAt).not.toBeNull();
      expect(responseData.errors).toEqual([{ message: 'Failed to sync contact', contactId: 'contact-1' }]);
    });
  });

  describe('Returns correct status for FAILED jobs', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 200 with FAILED status', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174008';
      const mockJob = {
        id: validUuid,
        status: 'FAILED' as const,
        syncedContacts: 30,
        failedContacts: 70,
        totalContacts: 100,
        tokenExpired: false,
        errors: [{ message: 'Sync failed due to API error', code: 'API_ERROR' }],
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:15:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('FAILED');
      expect(responseData).toEqual({
        id: validUuid,
        status: 'FAILED',
        syncedContacts: 30,
        failedContacts: 70,
        totalContacts: 100,
        tokenExpired: false,
        errors: [{ message: 'Sync failed due to API error', code: 'API_ERROR' }],
        startedAt: mockJob.startedAt,
        completedAt: mockJob.completedAt,
      });
    });

    it('should return correct status for FAILED job with token expiration', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174009';
      const mockJob = {
        id: validUuid,
        status: 'FAILED' as const,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: true,
        errors: [{ message: 'Facebook access token expired', code: 'TOKEN_EXPIRED' }],
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:05:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('FAILED');
      expect(responseData.tokenExpired).toBe(true);
      expect(responseData.errors).toEqual([{ message: 'Facebook access token expired', code: 'TOKEN_EXPIRED' }]);
      expect(responseData.completedAt).not.toBeNull();
    });
  });

  describe('Returns correct status for CANCELLED jobs', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return 200 with CANCELLED status', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174010';
      const mockJob = {
        id: validUuid,
        status: 'CANCELLED' as const,
        syncedContacts: 25,
        failedContacts: 2,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:15:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('CANCELLED');
      expect(responseData).toEqual({
        id: validUuid,
        status: 'CANCELLED',
        syncedContacts: 25,
        failedContacts: 2,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: mockJob.startedAt,
        completedAt: mockJob.completedAt,
      });
    });

    it('should return correct status for CANCELLED job with partial progress', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174011';
      const mockJob = {
        id: validUuid,
        status: 'CANCELLED' as const,
        syncedContacts: 50,
        failedContacts: 5,
        totalContacts: 200,
        tokenExpired: false,
        errors: [
          { message: 'Job cancelled by user', timestamp: '2024-01-01T10:15:00Z' },
        ],
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:15:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('CANCELLED');
      expect(responseData.syncedContacts).toBe(50);
      expect(responseData.failedContacts).toBe(5);
      expect(responseData.totalContacts).toBe(200);
      expect(responseData.errors).toEqual([
        { message: 'Job cancelled by user', timestamp: '2024-01-01T10:15:00Z' },
      ]);
    });
  });

  describe('Returns progress counts (analyzed, failed, total)', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return correct progress counts for completed job', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174012';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 150, // analyzed count
        failedContacts: 10,   // failed count
        totalContacts: 160,   // total count
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData).toHaveProperty('syncedContacts', 150);
      expect(responseData).toHaveProperty('failedContacts', 10);
      expect(responseData).toHaveProperty('totalContacts', 160);
      expect(typeof responseData.syncedContacts).toBe('number');
      expect(typeof responseData.failedContacts).toBe('number');
      expect(typeof responseData.totalContacts).toBe('number');
    });

    it('should return correct progress counts for in-progress job', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174013';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        syncedContacts: 75,  // analyzed so far
        failedContacts: 3,    // failed so far
        totalContacts: 200,   // total to process
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.syncedContacts).toBe(75);
      expect(responseData.failedContacts).toBe(3);
      expect(responseData.totalContacts).toBe(200);
      // Verify counts are numbers
      expect(typeof responseData.syncedContacts).toBe('number');
      expect(typeof responseData.failedContacts).toBe('number');
      expect(typeof responseData.totalContacts).toBe('number');
    });

    it('should return zero progress counts for pending job', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174014';
      const mockJob = {
        id: validUuid,
        status: 'PENDING' as const,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        tokenExpired: false,
        errors: null,
        startedAt: null,
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.syncedContacts).toBe(0);
      expect(responseData.failedContacts).toBe(0);
      expect(responseData.totalContacts).toBe(0);
    });
  });

  describe('Returns errors array when present', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should return errors array when errors are present', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174015';
      const mockErrors = [
        { contactId: 'contact-1', error: 'Failed to sync contact', platform: 'Messenger' },
        { contactId: 'contact-2', error: 'API rate limit exceeded', platform: 'Instagram' },
        { contactId: 'contact-3', error: 'Invalid contact data', platform: 'Messenger' },
      ];
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 147,
        failedContacts: 3,
        totalContacts: 150,
        tokenExpired: false,
        errors: mockErrors,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.errors).toBeDefined();
      expect(Array.isArray(responseData.errors)).toBe(true);
      expect(responseData.errors).toHaveLength(3);
      expect(responseData.errors).toEqual(mockErrors);
      expect(responseData.errors[0]).toHaveProperty('contactId');
      expect(responseData.errors[0]).toHaveProperty('error');
    });

    it('should return errors array with single error', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174016';
      const mockErrors = [
        { error: 'Token expired during sync', timestamp: '2024-01-01T10:15:00Z' },
      ];
      const mockJob = {
        id: validUuid,
        status: 'FAILED' as const,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: true,
        errors: mockErrors,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:15:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.errors).toBeDefined();
      expect(Array.isArray(responseData.errors)).toBe(true);
      expect(responseData.errors).toHaveLength(1);
      expect(responseData.errors[0]).toEqual(mockErrors[0]);
    });

    it('should return null when errors array is not present', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174017';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        syncedContacts: 100,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: new Date('2024-01-01T10:30:00Z'),
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.errors).toBeNull();
    });
  });

  describe('Handles null progress counts gracefully', () => {
    const mockAuthenticatedSession = {
      user: {
        id: 'user-123',
        email: 'test@example.com',
        organizationId: 'org-123',
      },
    };

    beforeEach(() => {
      mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
      mockedValidateSession.mockReturnValue({
        session: mockAuthenticatedSession,
      });
      mockedValidateUUID.mockReturnValue(null);
    });

    it('should handle null syncedContacts gracefully', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174018';
      // Simulate edge case where database might return null (shouldn't happen per schema, but test defensive handling)
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        syncedContacts: null as any, // Edge case: null value
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      // Endpoint should return the value as-is from database (null in this edge case)
      expect(responseData.syncedContacts).toBeNull();
      expect(responseData.failedContacts).toBe(0);
      expect(responseData.totalContacts).toBe(100);
    });

    it('should handle null failedContacts gracefully', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174019';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        syncedContacts: 50,
        failedContacts: null as any, // Edge case: null value
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01T10:00:00Z'),
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.syncedContacts).toBe(50);
      // Endpoint should return the value as-is from database (null in this edge case)
      expect(responseData.failedContacts).toBeNull();
      expect(responseData.totalContacts).toBe(100);
    });

    it('should handle null totalContacts gracefully', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174020';
      const mockJob = {
        id: validUuid,
        status: 'PENDING' as const,
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: null as any, // Edge case: null value
        tokenExpired: false,
        errors: null,
        startedAt: null,
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.syncedContacts).toBe(0);
      expect(responseData.failedContacts).toBe(0);
      // Endpoint should return the value as-is from database (null in this edge case)
      expect(responseData.totalContacts).toBeNull();
    });

    it('should handle all progress counts as null gracefully', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174021';
      const mockJob = {
        id: validUuid,
        status: 'PENDING' as const,
        syncedContacts: null as any,
        failedContacts: null as any,
        totalContacts: null as any,
        tokenExpired: false,
        errors: null,
        startedAt: null,
        completedAt: null,
        facebookPage: {
          organizationId: 'org-123',
        },
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);

      const request = {
        url: `http://localhost:3000/api/facebook/sync-status/${validUuid}`,
        json: jest.fn(),
      } as any;
      const params = Promise.resolve({ jobId: validUuid });

      const response = await GET(request, { params });
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.status).toBe('PENDING');
      // Endpoint should return null values as-is from database
      expect(responseData.syncedContacts).toBeNull();
      expect(responseData.failedContacts).toBeNull();
      expect(responseData.totalContacts).toBeNull();
      // Verify response structure is still valid
      expect(responseData).toHaveProperty('id');
      expect(responseData).toHaveProperty('status');
      expect(responseData).toHaveProperty('tokenExpired');
    });
  });
});
