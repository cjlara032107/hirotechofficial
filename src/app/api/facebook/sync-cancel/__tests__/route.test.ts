/**
 * API Route Tests for /api/facebook/sync-cancel
 * 
 * Tests for:
 * - Returns 401 for unauthenticated requests
 * - Returns 400 for missing jobId
 * - Returns 400 for invalid jobId format
 * - Returns 404 when job doesn't exist
 * - Returns 403 when user doesn't own job's page
 * - Returns 400 when trying to cancel already completed/failed/cancelled jobs
 * - Returns 200 and cancels job successfully
 * - Handles concurrent cancellation attempts (idempotent)
 */

import { NextRequest, NextResponse } from 'next/server';
import { POST } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateUUID } from '@/lib/api/validate-uuid';

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
    syncJob: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    facebookPage: {
      findFirst: jest.fn(),
    },
  },
}));

jest.mock('@/lib/api/validate-uuid', () => ({
  validateUUID: jest.fn(),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedValidateUUID = validateUUID as jest.MockedFunction<typeof validateUUID>;

describe('API Route: /api/facebook/sync-cancel', () => {
  const mockAuthenticatedSession = {
    user: {
      id: 'user-123',
      email: 'test@example.com',
      organizationId: 'org-123',
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue(mockAuthenticatedSession as any);
    mockedValidateUUID.mockReturnValue(null); // Default: valid UUID
  });

  describe('Returns 401 for unauthenticated requests', () => {
    it('should return 401 when user is not authenticated', async () => {
      mockedAuth.mockResolvedValue(null);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: '123e4567-e89b-12d3-a456-426614174000' }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(401);
      expect(responseData).toEqual({ error: 'Unauthorized' });
      expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
    });

    it('should return 401 when session exists but user is missing', async () => {
      mockedAuth.mockResolvedValue({} as any);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: '123e4567-e89b-12d3-a456-426614174000' }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(401);
      expect(responseData).toEqual({ error: 'Unauthorized' });
      expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
    });
  });

  describe('Returns 400 for missing jobId', () => {
    it('should return 400 when jobId is missing', async () => {
      const request = {
        json: jest.fn().mockResolvedValue({}),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData).toEqual({ error: 'Missing jobId' });
      expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
    });

    it('should return 400 when jobId is null', async () => {
      const request = {
        json: jest.fn().mockResolvedValue({ jobId: null }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData).toEqual({ error: 'Missing jobId' });
    });
  });

  describe('Validates jobId format', () => {
    it('should return 400 for invalid UUID format', async () => {
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
        '', // Empty string
      ];

      for (const invalidJobId of invalidJobIds) {
        const request = {
          json: jest.fn().mockResolvedValue({ jobId: invalidJobId }),
        } as any;

        const response = await POST(request);
        const responseData = await response.json();

        expect(response.status).toBe(400);
        expect(responseData.error).toContain('Invalid');
        expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
      }
    });

    it('should return 400 for non-string jobId', async () => {
      const request = {
        json: jest.fn().mockResolvedValue({ jobId: 12345 }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData).toEqual({ error: 'Invalid job ID format' });
      expect(mockedPrisma.syncJob.findUnique).not.toHaveBeenCalled();
    });

    it('should return 400 for empty string jobId', async () => {
      const request = {
        json: jest.fn().mockResolvedValue({ jobId: '' }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData).toEqual({ error: 'Invalid job ID format' });
    });

    it('should accept valid UUID format', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      mockedValidateUUID.mockReturnValue(null);

      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(mockedValidateUUID).toHaveBeenCalledWith(validUuid);
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledWith({
        where: { id: validUuid },
        data: {
          status: 'CANCELLED',
          completedAt: expect.any(Date),
        },
      });
    });

    it('should trim whitespace from jobId', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const jobIdWithWhitespace = `  ${validUuid}  `;
      mockedValidateUUID.mockReturnValue(null);

      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: jobIdWithWhitespace }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(mockedValidateUUID).toHaveBeenCalledWith(validUuid); // Should be called with trimmed value
      expect(mockedPrisma.syncJob.findUnique).toHaveBeenCalledWith({
        where: { id: validUuid },
      });
    });
  });

  describe('Returns 404 when job doesn\'t exist', () => {
    it('should return 404 when job does not exist', async () => {
      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(null);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: '123e4567-e89b-12d3-a456-426614174000' }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(404);
      expect(responseData).toEqual({ error: 'Sync job not found' });
    });
  });

  describe('Returns 403 when user doesn\'t own job\'s page', () => {
    it('should return 403 when job belongs to a different organization', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 10,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(null); // Page not found for user's org

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(403);
      expect(responseData).toEqual({ error: 'Unauthorized' });
      expect(mockedPrisma.syncJob.update).not.toHaveBeenCalled();
    });
  });

  describe('Returns 400 when trying to cancel already completed/failed/cancelled jobs', () => {
    it('should return 400 when trying to cancel a COMPLETED job', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'COMPLETED' as const,
        facebookPageId: 'page-123',
        syncedContacts: 100,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: new Date('2024-01-01'),
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData.error).toContain('Cannot cancel job with status: COMPLETED');
      expect(mockedPrisma.syncJob.update).not.toHaveBeenCalled();
    });

    it('should return 400 when trying to cancel a FAILED job', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'FAILED' as const,
        facebookPageId: 'page-123',
        syncedContacts: 0,
        failedContacts: 100,
        totalContacts: 100,
        tokenExpired: false,
        errors: [{ message: 'Error' }],
        startedAt: new Date('2024-01-01'),
        completedAt: new Date('2024-01-01'),
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData.error).toContain('Cannot cancel job with status: FAILED');
    });

    it('should return 400 when trying to cancel a CANCELLED job', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'CANCELLED' as const,
        facebookPageId: 'page-123',
        syncedContacts: 50,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: new Date('2024-01-01'),
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(400);
      expect(responseData.error).toContain('Cannot cancel job with status: CANCELLED');
    });
  });

  describe('Returns 200 and cancels job successfully', () => {
    it('should cancel a PENDING job successfully', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'PENDING' as const,
        facebookPageId: 'page-123',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: null,
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(responseData.job.status).toBe('CANCELLED');
      expect(responseData.job.completedAt).toBeDefined();
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledWith({
        where: { id: validUuid },
        data: {
          status: 'CANCELLED',
          completedAt: expect.any(Date),
        },
      });
    });

    it('should cancel an IN_PROGRESS job successfully', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 50,
        failedContacts: 2,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      expect(response.status).toBe(200);
      expect(responseData.success).toBe(true);
      expect(responseData.job.status).toBe('CANCELLED');
      expect(responseData.job.completedAt).toBeDefined();
    });
  });

  describe('Handles concurrent cancellation attempts', () => {
    it('should handle multiple concurrent cancellation requests idempotently', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 50,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      // Simulate concurrent behavior: first few reads return IN_PROGRESS,
      // then after first update, subsequent reads return CANCELLED
      let findUniqueCallCount = 0;
      let updateCallCount = 0;
      
      mockedPrisma.syncJob.findUnique = jest.fn().mockImplementation(() => {
        findUniqueCallCount++;
        // First 3 calls return IN_PROGRESS (simulating concurrent reads before any update)
        // After first update completes, subsequent reads return CANCELLED
        if (findUniqueCallCount <= 3 || updateCallCount === 0) {
          return Promise.resolve(mockJob);
        }
        return Promise.resolve(mockCancelledJob);
      });

      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      
      mockedPrisma.syncJob.update = jest.fn().mockImplementation(() => {
        updateCallCount++;
        return Promise.resolve(mockCancelledJob);
      });

      // Simulate 5 concurrent cancellation requests
      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const concurrentRequests = Array(5).fill(null).map(() => POST(request));
      const responses = await Promise.all(concurrentRequests);

      // All requests should complete successfully
      expect(responses).toHaveLength(5);
      
      // Parse all responses
      const responseDataArray = await Promise.all(
        responses.map(r => r.json())
      );

      // At least one request should succeed (200)
      const successCount = responses.filter(r => r.status === 200).length;
      expect(successCount).toBeGreaterThan(0);
      
      // Remaining requests may return 400 if they read CANCELLED status
      const errorCount = responses.filter(r => r.status === 400).length;
      
      // Verify successful requests
      responses.forEach((response, index) => {
        if (response.status === 200) {
          expect(responseDataArray[index].success).toBe(true);
          expect(responseDataArray[index].job.status).toBe('CANCELLED');
        } else if (response.status === 400) {
          expect(responseDataArray[index].error).toContain('Cannot cancel job with status: CANCELLED');
        }
      });

      // Update should be called at least once (first successful cancellation)
      expect(mockedPrisma.syncJob.update).toHaveBeenCalled();
      expect(updateCallCount).toBeGreaterThan(0);
    });

    it('should handle race condition where job is cancelled between findUnique and update', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 50,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      // Simulate race: first findUnique returns IN_PROGRESS, but update fails because another request already cancelled
      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      
      // Update throws error simulating unique constraint or status conflict
      mockedPrisma.syncJob.update = jest.fn().mockRejectedValue(
        new Error('Job status conflict')
      );

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      const response = await POST(request);
      const responseData = await response.json();

      // Should handle error gracefully
      expect(response.status).toBe(500);
      expect(responseData.error).toBeDefined();
    });

    it('should handle concurrent requests where all read IN_PROGRESS before any update', async () => {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      const mockJob = {
        id: validUuid,
        status: 'IN_PROGRESS' as const,
        facebookPageId: 'page-123',
        syncedContacts: 50,
        failedContacts: 0,
        totalContacts: 100,
        tokenExpired: false,
        errors: null,
        startedAt: new Date('2024-01-01'),
        completedAt: null,
      };

      const mockPage = {
        id: 'page-123',
        organizationId: 'org-123',
      };

      const mockCancelledJob = {
        ...mockJob,
        status: 'CANCELLED' as const,
        completedAt: new Date(),
      };

      // All concurrent requests read IN_PROGRESS initially
      mockedPrisma.syncJob.findUnique = jest.fn().mockResolvedValue(mockJob);
      mockedPrisma.facebookPage.findFirst = jest.fn().mockResolvedValue(mockPage);
      mockedPrisma.syncJob.update = jest.fn().mockResolvedValue(mockCancelledJob);

      const request = {
        json: jest.fn().mockResolvedValue({ jobId: validUuid }),
      } as any;

      // Simulate 3 concurrent requests that all read IN_PROGRESS
      const concurrentRequests = Array(3).fill(null).map(() => POST(request));
      const responses = await Promise.all(concurrentRequests);

      // All should attempt to update
      expect(mockedPrisma.syncJob.update).toHaveBeenCalledTimes(3);
      
      // All should succeed (database handles the race condition)
      const responseDataPromises = responses.map(r => r.json());
      const responseDataArray = await Promise.all(responseDataPromises);
      
      for (let i = 0; i < responses.length; i++) {
        expect([200, 500]).toContain(responses[i].status);
        // If successful, should return cancelled job
        if (responses[i].status === 200) {
          expect(responseDataArray[i].success).toBe(true);
          expect(responseDataArray[i].job.status).toBe('CANCELLED');
        }
      }
    });
  });
});

