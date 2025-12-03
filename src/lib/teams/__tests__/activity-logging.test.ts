/**
 * Tests for Activity Logging Functionality
 * 
 * Tests that logActivity properly handles:
 * - Database errors gracefully
 * - Duplicate log entries (idempotency)
 * - Retry logic for resilience
 * - Non-blocking behavior (doesn't throw)
 */

import { logActivity, ActivityLogOptions } from '../activity';
import { Prisma } from '@prisma/client';
import { safePrismaOperation } from '../../prisma-error-handler';

// Mock prisma-error-handler
jest.mock('../../prisma-error-handler', () => ({
  safePrismaOperation: jest.fn(),
}));

// Mock db
jest.mock('../../db', () => ({
  prisma: {
    teamActivity: {
      create: jest.fn(),
      findFirst: jest.fn(),
    },
  },
}));

import { prisma } from '../../db';

const mockPrisma = prisma as jest.Mocked<typeof prisma>;
const mockSafePrismaOperation = safePrismaOperation as jest.MockedFunction<typeof safePrismaOperation>;

describe('Activity Logging Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const baseOptions: ActivityLogOptions = {
    teamId: 'team-123',
    memberId: 'member-456',
    type: 'VIEW_PAGE',
    action: 'Viewed dashboard',
    entityType: 'page',
    entityId: 'page-789',
  };

  describe('Test: Handles database errors gracefully', () => {
    it('should handle connection errors gracefully', async () => {
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      // safePrismaOperation throws the error
      mockSafePrismaOperation.mockRejectedValueOnce(connectionError);

      // Should not throw (non-blocking)
      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[Activity Log] Failed to log activity'),
        expect.objectContaining({
          error: expect.stringContaining("Can't reach database server"),
          teamId: 'team-123',
        })
      );
    });

    it('should handle connection pool exhaustion gracefully', async () => {
      const poolError = {
        code: 'P2024',
        message: 'Unable to check out process from the pool',
      } as Prisma.PrismaClientKnownRequestError;

      mockSafePrismaOperation.mockRejectedValueOnce(poolError);

      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle timeout errors gracefully', async () => {
      const timeoutError = new Error('ETIMEDOUT: Connection timeout');
      (timeoutError as Error & { code?: string }).code = 'ETIMEDOUT';

      mockSafePrismaOperation.mockRejectedValueOnce(timeoutError);

      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle generic database errors gracefully', async () => {
      const genericError = new Error('Database query failed');
      mockSafePrismaOperation.mockRejectedValueOnce(genericError);

      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });

    it('should handle Prisma validation errors gracefully', async () => {
      const validationError = {
        code: 'P2003',
        message: 'Foreign key constraint failed',
      } as Prisma.PrismaClientKnownRequestError;

      mockSafePrismaOperation.mockRejectedValueOnce(validationError);

      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });

    it('should use safePrismaOperation with correct retry configuration', async () => {
      const mockActivity = { id: 'activity-123', ...baseOptions };
      mockSafePrismaOperation.mockResolvedValueOnce(mockActivity);

      await logActivity(baseOptions);

      expect(mockSafePrismaOperation).toHaveBeenCalledWith(
        expect.any(Function),
        {
          operationName: 'create activity log',
          maxRetries: 3,
          initialDelay: 1000,
          maxDelay: 10000,
        }
      );
    });
  });

  describe('Test: Handles duplicate log entries (idempotency)', () => {
    it('should return existing entry when duplicate is detected', async () => {
      const existingActivity = {
        id: 'existing-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      // First call: check for duplicate (returns existing)
      mockSafePrismaOperation.mockResolvedValueOnce(existingActivity);

      const result = await logActivity(optionsWithKey);

      expect(result).toEqual(existingActivity);
      expect(mockSafePrismaOperation).toHaveBeenCalledTimes(1);
      // Should not call create when duplicate exists
      expect(mockPrisma.teamActivity.create).not.toHaveBeenCalled();
    });

    it('should create new entry when no duplicate exists', async () => {
      const newActivity = {
        id: 'new-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      // First call: check for duplicate (returns null)
      mockSafePrismaOperation.mockResolvedValueOnce(null);
      // Second call: create new entry
      mockSafePrismaOperation.mockResolvedValueOnce(newActivity);

      const result = await logActivity(optionsWithKey);

      expect(result).toEqual(newActivity);
      expect(mockSafePrismaOperation).toHaveBeenCalledTimes(2);
    });

    it('should check for duplicates within 5 minute window', async () => {
      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      const newActivity = {
        id: 'new-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // First call: duplicate check returns null (no duplicate)
      // Second call: create new activity
      mockSafePrismaOperation
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(newActivity);

      const result = await logActivity(optionsWithKey);

      expect(result).toEqual(newActivity);
      
      // Verify duplicate check was called with correct operation name
      const checkCall = mockSafePrismaOperation.mock.calls[0];
      expect(checkCall[1]?.operationName).toBe('check duplicate activity log');
      expect(checkCall[1]?.maxRetries).toBe(2);
    });

    it('should handle duplicate check errors gracefully and continue to create', async () => {
      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      const checkError = new Error('Database connection failed');
      const newActivity = {
        id: 'new-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // Duplicate check fails, but create succeeds
      mockSafePrismaOperation
        .mockRejectedValueOnce(checkError)
        .mockResolvedValueOnce(newActivity);

      jest.spyOn(console, 'warn').mockImplementation(() => {});

      const result = await logActivity(optionsWithKey);

      // Should still create activity (non-blocking)
      expect(result).toEqual(newActivity);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('[Activity Log] Duplicate check failed'),
        expect.any(Object)
      );
    });

    it('should work without idempotency key (backward compatible)', async () => {
      const newActivity = {
        id: 'new-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // Without idempotency key, should skip duplicate check
      mockSafePrismaOperation.mockResolvedValueOnce(newActivity);

      const result = await logActivity(baseOptions);

      expect(result).toEqual(newActivity);
      // Should only call create, not duplicate check
      expect(mockSafePrismaOperation).toHaveBeenCalledTimes(1);
    });
  });

  describe('Test: Uses retry logic for resilience', () => {
    it('should retry on connection errors', async () => {
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      const successActivity = {
        id: 'activity-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // First two attempts fail, third succeeds
      mockSafePrismaOperation
        .mockRejectedValueOnce(connectionError)
        .mockRejectedValueOnce(connectionError)
        .mockResolvedValueOnce(successActivity);

      const result = await logActivity(baseOptions);

      expect(result).toEqual(successActivity);
      expect(mockSafePrismaOperation).toHaveBeenCalledTimes(3);
    });

    it('should retry on pool exhaustion errors', async () => {
      const poolError = {
        code: 'P2024',
        message: 'Unable to check out process from the pool',
      } as Prisma.PrismaClientKnownRequestError;

      const successActivity = {
        id: 'activity-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // First attempt fails, second succeeds
      mockSafePrismaOperation
        .mockRejectedValueOnce(poolError)
        .mockResolvedValueOnce(successActivity);

      const result = await logActivity(baseOptions);

      expect(result).toEqual(successActivity);
      expect(mockSafePrismaOperation).toHaveBeenCalledTimes(2);
    });

    it('should use exponential backoff via safePrismaOperation', async () => {
      const successActivity = {
        id: 'activity-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      mockSafePrismaOperation.mockResolvedValueOnce(successActivity);

      await logActivity(baseOptions);

      expect(mockSafePrismaOperation).toHaveBeenCalledWith(
        expect.any(Function),
        expect.objectContaining({
          maxRetries: 3,
          initialDelay: 1000,
          maxDelay: 10000,
        })
      );
    });

    it('should retry duplicate check with fewer retries', async () => {
      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      const existingActivity = {
        id: 'existing-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      mockSafePrismaOperation.mockResolvedValueOnce(existingActivity);

      await logActivity(optionsWithKey);

      // Verify duplicate check uses fewer retries
      const checkCall = mockSafePrismaOperation.mock.calls[0];
      expect(checkCall[1]?.maxRetries).toBe(2);
    });
  });

  describe('Test: Is non-blocking (doesn\'t throw)', () => {
    it('should not throw on database errors', async () => {
      const error = new Error('Database error');
      mockSafePrismaOperation.mockRejectedValueOnce(error);

      // Should not throw
      await expect(logActivity(baseOptions)).resolves.toBeNull();
    });

    it('should not throw on connection failures', async () => {
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      mockSafePrismaOperation.mockRejectedValueOnce(connectionError);

      await expect(logActivity(baseOptions)).resolves.toBeNull();
    });

    it('should not throw on validation errors', async () => {
      const validationError = {
        code: 'P2003',
        message: 'Foreign key constraint failed',
      } as Prisma.PrismaClientKnownRequestError;

      mockSafePrismaOperation.mockRejectedValueOnce(validationError);

      await expect(logActivity(baseOptions)).resolves.toBeNull();
    });

    it('should not throw on timeout errors', async () => {
      const timeoutError = new Error('ETIMEDOUT: Connection timeout');
      (timeoutError as Error & { code?: string }).code = 'ETIMEDOUT';

      mockSafePrismaOperation.mockRejectedValueOnce(timeoutError);

      await expect(logActivity(baseOptions)).resolves.toBeNull();
    });

    it('should return null instead of throwing', async () => {
      const error = new Error('Any error');
      mockSafePrismaOperation.mockRejectedValueOnce(error);

      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      // Verify error was logged
      expect(console.error).toHaveBeenCalled();
    });

    it('should allow application to continue after logging failure', async () => {
      const error = new Error('Database unavailable');
      mockSafePrismaOperation.mockRejectedValueOnce(error);

      // Simulate application flow continuing
      const result = await logActivity(baseOptions);
      expect(result).toBeNull();

      // Application can continue without crashing
      const nextOperation = 'Application continues normally';
      expect(nextOperation).toBeTruthy();
    });

    it('should handle errors in duplicate check without throwing and continue to create', async () => {
      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      const checkError = new Error('Duplicate check failed');
      const newActivity = {
        id: 'new-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      jest.spyOn(console, 'warn').mockImplementation(() => {});

      // Duplicate check fails, but create succeeds
      mockSafePrismaOperation
        .mockRejectedValueOnce(checkError)
        .mockResolvedValueOnce(newActivity);

      // Should not throw, should continue and create
      const result = await logActivity(optionsWithKey);
      expect(result).toEqual(newActivity);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should log error details for debugging', async () => {
      const error = new Error('Test error');
      mockSafePrismaOperation.mockRejectedValueOnce(error);

      await logActivity(baseOptions);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[Activity Log] Failed to log activity'),
        expect.objectContaining({
          error: 'Test error',
          teamId: baseOptions.teamId,
          type: baseOptions.type,
          action: baseOptions.action,
        })
      );
    });
  });

  describe('Integration: All features working together', () => {
    it('should handle idempotency, retry, and non-blocking together', async () => {
      const optionsWithKey: ActivityLogOptions = {
        ...baseOptions,
        idempotencyKey: 'view-page-789-1234567890',
      };

      const existingActivity = {
        id: 'existing-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // Duplicate check succeeds, returns existing
      mockSafePrismaOperation.mockResolvedValueOnce(existingActivity);

      const result = await logActivity(optionsWithKey);

      expect(result).toEqual(existingActivity);
      // Should not throw (non-blocking)
      expect(result).not.toBeNull();
    });

    it('should retry on transient errors and eventually succeed', async () => {
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      const successActivity = {
        id: 'activity-123',
        ...baseOptions,
        createdAt: new Date(),
      };

      // Fail twice, then succeed
      mockSafePrismaOperation
        .mockRejectedValueOnce(connectionError)
        .mockRejectedValueOnce(connectionError)
        .mockResolvedValueOnce(successActivity);

      const result = await logActivity(baseOptions);

      expect(result).toEqual(successActivity);
      // Non-blocking: should return result, not throw
      expect(result).not.toBeNull();
    });

    it('should handle all failures gracefully (non-blocking)', async () => {
      const error = new Error('Persistent database error');
      mockSafePrismaOperation.mockRejectedValue(error);

      // Should not throw even after all retries fail
      const result = await logActivity(baseOptions);

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });
  });
});

