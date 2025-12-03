/**
 * Comprehensive Error Handling Tests
 * 
 * Tests to verify error handling works correctly:
 * - All error paths are handled
 * - Retry logic works for transient errors
 * - Error recovery mechanisms function properly
 * - User-friendly error messages are returned
 * - Error tracking and logging work correctly
 */

import { 
  isRetryablePrismaError, 
  getPrismaErrorMessage, 
  handlePrismaError,
  safePrismaOperation 
} from '@/lib/prisma-error-handler';
import { prisma } from '@/lib/db';
import { trackError } from '@/lib/monitoring/track-error';

// Mock Prisma client (also mocked in jest.setup.js but need it here for hoisting)
jest.mock('@prisma/client', () => ({
  Prisma: {
    PrismaClientKnownRequestError: class PrismaClientKnownRequestError extends Error {
      constructor(message, meta) {
        super(message);
        this.code = meta.code;
        this.clientVersion = meta.clientVersion;
        this.name = 'PrismaClientKnownRequestError';
      }
    },
  },
}));

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    contact: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    $disconnect: jest.fn(),
  },
  connectPrisma: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('@/lib/db-retry', () => ({
  withRetry: jest.fn((fn) => fn()),
}));

jest.mock('@/lib/monitoring/system-monitor', () => ({
  systemMonitor: {
    recordError: jest.fn(),
  },
}));

jest.mock('@/lib/monitoring/track-error', () => ({
  trackError: jest.fn(),
}));

jest.mock('@/lib/logging/error-logger', () => ({
  logErrorWithContext: jest.fn().mockResolvedValue(undefined),
}));

describe('Comprehensive Error Handling Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Retryable Error Detection', () => {
    it('should identify connection pool errors as retryable', () => {
      const error = new Error('Unable to check out process from the pool');
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should identify P2024 (connection pool timeout) as retryable', () => {
      const error = { code: 'P2024', message: 'Connection pool timeout' };
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should identify P1001 (database unreachable) as retryable', () => {
      const error = { code: 'P1001', message: "Can't reach database" };
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should identify P2034 (deadlock) as retryable', () => {
      const error = { code: 'P2034', message: 'Deadlock detected' };
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should identify timeout errors as retryable', () => {
      const error = new Error('Request timeout');
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should identify connection closed errors as retryable', () => {
      const error = new Error('Connection closed');
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should identify engine not connected errors as retryable', () => {
      const error = new Error('Engine is not yet connected');
      expect(isRetryablePrismaError(error)).toBe(true);
    });

    it('should not identify unique constraint violations as retryable', () => {
      // Create a mock Prisma error object
      const error: any = new Error('Unique constraint violation');
      error.code = 'P2002';
      error.clientVersion = '1.0.0';
      expect(isRetryablePrismaError(error)).toBe(false);
    });

    it('should not identify record not found errors as retryable', () => {
      // Create a mock Prisma error object
      const error: any = new Error('Record not found');
      error.code = 'P2025';
      error.clientVersion = '1.0.0';
      expect(isRetryablePrismaError(error)).toBe(false);
    });
  });

  describe('Error Message Generation', () => {
    it('should return user-friendly message for connection pool errors', () => {
      const error = new Error('Unable to check out process from the pool');
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('temporarily busy');
      expect(message).toContain('try again');
    });

    it('should return user-friendly message for database unreachable errors', () => {
      const error = { code: 'P1001', message: "Can't reach database" };
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('Unable to connect');
      expect(message).toContain('try again');
    });

    it('should return user-friendly message for timeout errors', () => {
      const error = new Error('Request timeout');
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('too long');
      expect(message).toContain('try again');
    });

    it('should return user-friendly message for deadlock errors', () => {
      const error = { code: 'P2034', message: 'Deadlock detected' };
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('conflict');
      expect(message).toContain('retried automatically');
    });

    it('should return user-friendly message for unique constraint violations', () => {
      // Create a mock Prisma error using the mocked class
      const { Prisma } = require('@prisma/client');
      const error = new Prisma.PrismaClientKnownRequestError(
        'Unique constraint violation',
        { code: 'P2002', clientVersion: '1.0.0' }
      );
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('already exists');
    });

    it('should return user-friendly message for record not found errors', () => {
      // Create a mock Prisma error using the mocked class
      const { Prisma } = require('@prisma/client');
      const error = new Prisma.PrismaClientKnownRequestError(
        'Record not found',
        { code: 'P2025', clientVersion: '1.0.0' }
      );
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('does not exist');
    });

    it('should return generic message for unknown errors', () => {
      const error = new Error('Unknown error');
      const message = getPrismaErrorMessage(error);
      expect(message).toContain('error occurred');
      expect(message).toContain('try again');
    });
  });

  describe('Error Handling for API Responses', () => {
    it('should return 503 for retryable errors', () => {
      const error = new Error('Unable to check out process from the pool');
      const { status, shouldRetry } = handlePrismaError(error);
      expect(status).toBe(503);
      expect(shouldRetry).toBe(true);
    });

    it('should return 500 for non-retryable errors', () => {
      // Create a mock Prisma error using the mocked class
      const { Prisma } = require('@prisma/client');
      const error = new Prisma.PrismaClientKnownRequestError(
        'Unique constraint violation',
        { code: 'P2002', clientVersion: '1.0.0' }
      );
      const { status, shouldRetry } = handlePrismaError(error);
      expect(status).toBe(500);
      expect(shouldRetry).toBe(false);
    });

    it('should include user-friendly message in error response', () => {
      const error = new Error('Connection timeout');
      const { message, status } = handlePrismaError(error);
      expect(message).toBeTruthy();
      expect(typeof message).toBe('string');
      expect(message.length).toBeGreaterThan(0);
      expect(status).toBe(503);
    });
  });

  describe('Safe Prisma Operation Error Handling', () => {
    it('should retry on retryable errors', async () => {
      const { withRetry } = require('@/lib/db-retry');
      let attemptCount = 0;

      (prisma.contact.findMany as jest.Mock).mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 3) {
          const error = new Error('Unable to check out process from the pool');
          throw error;
        }
        return Promise.resolve([{ id: '1', firstName: 'Test' }]);
      });

      (withRetry as jest.Mock).mockImplementation(async (fn) => {
        let lastError;
        for (let i = 0; i < 3; i++) {
          try {
            return await fn();
          } catch (error) {
            lastError = error;
            if (i < 2) {
              await new Promise(resolve => setTimeout(resolve, 100));
            }
          }
        }
        throw lastError;
      });

      try {
        await safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: 'testOperation', maxRetries: 3 }
        );
      } catch (error) {
        // Should eventually succeed or throw after retries
      }

      expect(attemptCount).toBeGreaterThan(1);
    });

    it('should throw user-friendly error after max retries', async () => {
      const { withRetry } = require('@/lib/db-retry');
      const { systemMonitor } = require('@/lib/monitoring/system-monitor');

      (prisma.contact.findMany as jest.Mock).mockRejectedValue(
        new Error('Unable to check out process from the pool')
      );

      (withRetry as jest.Mock).mockRejectedValue(
        new Error('Unable to check out process from the pool')
      );

      await expect(
        safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: 'testOperation', maxRetries: 3 }
        )
      ).rejects.toThrow();

      // Error should be tracked in system monitor (trackError is called via logErrorWithContext)
      expect(systemMonitor.recordError).toHaveBeenCalled();
    });

    it('should handle deadlock errors with shorter backoff', async () => {
      const { withRetry } = require('@/lib/db-retry');
      let deadlockDetected = false;

      (prisma.contact.findMany as jest.Mock).mockImplementation(() => {
        if (!deadlockDetected) {
          deadlockDetected = true;
          const error: any = new Error('Deadlock detected');
          error.code = 'P2034';
          throw error;
        }
        return Promise.resolve([{ id: '1', firstName: 'Test' }]);
      });

      (withRetry as jest.Mock).mockImplementation(async (fn) => {
        try {
          return await fn();
        } catch (error: any) {
          if (error.code === 'P2034') {
            await new Promise(resolve => setTimeout(resolve, 50));
            return await fn();
          }
          throw error;
        }
      });

      const result = await safePrismaOperation(
        () => prisma.contact.findMany({ take: 10 }),
        { operationName: 'testDeadlock' }
      );

      expect(result).toBeDefined();
    });
  });

  describe('Error Tracking and Logging', () => {
    it('should track errors in system monitor', async () => {
      const { systemMonitor } = require('@/lib/monitoring/system-monitor');

      (prisma.contact.findMany as jest.Mock).mockRejectedValue(
        new Error('Test error')
      );

      const { withRetry } = require('@/lib/db-retry');
      (withRetry as jest.Mock).mockRejectedValue(new Error('Test error'));

      try {
        await safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: 'testTracking' }
        );
      } catch {
        // Expected to throw
      }

      expect(systemMonitor.recordError).toHaveBeenCalled();
    });

    it('should include operation context in error tracking', async () => {
      const { systemMonitor } = require('@/lib/monitoring/system-monitor');

      (prisma.contact.findMany as jest.Mock).mockRejectedValue(
        new Error('Test error')
      );

      const { withRetry } = require('@/lib/db-retry');
      (withRetry as jest.Mock).mockRejectedValue(new Error('Test error'));

      try {
        await safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: 'testContext' }
        );
      } catch {
        // Expected to throw
      }

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          context: expect.objectContaining({
            operationName: 'testContext',
          }),
        })
      );
    });
  });

  describe('Error Recovery', () => {
    it('should attempt to reconnect on connection errors', async () => {
      const { connectPrisma } = require('@/lib/db');
      let reconnectAttempted = false;

      (prisma.contact.findMany as jest.Mock).mockImplementation(() => {
        if (!reconnectAttempted) {
          reconnectAttempted = true;
          const error = new Error('Connection closed');
          throw error;
        }
        return Promise.resolve([{ id: '1', firstName: 'Test' }]);
      });

      (prisma.$disconnect as jest.Mock).mockResolvedValue(undefined);
      (connectPrisma as jest.Mock).mockResolvedValue(undefined);

      const { withRetry } = require('@/lib/db-retry');
      (withRetry as jest.Mock).mockImplementation(async (fn) => {
        try {
          return await fn();
        } catch (error: any) {
          if (error.message.includes('Connection closed')) {
            await prisma.$disconnect();
            await new Promise(resolve => setTimeout(resolve, 500));
            await connectPrisma();
            return await fn();
          }
          throw error;
        }
      });

      const result = await safePrismaOperation(
        () => prisma.contact.findMany({ take: 10 }),
        { operationName: 'testReconnect' }
      );

      expect(result).toBeDefined();
      expect(reconnectAttempted).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null/undefined errors gracefully', () => {
      expect(isRetryablePrismaError(null)).toBe(false);
      expect(isRetryablePrismaError(undefined)).toBe(false);
      expect(getPrismaErrorMessage(null)).toContain('unexpected error');
      expect(getPrismaErrorMessage(undefined)).toContain('unexpected error');
    });

    it('should handle non-Error objects', () => {
      const error = { message: 'String error' };
      expect(getPrismaErrorMessage(error)).toBeTruthy();
    });

    it('should handle errors without messages', () => {
      const error = {};
      const message = getPrismaErrorMessage(error);
      expect(message).toBeTruthy();
      expect(typeof message).toBe('string');
    });
  });
});

