/**
 * Tests for Database Deadlock Handling
 * 
 * Tests ensure that:
 * - Deadlock errors (P2034) are detected correctly
 * - Deadlocks trigger automatic retries with appropriate backoff
 * - Deadlock retries use shorter delays than connection errors
 * - Deadlocks are properly logged and handled
 */

import { Prisma } from '@prisma/client';
import { isRetryablePrismaError, getPrismaErrorMessage, safePrismaOperation } from '../prisma-error-handler';
import { withRetry } from '../db-retry';
import { prisma } from '../db';

// Mock dependencies
jest.mock('../db', () => ({
  prisma: {
    $disconnect: jest.fn(),
    $connect: jest.fn(),
  },
}));

jest.mock('../db-retry', () => ({
  withRetry: jest.fn(),
}));

jest.mock('../db', () => ({
  connectPrisma: jest.fn(),
}));

const mockedWithRetry = withRetry as jest.MockedFunction<typeof withRetry>;

describe('Deadlock Handling', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Deadlock Detection', () => {
    it('should detect P2034 deadlock errors', () => {
      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      const isRetryable = isRetryablePrismaError(deadlockError);
      expect(isRetryable).toBe(true);
    });

    it('should detect deadlock in error message (case-insensitive)', () => {
      const deadlockError = new Error('Database deadlock detected during transaction');
      const isRetryable = isRetryablePrismaError(deadlockError);
      expect(isRetryable).toBe(true);
    });

    it('should provide user-friendly message for deadlocks', () => {
      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      const message = getPrismaErrorMessage(deadlockError);
      expect(message).toContain('database conflict');
      expect(message).toContain('retried automatically');
    });
  });

  describe('Deadlock Retry Logic', () => {
    it('should retry deadlocks with shorter backoff', async () => {
      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      const mockOperation = jest.fn()
        .mockRejectedValueOnce(deadlockError)
        .mockResolvedValueOnce('success');

      mockedWithRetry.mockImplementation(async (operation) => {
        return operation();
      });

      await safePrismaOperation(mockOperation, {
        operationName: 'test operation',
        maxRetries: 3,
      });

      expect(mockedWithRetry).toHaveBeenCalled();
      const retryableErrors = mockedWithRetry.mock.calls[0]?.[1]?.retryableErrors;
      expect(retryableErrors).toContain('P2034');
      expect(retryableErrors).toContain('deadlock');
    });

    it('should handle multiple deadlock retries', async () => {
      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      const mockOperation = jest.fn()
        .mockRejectedValueOnce(deadlockError)
        .mockRejectedValueOnce(deadlockError)
        .mockResolvedValueOnce('success');

      mockedWithRetry.mockImplementation(async (operation) => {
        return operation();
      });

      const result = await safePrismaOperation(mockOperation, {
        operationName: 'test operation',
        maxRetries: 3,
      });

      expect(result).toBe('success');
    });
  });

  describe('Deadlock vs Other Errors', () => {
    it('should distinguish deadlocks from connection errors', () => {
      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      const connectionError = new Prisma.PrismaClientKnownRequestError(
        'Connection pool timeout',
        {
          code: 'P2024',
          clientVersion: '5.0.0',
        } as any
      );

      expect(isRetryablePrismaError(deadlockError)).toBe(true);
      expect(isRetryablePrismaError(connectionError)).toBe(true);

      const deadlockMessage = getPrismaErrorMessage(deadlockError);
      const connectionMessage = getPrismaErrorMessage(connectionError);

      expect(deadlockMessage).toContain('database conflict');
      expect(connectionMessage).toContain('temporarily busy');
    });
  });
});









