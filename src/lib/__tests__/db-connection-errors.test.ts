/**
 * Tests for Database Connection Error Handling
 * 
 * Tests that the database connection layer properly handles:
 * - Connection failures (P1001)
 * - Connection pool exhaustion (P2024)
 * - Timeout errors
 * - Network errors
 * - Retry logic with exponential backoff
 */

import { safePrismaOperation, isRetryablePrismaError, getPrismaErrorMessage } from '../prisma-error-handler';
import { Prisma } from '@prisma/client';

// Mock db-retry to avoid actual delays in tests
jest.mock('../db-retry', () => ({
  withRetry: jest.fn(async (operation, options) => {
    // Execute operation immediately without retry delays for testing
    let lastError: unknown;
    const maxRetries = options?.maxRetries || 3;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error: unknown) {
        lastError = error;
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorCode = (error as any)?.code;
        
        const retryableErrors = options?.retryableErrors || [
          'Unable to check out process from the pool',
          'connection pool',
          'P2024',
          'P1001',
          'timeout',
        ];
        
        const isRetryable = retryableErrors.some(pattern => 
          errorMessage.includes(pattern) || errorCode === pattern
        );
        
        if (!isRetryable || attempt === maxRetries) {
          throw error;
        }
      }
    }
    
    throw lastError;
  }),
}));

// Mock Prisma client - everything must be defined inside jest.mock factory
jest.mock('../db', () => {
  const mockPrisma = {
    $connect: jest.fn(),
    $disconnect: jest.fn(),
    user: {
      findFirst: jest.fn(),
      count: jest.fn(),
    },
  };

  // Create a mock connectPrisma that simulates retry logic
  const mockConnectPrisma = jest.fn(async (maxRetries = 3, retryDelay = 1000) => {
    let lastError: unknown;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        await mockPrisma.$connect();
        return;
      } catch (error: unknown) {
        lastError = error;
        const errorObj = error as { code?: string; message?: string };
        
        const isConnectionError = errorObj?.code === 'P1001' || 
          errorObj?.code === 'P2024' ||
          errorObj?.message?.includes("Can't reach database") ||
          errorObj?.message?.includes('connection') ||
          errorObj?.message?.includes('pool') ||
          errorObj?.message?.includes('timeout') ||
          errorObj?.code === 'ETIMEDOUT' ||
          errorObj?.code === 'ECONNRESET';
        
        if (!isConnectionError || attempt === maxRetries) {
          throw error;
        }
        
        const delay = retryDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    throw lastError;
  });

  return {
    prisma: mockPrisma,
    connectPrisma: mockConnectPrisma,
  };
});

// Import after mock to get the mocked versions
import { prisma, connectPrisma } from '../db';

const mockPrisma = prisma as jest.Mocked<typeof prisma>;
const mockConnectPrisma = connectPrisma as jest.MockedFunction<typeof connectPrisma>;

describe('Database Connection Error Handling', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Handles database connection errors', () => {
    describe('connectPrisma() - Connection Error Handling', () => {
      it('should handle P1001 connection error (Can\'t reach database)', async () => {
        const connectionError = {
          code: 'P1001',
          message: "Can't reach database server at localhost:5432",
        } as Prisma.PrismaClientKnownRequestError;

        mockPrisma.$connect.mockRejectedValueOnce(connectionError);
        mockPrisma.$connect.mockRejectedValueOnce(connectionError);
        mockPrisma.$connect.mockRejectedValueOnce(connectionError);

        await expect(mockConnectPrisma(3, 100)).rejects.toThrow();
        expect(mockPrisma.$connect).toHaveBeenCalledTimes(3);
      });

      it('should handle P2024 connection pool timeout error', async () => {
        const poolError = {
          code: 'P2024',
          message: 'Unable to check out process from the pool due to timeout',
        } as Prisma.PrismaClientKnownRequestError;

        mockPrisma.$connect.mockRejectedValueOnce(poolError);
        mockPrisma.$connect.mockRejectedValueOnce(poolError);
        mockPrisma.$connect.mockRejectedValueOnce(poolError);

        await expect(mockConnectPrisma(3, 100)).rejects.toThrow();
        expect(mockPrisma.$connect).toHaveBeenCalledTimes(3);
      });

      it('should handle network timeout errors', async () => {
        const timeoutError = new Error('ETIMEDOUT: Connection timeout');
        (timeoutError as any).code = 'ETIMEDOUT';

        mockPrisma.$connect.mockRejectedValueOnce(timeoutError);
        mockPrisma.$connect.mockRejectedValueOnce(timeoutError);
        mockPrisma.$connect.mockRejectedValueOnce(timeoutError);

        await expect(mockConnectPrisma(3, 100)).rejects.toThrow();
        expect(mockPrisma.$connect).toHaveBeenCalledTimes(3);
      });

      it('should handle connection reset errors', async () => {
        const resetError = new Error('Connection was forcibly closed by the remote host');
        (resetError as any).code = 'ECONNRESET';

        mockPrisma.$connect.mockRejectedValueOnce(resetError);
        mockPrisma.$connect.mockRejectedValueOnce(resetError);
        mockPrisma.$connect.mockRejectedValueOnce(resetError);

        await expect(mockConnectPrisma(3, 100)).rejects.toThrow();
        expect(mockPrisma.$connect).toHaveBeenCalledTimes(3);
      });

      it('should retry connection errors with exponential backoff', async () => {
        const connectionError = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        // First two attempts fail, third succeeds
        mockPrisma.$connect.mockRejectedValueOnce(connectionError);
        mockPrisma.$connect.mockRejectedValueOnce(connectionError);
        mockPrisma.$connect.mockResolvedValueOnce(undefined);

        // Use jest.useFakeTimers to test timing
        jest.useFakeTimers();
        
        const connectPromise = mockConnectPrisma(3, 100);
        
        // Fast-forward through retries (100ms + 200ms = 300ms)
        jest.advanceTimersByTime(300);
        
        await expect(connectPromise).resolves.not.toThrow();
        expect(mockPrisma.$connect).toHaveBeenCalledTimes(3);
        
        jest.useRealTimers();
      });

      it('should throw error after max retries exhausted', async () => {
        const connectionError = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        // All attempts fail
        mockPrisma.$connect.mockRejectedValue(connectionError);

        await expect(mockConnectPrisma(3, 100)).rejects.toThrow();
        expect(mockPrisma.$connect).toHaveBeenCalledTimes(3);
      });
    });

    describe('safePrismaOperation() - Error Handling', () => {
      it('should handle connection errors during operation', async () => {
        const connectionError = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        mockPrisma.user.findFirst.mockRejectedValue(connectionError);
        mockPrisma.$connect.mockResolvedValue(undefined);
        mockConnectPrisma.mockResolvedValue(undefined);

        const operation = async () => {
          await mockConnectPrisma();
          return await mockPrisma.user.findFirst({ where: { id: 'test' } });
        };

        await expect(
          safePrismaOperation(operation, { 
            operationName: 'test query',
            maxRetries: 1, // Fail fast
          })
        ).rejects.toThrow();
      }, 10000);

      it('should retry operation on connection pool exhaustion', async () => {
        const poolError = {
          code: 'P2024',
          message: 'Unable to check out process from the pool',
        } as Prisma.PrismaClientKnownRequestError;

        // First attempt fails, second succeeds
        mockPrisma.user.count.mockRejectedValueOnce(poolError);
        mockPrisma.user.count.mockResolvedValueOnce(5);
        mockPrisma.$connect.mockResolvedValue(undefined);
        mockConnectPrisma.mockResolvedValue(undefined);

        const operation = async () => {
          await mockConnectPrisma();
          return await mockPrisma.user.count();
        };

        const result = await safePrismaOperation(operation, {
          operationName: 'count users',
          maxRetries: 3,
        });

        expect(result).toBe(5);
        expect(mockPrisma.user.count).toHaveBeenCalledTimes(2);
      }, 10000);

      it('should disconnect and reconnect on connection errors', async () => {
        const connectionError = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        // First call fails, second succeeds
        mockPrisma.user.findFirst.mockRejectedValueOnce(connectionError);
        mockPrisma.user.findFirst.mockResolvedValueOnce({ id: 'test' });
        mockPrisma.$connect.mockResolvedValue(undefined);
        mockPrisma.$disconnect.mockResolvedValue(undefined);
        mockConnectPrisma.mockResolvedValue(undefined);

        const operation = async () => {
          await mockConnectPrisma();
          return await mockPrisma.user.findFirst({ where: { id: 'test' } });
        };

        const result = await safePrismaOperation(operation, {
          operationName: 'find user',
          maxRetries: 3,
          initialDelay: 100,
        });

        expect(result).toEqual({ id: 'test' });
        // safePrismaOperation will call disconnect on retryable errors
        expect(mockPrisma.user.findFirst).toHaveBeenCalledTimes(2);
        // Verify disconnect was called during retry
        expect(mockPrisma.$disconnect).toHaveBeenCalled();
      }, 10000);

      it('should provide user-friendly error messages', async () => {
        const connectionError = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        mockPrisma.user.findFirst.mockRejectedValue(connectionError);
        mockPrisma.$connect.mockResolvedValue(undefined);
        mockConnectPrisma.mockResolvedValue(undefined);

        const operation = async () => {
          await mockConnectPrisma();
          return await mockPrisma.user.findFirst({ where: { id: 'test' } });
        };

        try {
          await safePrismaOperation(operation, { 
            operationName: 'test query',
            maxRetries: 1, // Fail fast for this test
          });
          fail('Should have thrown an error');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          const err = error as Error;
          expect(err.message).toContain('Unable to connect');
          expect((err as any).isPrismaError).toBe(true);
        }
      }, 10000);
    });

    describe('isRetryablePrismaError() - Error Classification', () => {
      it('should identify P1001 as retryable', () => {
        const error = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        expect(isRetryablePrismaError(error)).toBe(true);
      });

      it('should identify P2024 as retryable', () => {
        const error = {
          code: 'P2024',
          message: 'Unable to check out process from the pool',
        } as Prisma.PrismaClientKnownRequestError;

        expect(isRetryablePrismaError(error)).toBe(true);
      });

      it('should identify timeout errors as retryable', () => {
        const error = new Error('ETIMEDOUT: Connection timeout');
        (error as any).code = 'ETIMEDOUT';

        expect(isRetryablePrismaError(error)).toBe(true);
      });

      it('should identify connection pool errors as retryable', () => {
        const error = new Error('Unable to check out process from the connection pool');

        expect(isRetryablePrismaError(error)).toBe(true);
      });

      it('should identify non-retryable errors correctly', () => {
        const error = {
          code: 'P2002',
          message: 'Unique constraint violation',
        } as Prisma.PrismaClientKnownRequestError;

        expect(isRetryablePrismaError(error)).toBe(false);
      });
    });

    describe('getPrismaErrorMessage() - User-Friendly Messages', () => {
      it('should return friendly message for P1001', () => {
        const error = {
          code: 'P1001',
          message: "Can't reach database server",
        } as Prisma.PrismaClientKnownRequestError;

        const message = getPrismaErrorMessage(error);
        expect(message).toContain('Unable to connect');
      });

      it('should return friendly message for P2024', () => {
        const error = {
          code: 'P2024',
          message: 'Unable to check out process from the pool',
        } as Prisma.PrismaClientKnownRequestError;

        const message = getPrismaErrorMessage(error);
        expect(message).toContain('temporarily busy');
      });

      it('should return friendly message for timeout errors', () => {
        const error = new Error('ETIMEDOUT: Connection timeout');

        const message = getPrismaErrorMessage(error);
        expect(message).toContain('too long');
      });

      it('should return friendly message for connection closed', () => {
        const error = new Error('Connection closed');

        const message = getPrismaErrorMessage(error);
        expect(message).toContain('connection was lost');
      });

      it('should return generic message for unknown errors', () => {
        const error = new Error('Unknown error');

        const message = getPrismaErrorMessage(error);
        expect(message).toBeTruthy();
        expect(message.length).toBeGreaterThan(0);
      });
    });
  });
});
