/**
 * Tests for chunked contact updates utility
 */

import { updateContactsInChunks, retryFailedChunks } from '../chunked-contact-updates';
import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

// Mock Prisma
jest.mock('@/lib/db', () => ({
  prisma: {
    $transaction: jest.fn(),
  },
}));

describe('chunked-contact-updates', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('updateContactsInChunks', () => {
    it('should process contacts in chunks of 50', async () => {
      const contactIds = Array.from({ length: 150 }, (_, i) => `contact-${i}`);
      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate successful update
      });

      (prisma.$transaction as jest.Mock).mockImplementation(
        async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
          const mockTx = {} as Prisma.TransactionClient;
          await callback(mockTx);
        }
      );

      const result = await updateContactsInChunks(updateFn, {
        contactIds,
        chunkSize: 50,
      });

      expect(result.totalContacts).toBe(150);
      expect(result.successfulContacts).toBe(150);
      expect(result.failedContacts).toBe(0);
      expect(result.completedChunks).toBe(3); // 150 / 50 = 3 chunks
      expect(result.failedChunks).toBe(0);
      expect(prisma.$transaction).toHaveBeenCalledTimes(3);
    });

    it('should rollback chunk on error without affecting other chunks', async () => {
      const contactIds = Array.from({ length: 100 }, (_, i) => `contact-${i}`);
      let callCount = 0;

      (prisma.$transaction as jest.Mock).mockImplementation(
        async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
          callCount++;
          // Simulate error on second chunk
          if (callCount === 2) {
            throw new Error('Database error');
          }
          const mockTx = {} as Prisma.TransactionClient;
          await callback(mockTx);
        }
      );

      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate update
      });

      const result = await updateContactsInChunks(updateFn, {
        contactIds,
        chunkSize: 50,
        maxRetries: 1,
      });

      expect(result.totalContacts).toBe(100);
      expect(result.successfulContacts).toBe(50); // First chunk succeeded
      expect(result.failedContacts).toBe(50); // Second chunk failed
      expect(result.completedChunks).toBe(1);
      expect(result.failedChunks).toBe(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].chunkIndex).toBe(1);
    });

    it('should retry failed chunks up to maxRetries', async () => {
      const contactIds = Array.from({ length: 50 }, (_, i) => `contact-${i}`);
      let attemptCount = 0;

      (prisma.$transaction as jest.Mock).mockImplementation(
        async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
          attemptCount++;
          // Fail first 2 attempts, succeed on 3rd
          if (attemptCount <= 2) {
            throw new Error('Temporary error');
          }
          const mockTx = {} as Prisma.TransactionClient;
          await callback(mockTx);
        }
      );

      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate update
      });

      const result = await updateContactsInChunks(updateFn, {
        contactIds,
        chunkSize: 50,
        maxRetries: 3,
      });

      expect(result.successfulContacts).toBe(50);
      expect(result.failedContacts).toBe(0);
      expect(prisma.$transaction).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
    });

    it('should call onProgress callback for each chunk', async () => {
      const contactIds = Array.from({ length: 100 }, (_, i) => `contact-${i}`);
      const progressUpdates: Array<{ processed: number; total: number }> = [];

      (prisma.$transaction as jest.Mock).mockImplementation(
        async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
          const mockTx = {} as Prisma.TransactionClient;
          await callback(mockTx);
        }
      );

      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate update
      });

      await updateContactsInChunks(updateFn, {
        contactIds,
        chunkSize: 50,
        onProgress: (progress) => {
          progressUpdates.push({
            processed: progress.processedContacts,
            total: progress.totalContacts,
          });
        },
      });

      expect(progressUpdates.length).toBeGreaterThan(0);
      expect(progressUpdates[progressUpdates.length - 1].processed).toBe(100);
      expect(progressUpdates[progressUpdates.length - 1].total).toBe(100);
    });

    it('should call onChunkComplete callback for each chunk', async () => {
      const contactIds = Array.from({ length: 100 }, (_, i) => `contact-${i}`);
      const completedChunks: Array<{ index: number; success: boolean; count: number }> = [];

      (prisma.$transaction as jest.Mock).mockImplementation(
        async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
          const mockTx = {} as Prisma.TransactionClient;
          await callback(mockTx);
        }
      );

      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate update
      });

      await updateContactsInChunks(updateFn, {
        contactIds,
        chunkSize: 50,
        onChunkComplete: (chunkIndex, success, count) => {
          completedChunks.push({ index: chunkIndex, success, count });
        },
      });

      expect(completedChunks).toHaveLength(2);
      expect(completedChunks[0].success).toBe(true);
      expect(completedChunks[0].count).toBe(50);
      expect(completedChunks[1].success).toBe(true);
      expect(completedChunks[1].count).toBe(50);
    });

    it('should handle empty contact list', async () => {
      const result = await updateContactsInChunks(
        jest.fn(),
        {
          contactIds: [],
          chunkSize: 50,
        }
      );

      expect(result.totalContacts).toBe(0);
      expect(result.successfulContacts).toBe(0);
      expect(result.failedContacts).toBe(0);
      expect(result.completedChunks).toBe(0);
      expect(prisma.$transaction).not.toHaveBeenCalled();
    });
  });

  describe('retryFailedChunks', () => {
    it('should retry failed chunks independently', async () => {
      const failedChunks = [
        { chunkIndex: 0, contactIds: ['contact-1', 'contact-2'], error: new Error('Failed') },
        { chunkIndex: 2, contactIds: ['contact-3', 'contact-4'], error: new Error('Failed') },
      ];

      let attemptCount = 0;
      (prisma.$transaction as jest.Mock).mockImplementation(
        async (callback: (tx: Prisma.TransactionClient) => Promise<void>) => {
          attemptCount++;
          // Succeed on first retry
          const mockTx = {} as Prisma.TransactionClient;
          await callback(mockTx);
        }
      );

      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate update
      });

      const result = await retryFailedChunks(updateFn, failedChunks, {
        maxRetries: 3,
      });

      expect(result.successfulContacts).toBe(4);
      expect(result.failedContacts).toBe(0);
      expect(result.completedChunks).toBe(2);
      expect(result.failedChunks).toBe(0);
      expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    });

    it('should handle chunks that still fail after retries', async () => {
      const failedChunks = [
        { chunkIndex: 0, contactIds: ['contact-1'], error: new Error('Failed') },
      ];

      (prisma.$transaction as jest.Mock).mockRejectedValue(
        new Error('Persistent error')
      );

      const updateFn = jest.fn(async (chunk: string[]) => {
        // Simulate update
      });

      const result = await retryFailedChunks(updateFn, failedChunks, {
        maxRetries: 2,
      });

      expect(result.successfulContacts).toBe(0);
      expect(result.failedContacts).toBe(1);
      expect(result.completedChunks).toBe(0);
      expect(result.failedChunks).toBe(1);
      expect(result.errors).toHaveLength(1);
      // Should have attempted 3 times (1 initial + 2 retries)
      expect(prisma.$transaction).toHaveBeenCalledTimes(3);
    });
  });
});









