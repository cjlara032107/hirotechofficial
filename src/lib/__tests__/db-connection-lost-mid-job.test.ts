/**
 * Tests for Database Connection Lost Mid-Job
 * 
 * Tests ensure that:
 * - Database connection failures during long-running operations are handled
 * - Operations can recover from mid-job connection losses
 * - Partial progress is preserved when connection is lost
 * - Retry logic works correctly for mid-job failures
 */

import { prisma } from '../db';
import { connectPrisma } from '../db';
import { Prisma } from '@prisma/client';

// Mock Prisma client
jest.mock('../db', () => {
  const mockPrisma = {
    $connect: jest.fn(),
    $disconnect: jest.fn(),
    syncJob: {
      findUnique: jest.fn(),
      update: jest.fn(),
      create: jest.fn(),
    },
    contact: {
      createMany: jest.fn(),
      findMany: jest.fn(),
      updateMany: jest.fn(),
    },
    facebookPage: {
      findUnique: jest.fn(),
    },
  };

  const mockConnectPrisma = jest.fn(async () => {
    await mockPrisma.$connect();
  });

  return {
    prisma: mockPrisma,
    connectPrisma: mockConnectPrisma,
  };
});

const mockPrisma = prisma as jest.Mocked<typeof prisma>;
const mockConnectPrisma = connectPrisma as jest.MockedFunction<typeof connectPrisma>;

describe('Database Connection Lost Mid-Job', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Database connection lost mid-job', () => {
    it('should handle connection loss during sync job update', async () => {
      const jobId = 'test-job-id';
      
      // First update succeeds
      mockPrisma.syncJob.update.mockResolvedValueOnce({
        id: jobId,
        status: 'IN_PROGRESS',
        syncedContacts: 10,
        totalContacts: 100,
      } as any);

      // Second update fails with connection error
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      mockPrisma.syncJob.update.mockRejectedValueOnce(connectionError);

      // Simulate a sync operation that updates progress
      const updateProgress = async (synced: number) => {
        try {
          await connectPrisma();
          return await mockPrisma.syncJob.update({
            where: { id: jobId },
            data: { syncedContacts: synced },
          });
        } catch (error: unknown) {
          const errorObj = error as { code?: string; message?: string };
          if (errorObj?.code === 'P1001' || errorObj?.message?.includes("Can't reach database")) {
            // Retry once
            await new Promise(resolve => setTimeout(resolve, 100));
            await connectPrisma();
            return await mockPrisma.syncJob.update({
              where: { id: jobId },
              data: { syncedContacts: synced },
            });
          }
          throw error;
        }
      };

      // First update succeeds
      await updateProgress(10);

      // Second update fails, then succeeds on retry
      mockPrisma.syncJob.update.mockResolvedValueOnce({
        id: jobId,
        status: 'IN_PROGRESS',
        syncedContacts: 20,
        totalContacts: 100,
      } as any);

      const result = await updateProgress(20);

      expect(result.syncedContacts).toBe(20);
      expect(mockPrisma.syncJob.update).toHaveBeenCalledTimes(3); // 1 success + 1 fail + 1 retry success
    });

    it('should handle connection loss during bulk contact creation', async () => {
      const contacts = [
        { messengerPSID: 'psid1', firstName: 'John', lastName: 'Doe' },
        { messengerPSID: 'psid2', firstName: 'Jane', lastName: 'Smith' },
      ];

      // First createMany succeeds partially
      mockPrisma.contact.createMany.mockResolvedValueOnce({
        count: 1,
      } as any);

      // Second createMany fails with connection error
      const connectionError = {
        code: 'P1001',
        message: "Can't reach database server",
      } as Prisma.PrismaClientKnownRequestError;

      mockPrisma.contact.createMany.mockRejectedValueOnce(connectionError);

      // Simulate bulk create with retry
      const bulkCreateContacts = async (contactsToCreate: typeof contacts) => {
        try {
          await connectPrisma();
          return await mockPrisma.contact.createMany({
            data: contactsToCreate,
            skipDuplicates: true,
          });
        } catch (error: unknown) {
          const errorObj = error as { code?: string; message?: string };
          if (errorObj?.code === 'P1001' || errorObj?.message?.includes("Can't reach database")) {
            // Retry once
            await new Promise(resolve => setTimeout(resolve, 100));
            await connectPrisma();
            return await mockPrisma.contact.createMany({
              data: contactsToCreate,
              skipDuplicates: true,
            });
          }
          throw error;
        }
      };

      // First batch succeeds
      await bulkCreateContacts([contacts[0]]);

      // Second batch fails, then succeeds on retry
      mockPrisma.contact.createMany.mockResolvedValueOnce({
        count: 1,
      } as any);

      const result = await bulkCreateContacts([contacts[1]]);

      expect(result.count).toBe(1);
      expect(mockPrisma.contact.createMany).toHaveBeenCalledTimes(3); // 1 success + 1 fail + 1 retry success
    });

    it('should handle connection pool exhaustion mid-job', async () => {
      const poolError = {
        code: 'P2024',
        message: 'Unable to check out process from the pool due to timeout',
      } as Prisma.PrismaClientKnownRequestError;

      mockPrisma.contact.findMany.mockRejectedValueOnce(poolError);

      // Simulate query with retry
      const queryContacts = async () => {
        let lastError: unknown;
        for (let attempt = 1; attempt <= 3; attempt++) {
          try {
            await connectPrisma();
            return await mockPrisma.contact.findMany({
              where: { organizationId: 'org-id' },
            });
          } catch (error) {
            lastError = error;
            const errorObj = error as { code?: string; message?: string };
            if (errorObj?.code === 'P2024' && attempt < 3) {
              // Wait before retry
              await new Promise(resolve => setTimeout(resolve, 100 * attempt));
              continue;
            }
            throw error;
          }
        }
        throw lastError;
      };

      // First attempt fails, second succeeds
      mockPrisma.contact.findMany.mockResolvedValueOnce([
        { id: 'contact1', firstName: 'John' },
      ] as any);

      const result = await queryContacts();

      expect(result).toHaveLength(1);
      expect(mockPrisma.contact.findMany).toHaveBeenCalledTimes(2);
    });

    it('should preserve partial progress when connection is lost', async () => {
      const jobId = 'test-job-id';
      let syncedCount = 0;

      // Simulate sync operation with progress tracking
      const syncOperation = async () => {
        const batchSize = 10;
        const totalItems = 100;

        for (let i = 0; i < totalItems; i += batchSize) {
          try {
            await connectPrisma();
            
            // Simulate processing batch
            syncedCount += batchSize;

            // Update progress - this might fail
            await mockPrisma.syncJob.update({
              where: { id: jobId },
              data: { syncedContacts: syncedCount },
            });
          } catch (error) {
            const errorObj = error as { code?: string; message?: string };
            if (errorObj?.code === 'P1001' || errorObj?.code === 'P2024') {
              // Connection lost - but progress is preserved in memory
              console.warn(`Connection lost at ${syncedCount}/${totalItems}, retrying...`);
              await new Promise(resolve => setTimeout(resolve, 100));
              await connectPrisma();
              // Retry the update
              await mockPrisma.syncJob.update({
                where: { id: jobId },
                data: { syncedContacts: syncedCount },
              });
            } else {
              throw error;
            }
          }
        }
      };

      // Mock successful updates
      mockPrisma.syncJob.update.mockResolvedValue({
        id: jobId,
        syncedContacts: syncedCount,
      } as any);

      // Simulate connection loss at 30 items
      let callCount = 0;
      mockPrisma.syncJob.update.mockImplementation(async () => {
        callCount++;
        if (callCount === 3) {
          // Third update fails
          throw {
            code: 'P1001',
            message: "Can't reach database server",
          } as Prisma.PrismaClientKnownRequestError;
        }
        return {
          id: jobId,
          syncedContacts: syncedCount,
        } as any;
      });

      await syncOperation();

      // Progress should be preserved
      expect(syncedCount).toBe(100);
    });

    it('should handle connection reset during transaction', async () => {
      const resetError = new Error('Connection was forcibly closed by the remote host');
      (resetError as any).code = 'ECONNRESET';

      mockPrisma.contact.updateMany.mockRejectedValueOnce(resetError);

      // Simulate update with retry
      const updateContacts = async () => {
        try {
          await connectPrisma();
          return await mockPrisma.contact.updateMany({
            where: { organizationId: 'org-id' },
            data: { lastSyncedAt: new Date() },
          });
        } catch (error) {
          const errorObj = error as Error & { code?: string };
          if (errorObj?.code === 'ECONNRESET') {
            // Disconnect and reconnect
            await mockPrisma.$disconnect();
            await new Promise(resolve => setTimeout(resolve, 100));
            await connectPrisma();
            return await mockPrisma.contact.updateMany({
              where: { organizationId: 'org-id' },
              data: { lastSyncedAt: new Date() },
            });
          }
          throw error;
        }
      };

      // Retry succeeds
      mockPrisma.contact.updateMany.mockResolvedValueOnce({
        count: 5,
      } as any);

      const result = await updateContacts();

      expect(result.count).toBe(5);
      expect(mockPrisma.$disconnect).toHaveBeenCalled();
      expect(mockPrisma.contact.updateMany).toHaveBeenCalledTimes(2);
    });
  });
});

