/**
 * Tests for hybrid auto-tag processor
 */

import { HybridAutoTagProcessor, processAutoTagForContact } from '../hybrid-auto-tag-processor';
import { prisma } from '@/lib/db';

jest.mock('@/lib/db', () => ({
  prisma: {
    pipelineStage: {
      findUnique: jest.fn(),
    },
    contact: {
      findUnique: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
    },
    tag: {
      updateMany: jest.fn(),
    },
    contactActivity: {
      create: jest.fn(),
    },
    $transaction: jest.fn((callback) => {
      const mockTx = {
        contact: {
          update: jest.fn(),
          findMany: jest.fn(),
        },
        tag: {
          updateMany: jest.fn(),
        },
        contactActivity: {
          create: jest.fn(),
        },
      };
      return callback(mockTx);
    }),
  },
}));

jest.mock('@/lib/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
  },
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('HybridAutoTagProcessor', () => {
  const mockContactId = 'contact-123';
  const mockStageId = 'stage-456';
  const mockOrganizationId = 'org-789';
  const mockUserId = 'user-abc';

  const mockStage = {
    autoTagEnabled: true,
    autoTagToAdd: 'new-tag',
    autoTagToRemove: 'old-tag',
  };

  const mockContact = {
    id: mockContactId,
    tags: ['old-tag', 'existing-tag'],
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Immediate Processing', () => {
    it('should process single contact immediately', async () => {
      mockedPrisma.pipelineStage.findUnique.mockResolvedValue(mockStage as never);
      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as never);

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: (tx: unknown) => Promise<unknown>) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockResolvedValue({}),
          },
          tag: {
            updateMany: jest.fn().mockResolvedValue({}),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(mockTx);
      });

      const result = await HybridAutoTagProcessor.process(
        [{ contactId: mockContactId, stageId: mockStageId, organizationId: mockOrganizationId, userId: mockUserId }],
        { contactCount: 1, operationType: 'single', sync: true }
      );

      expect(result.method).toBe('immediate');
      expect(result.processed).toBe(1);
      expect(result.failed).toBe(0);
    });

    it('should skip if auto-tag disabled', async () => {
      const disabledStage = { ...mockStage, autoTagEnabled: false };
      mockedPrisma.pipelineStage.findUnique.mockResolvedValue(disabledStage as never);

      const result = await HybridAutoTagProcessor.process(
        [{ contactId: mockContactId, stageId: mockStageId, organizationId: mockOrganizationId, userId: mockUserId }],
        { contactCount: 1, operationType: 'single', sync: true }
      );

      expect(result.processed).toBe(1);
    });
  });

  describe('Batch Processing', () => {
    it('should process small bulk in batches', async () => {
      const jobs = Array.from({ length: 30 }, (_, i) => ({
        contactId: `contact-${i}`,
        stageId: mockStageId,
        organizationId: mockOrganizationId,
        userId: mockUserId,
      }));

      mockedPrisma.pipelineStage.findUnique.mockResolvedValue(mockStage as never);
      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as never);

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: (tx: unknown) => Promise<unknown>) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockResolvedValue({}),
          },
          tag: {
            updateMany: jest.fn().mockResolvedValue({}),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(mockTx);
      });

      const result = await HybridAutoTagProcessor.process(
        jobs,
        { contactCount: 30, operationType: 'batch' }
      );

      expect(result.method).toBe('batch');
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors', async () => {
      mockedPrisma.pipelineStage.findUnique.mockRejectedValue(new Error('Database error'));

      const result = await HybridAutoTagProcessor.process(
        [{ contactId: mockContactId, stageId: mockStageId, organizationId: mockOrganizationId, userId: mockUserId }],
        { contactCount: 1, operationType: 'single', sync: true }
      );

      expect(result.failed).toBe(1);
    });
  });

  describe('Convenience Functions', () => {
    it('processAutoTagForContact should work correctly', async () => {
      mockedPrisma.pipelineStage.findUnique.mockResolvedValue(mockStage as never);
      mockedPrisma.contact.findUnique.mockResolvedValue(mockContact as never);

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: (tx: unknown) => Promise<unknown>) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockResolvedValue({}),
          },
          tag: {
            updateMany: jest.fn().mockResolvedValue({}),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({}),
          },
        };
        return callback(mockTx);
      });

      const result = await processAutoTagForContact(
        mockContactId,
        mockStageId,
        mockOrganizationId,
        mockUserId
      );

      expect(result).toBe(true);
    });
  });
});

