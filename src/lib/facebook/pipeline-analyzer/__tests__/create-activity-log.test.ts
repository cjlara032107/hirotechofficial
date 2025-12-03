/**
 * Tests for createActivityLog function
 * 
 * Tests verify:
 * - Creates activity log entry successfully
 * - Handles null stageId (removal case)
 * - Handles null previousStageId (initial assignment)
 */

import { createActivityLog } from '../create-activity-log';
import { prisma } from '@/lib/db';
import { withRetry } from '@/lib/db-retry';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    contactActivity: {
      create: jest.fn(),
    },
  },
}));

jest.mock('@/lib/db-retry', () => ({
  withRetry: jest.fn((fn) => fn()),
}));

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const mockedWithRetry = withRetry as jest.MockedFunction<typeof withRetry>;

describe('createActivityLog', () => {
  const mockContactId = 'contact-123';
  const mockStageId = 'stage-456';
  const mockPreviousStageId = 'stage-789';
  const mockUserId = 'user-123';
  const mockReason = 'AI auto-assigned to pipeline';

  const mockActivityLog = {
    id: 'activity-123',
    contactId: mockContactId,
    type: 'STAGE_CHANGED' as const,
    title: 'Contact moved to new stage',
    description: mockReason,
    toStageId: mockStageId,
    fromStageId: mockPreviousStageId,
    userId: mockUserId,
    metadata: { confidence: 85 },
    createdAt: new Date(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Default mock for withRetry - just execute the function
    mockedWithRetry.mockImplementation(async (fn) => fn());
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Creates activity log entry successfully', () => {
    it('should create activity log entry with all fields', async () => {
      mockedPrisma.contactActivity.create.mockResolvedValue(mockActivityLog);

      const result = await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: mockPreviousStageId,
        reason: mockReason,
        metadata: { confidence: 85 },
        userId: mockUserId,
      });

      expect(result).toEqual(mockActivityLog);
      expect(mockedWithRetry).toHaveBeenCalledTimes(1);
      expect(mockedPrisma.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'Contact moved to new stage',
          description: mockReason,
          toStageId: mockStageId,
          fromStageId: mockPreviousStageId,
          userId: mockUserId,
          metadata: { confidence: 85 },
        },
      });
    });

    it('should create activity log entry with minimal required fields', async () => {
      const minimalLog = {
        ...mockActivityLog,
        fromStageId: null,
        userId: null,
        metadata: null,
      };
      mockedPrisma.contactActivity.create.mockResolvedValue(minimalLog as any);

      const result = await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: null,
        reason: mockReason,
      });

      expect(result).toEqual(minimalLog);
      expect(mockedPrisma.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'Contact assigned to stage',
          description: mockReason,
          toStageId: mockStageId,
          fromStageId: undefined,
          userId: undefined,
          metadata: undefined,
        },
      });
    });

    it('should use withRetry for resilience', async () => {
      mockedPrisma.contactActivity.create.mockResolvedValue(mockActivityLog);

      await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: mockPreviousStageId,
        reason: mockReason,
      });

      expect(mockedWithRetry).toHaveBeenCalledTimes(1);
      expect(mockedWithRetry).toHaveBeenCalledWith(expect.any(Function));
    });
  });

  describe('Test: Handles null stageId (removal case)', () => {
    it('should create activity log with null stageId for removal', async () => {
      const removalLog = {
        ...mockActivityLog,
        toStageId: null,
        title: 'Contact removed from stage',
      };
      mockedPrisma.contactActivity.create.mockResolvedValue(removalLog as any);

      const result = await createActivityLog({
        contactId: mockContactId,
        stageId: null,
        previousStageId: mockPreviousStageId,
        reason: 'Contact removed from pipeline',
      });

      expect(result).toEqual(removalLog);
      expect(mockedPrisma.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'Contact removed from stage',
          description: 'Contact removed from pipeline',
          toStageId: undefined,
          fromStageId: mockPreviousStageId,
          userId: undefined,
          metadata: undefined,
        },
      });
    });

    it('should handle removal with null previousStageId', async () => {
      const removalLog = {
        ...mockActivityLog,
        toStageId: null,
        fromStageId: null,
        title: 'Contact removed from stage',
      };
      mockedPrisma.contactActivity.create.mockResolvedValue(removalLog as any);

      const result = await createActivityLog({
        contactId: mockContactId,
        stageId: null,
        previousStageId: null,
        reason: 'Contact removed from pipeline',
      });

      expect(result).toEqual(removalLog);
      expect(mockedPrisma.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'Contact removed from stage',
          description: 'Contact removed from pipeline',
          toStageId: undefined,
          fromStageId: undefined,
          userId: undefined,
          metadata: undefined,
        },
      });
    });
  });

  describe('Test: Handles null previousStageId (initial assignment)', () => {
    it('should create activity log with null previousStageId for initial assignment', async () => {
      const initialAssignmentLog = {
        ...mockActivityLog,
        fromStageId: null,
        title: 'Contact assigned to stage',
      };
      mockedPrisma.contactActivity.create.mockResolvedValue(initialAssignmentLog as any);

      const result = await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: null,
        reason: mockReason,
      });

      expect(result).toEqual(initialAssignmentLog);
      expect(mockedPrisma.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'Contact assigned to stage',
          description: mockReason,
          toStageId: mockStageId,
          fromStageId: undefined,
          userId: undefined,
          metadata: undefined,
        },
      });
    });

    it('should use correct title for initial assignment', async () => {
      const initialAssignmentLog = {
        ...mockActivityLog,
        fromStageId: null,
        title: 'Contact assigned to stage',
      };
      mockedPrisma.contactActivity.create.mockResolvedValue(initialAssignmentLog as any);

      await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: null,
        reason: mockReason,
      });

      const createCall = mockedPrisma.contactActivity.create.mock.calls[0][0];
      expect(createCall.data.title).toBe('Contact assigned to stage');
    });
  });

  describe('Error handling', () => {
    it('should handle database errors gracefully without throwing', async () => {
      const dbError = new Error('Database connection failed');
      mockedPrisma.contactActivity.create.mockRejectedValue(dbError);
      // withRetry will execute the function, which will throw, and withRetry will propagate the error
      mockedWithRetry.mockImplementation(async (fn) => {
        try {
          return await fn();
        } catch (error) {
          throw error;
        }
      });

      const result = await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: mockPreviousStageId,
        reason: mockReason,
      });

      expect(result).toBeUndefined();
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('[Create Activity Log] Failed to create activity log entry:'),
        expect.objectContaining({
          contactId: mockContactId,
          stageId: mockStageId,
          previousStageId: mockPreviousStageId,
        })
      );
    });

    it('should log error details when creation fails', async () => {
      const dbError = new Error('Prisma error: P2002');
      mockedPrisma.contactActivity.create.mockRejectedValue(dbError);
      // withRetry will execute the function, which will throw, and withRetry will propagate the error
      mockedWithRetry.mockImplementation(async (fn) => {
        try {
          return await fn();
        } catch (error) {
          throw error;
        }
      });

      await createActivityLog({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: mockPreviousStageId,
        reason: mockReason,
      });

      expect(console.error).toHaveBeenCalled();
      const errorCall = (console.error as jest.Mock).mock.calls[0];
      expect(errorCall[1]).toMatchObject({
        contactId: mockContactId,
        stageId: mockStageId,
        previousStageId: mockPreviousStageId,
        error: expect.stringContaining('Prisma error'),
      });
    });
  });
});

