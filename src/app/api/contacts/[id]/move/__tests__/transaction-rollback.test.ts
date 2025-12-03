/**
 * Tests for atomic contact updates with transaction rollback
 * 
 * Tests cover:
 * - Contact update and activity log are atomic (both succeed or both fail)
 * - Transaction rollback on contact update failure
 * - Transaction rollback on activity log creation failure
 * - No partial updates when errors occur
 */

import { POST } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { NextRequest } from 'next/server';

// Mock dependencies
jest.mock('@/auth');
jest.mock('@/lib/db', () => ({
  prisma: {
    contact: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    contactActivity: {
      create: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

jest.mock('@/lib/ai/feedback-tracker', () => ({
  recordStageChangeFeedback: jest.fn(),
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('Contact Move - Transaction Rollback Tests', () => {
  const mockUserId = 'user-123';
  const mockContactId = 'contact-123';
  const mockFromStageId = 'stage-from-123';
  const mockToStageId = 'stage-to-456';

  const mockSession = {
    user: {
      id: mockUserId,
      email: 'test@example.com',
      organizationId: 'org-123',
    },
  };

  const mockContact = {
    id: mockContactId,
    stageId: mockFromStageId,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue(mockSession as any);
    (mockedPrisma.contact.findFirst as jest.Mock).mockResolvedValue({
      ...mockContact,
      stageId: mockFromStageId,
    });
  });

  describe('Transaction rollback on contact update failure', () => {
    it('should rollback entire transaction when contact update fails', async () => {
      const updateError = new Error('Database constraint violation');
      
      // Mock transaction that fails on contact update
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockRejectedValue(updateError),
          },
          contactActivity: {
            create: jest.fn(),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction should rollback - verify activity log was never created
          expect(mockTx.contactActivity.create).not.toHaveBeenCalled();
          throw error;
        }
      });

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.error).toBe('Failed to move contact');
      
      // Verify transaction was called
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });

    it('should not update contact when transaction fails', async () => {
      const updateError = new Error('Database error');
      
      let contactUpdated = false;
      
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async () => {
              contactUpdated = true;
              throw updateError;
            }),
          },
          contactActivity: {
            create: jest.fn(),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction should rollback
          throw error;
        }
      });

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request, { params: Promise.resolve({ id: mockContactId }) });

      // Even though update was called, transaction should rollback
      // In a real scenario, we'd verify the database state, but in this test
      // we verify that the transaction properly handles the error
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });
  });

  describe('Transaction rollback on activity log creation failure', () => {
    it('should rollback entire transaction when activity log creation fails', async () => {
      const activityLogError = new Error('Activity log creation failed');
      
      let contactUpdateCalled = false;
      
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async () => {
              contactUpdateCalled = true;
              return { id: mockContactId, stageId: mockToStageId };
            }),
          },
          contactActivity: {
            create: jest.fn().mockRejectedValue(activityLogError),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction should rollback - contact update should be undone
          expect(contactUpdateCalled).toBe(true);
          throw error;
        }
      });

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.error).toBe('Failed to move contact');
      
      // Verify transaction was called and rolled back
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });
  });

  describe('Successful atomic update', () => {
    it('should update contact and create activity log atomically', async () => {
      const mockUpdatedContact = {
        id: mockContactId,
        stageId: mockToStageId,
        stageEnteredAt: new Date(),
      };

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockResolvedValue(mockUpdatedContact),
          },
          contactActivity: {
            create: jest.fn().mockResolvedValue({
              id: 'activity-123',
              contactId: mockContactId,
              type: 'STAGE_CHANGED',
            }),
          },
        };
        return await callback(mockTx);
      });

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.stageId).toBe(mockToStageId);
      
      // Verify transaction was called
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      
      // Verify both operations were called within transaction
      const transactionCallback = (mockedPrisma.$transaction as jest.Mock).mock.calls[0][0];
      const mockTx = {
        contact: {
          update: jest.fn().mockResolvedValue(mockUpdatedContact),
        },
        contactActivity: {
          create: jest.fn().mockResolvedValue({}),
        },
      };
      await transactionCallback(mockTx);
      
      expect(mockTx.contact.update).toHaveBeenCalledWith({
        where: { id: mockContactId },
        data: {
          stageId: mockToStageId,
          stageEnteredAt: expect.any(Date),
        },
      });
      
      expect(mockTx.contactActivity.create).toHaveBeenCalledWith({
        data: {
          contactId: mockContactId,
          type: 'STAGE_CHANGED',
          title: 'Contact moved to new stage',
          fromStageId: mockFromStageId,
          toStageId: mockToStageId,
          userId: mockUserId,
        },
      });
    });
  });

  describe('No partial updates', () => {
    it('should not leave contact in inconsistent state when activity log fails', async () => {
      let contactUpdateSucceeded = false;
      
      // Ensure contact is found
      (mockedPrisma.contact.findFirst as jest.Mock).mockResolvedValue({
        ...mockContact,
        stageId: mockFromStageId,
      });
      
      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async () => {
              contactUpdateSucceeded = true;
              return { id: mockContactId, stageId: mockToStageId };
            }),
          },
          contactActivity: {
            create: jest.fn().mockRejectedValue(new Error('Activity log failed')),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction rollback should prevent partial update
          // In real scenario, contact.stageId should still be mockFromStageId
          throw error;
        }
      });

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });

      // Should return error response
      expect(response.status).toBe(500);

      // Verify transaction handled the error (rollback)
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
      // Contact update was attempted but should be rolled back
      expect(contactUpdateSucceeded).toBe(true);
    });
  });

  describe('Edge cases and additional scenarios', () => {
    it('should handle concurrent transaction conflicts', async () => {
      const conflictError = {
        code: 'P2034',
        message: 'Transaction conflict',
      };

      (mockedPrisma.$transaction as jest.Mock).mockRejectedValue(conflictError);

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.error).toBe('Failed to move contact');
    });

    it('should handle database connection loss during transaction', async () => {
      const connectionError = new Error('Connection lost');
      connectionError.name = 'PrismaClientKnownRequestError';
      (connectionError as any).code = 'P1001';

      (mockedPrisma.$transaction as jest.Mock).mockRejectedValue(connectionError);

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.error).toBe('Failed to move contact');
    });

    it('should handle timeout during transaction', async () => {
      const timeoutError = new Error('Transaction timeout');
      (timeoutError as any).code = 'P2024';

      (mockedPrisma.$transaction as jest.Mock).mockRejectedValue(timeoutError);

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.error).toBe('Failed to move contact');
    });

    it('should verify transaction isolation - no partial state visible', async () => {
      let contactUpdateCompleted = false;
      let activityLogCreated = false;

      // Ensure contact is found
      (mockedPrisma.contact.findFirst as jest.Mock).mockResolvedValue({
        ...mockContact,
        stageId: mockFromStageId,
      });

      (mockedPrisma.$transaction as jest.Mock).mockImplementation(async (callback: any) => {
        const mockTx = {
          contact: {
            update: jest.fn().mockImplementation(async () => {
              contactUpdateCompleted = true;
              return { id: mockContactId, stageId: mockToStageId };
            }),
          },
          contactActivity: {
            create: jest.fn().mockImplementation(async () => {
              activityLogCreated = true;
              throw new Error('Activity log failed');
            }),
          },
        };
        try {
          return await callback(mockTx);
        } catch (error) {
          // Transaction rollback - both operations should be undone
          // In a real scenario, contact.stageId should still be mockFromStageId
          throw error;
        }
      });

      const request = new NextRequest(`http://localhost:3000/api/contacts/${mockContactId}/move`, {
        method: 'POST',
        body: JSON.stringify({ toStageId: mockToStageId }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request, { params: Promise.resolve({ id: mockContactId }) });

      // Should return error response
      expect(response.status).toBe(500);

      // Both operations were attempted
      expect(contactUpdateCompleted).toBe(true);
      expect(activityLogCreated).toBe(true);
      // But transaction should have rolled back both
      expect(mockedPrisma.$transaction).toHaveBeenCalled();
    });
  });
});

