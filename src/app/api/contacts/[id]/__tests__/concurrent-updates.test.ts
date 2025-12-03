/**
 * Tests for Concurrent Contact Updates
 * 
 * Tests ensure that:
 * - Concurrent updates are handled with optimistic locking
 * - Conflicts are detected and return 409 status
 * - Retries work correctly for transient conflicts
 * - Deadlocks are handled gracefully
 */

import { NextRequest } from 'next/server';
import { PATCH } from '../route';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

// Mock Next.js server modules
jest.mock('next/server', () => ({
  NextRequest: jest.fn().mockImplementation((url, init) => ({
    url,
    method: init?.method || 'PATCH',
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
    contact: {
      findFirst: jest.fn(),
      update: jest.fn(),
    },
    $transaction: jest.fn(),
  },
}));

const mockedAuth = auth as jest.MockedFunction<typeof auth>;
const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('Concurrent Contact Updates', () => {
  const mockContactId = 'test-contact-id';
  const mockUserId = 'test-user-id';
  const mockOrgId = 'test-org-id';
  const mockUpdatedAt = new Date('2024-01-01T00:00:00Z');
  const mockUpdatedAtLater = new Date('2024-01-01T00:00:01Z');

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAuth.mockResolvedValue({
      user: {
        id: mockUserId,
        organizationId: mockOrgId,
        email: 'test@example.com',
      },
    } as any);
  });

  describe('Optimistic Locking', () => {
    it('should detect concurrent modification when expectedUpdatedAt is provided', async () => {
      const request = new NextRequest(`http://localhost/api/contacts/${mockContactId}`, {
        method: 'PATCH',
      });
      request.json = jest.fn().mockResolvedValue({
        firstName: 'Updated',
        expectedUpdatedAt: mockUpdatedAt.toISOString(),
      });

      // First call returns contact with different updatedAt
      mockedPrisma.contact.findFirst.mockResolvedValueOnce({
        id: mockContactId,
        updatedAt: mockUpdatedAtLater, // Different timestamp
      } as any);

      const response = await PATCH(request, {
        params: Promise.resolve({ id: mockContactId }),
      });

      const responseData = await response.json();
      expect(response.status).toBe(409);
      expect(responseData.error).toContain('modified by another request');
      expect(responseData.code).toBe('CONCURRENT_MODIFICATION');
    });

    it('should succeed when expectedUpdatedAt matches current updatedAt', async () => {
      const request = new NextRequest(`http://localhost/api/contacts/${mockContactId}`, {
        method: 'PATCH',
      });
      request.json = jest.fn().mockResolvedValue({
        firstName: 'Updated',
        expectedUpdatedAt: mockUpdatedAt.toISOString(),
      });

      const mockContact = {
        id: mockContactId,
        firstName: 'Updated',
        lastName: 'Test',
        updatedAt: mockUpdatedAtLater,
      };

      // Transaction mock
      mockedPrisma.$transaction.mockImplementation(async (callback: any) => {
        // First findFirst call in transaction
        mockedPrisma.contact.findFirst.mockResolvedValueOnce({
          id: mockContactId,
          updatedAt: mockUpdatedAt, // Matches expected
        } as any);
        
        // Update call
        mockedPrisma.contact.update.mockResolvedValueOnce(mockContact as any);
        
        return callback({
          contact: {
            findFirst: mockedPrisma.contact.findFirst,
            update: mockedPrisma.contact.update,
          },
        });
      });

      // Initial findFirst call (before transaction)
      mockedPrisma.contact.findFirst.mockResolvedValueOnce({
        id: mockContactId,
        updatedAt: mockUpdatedAt, // Matches expected
      } as any);

      const response = await PATCH(request, {
        params: Promise.resolve({ id: mockContactId }),
      });

      const responseData = await response.json();
      expect(response.status).toBe(200);
      expect(responseData.firstName).toBe('Updated');
    });

    it('should retry on concurrent modification with exponential backoff', async () => {
      const request = new NextRequest(`http://localhost/api/contacts/${mockContactId}`, {
        method: 'PATCH',
      });
      request.json = jest.fn().mockResolvedValue({
        firstName: 'Updated',
        expectedUpdatedAt: mockUpdatedAt.toISOString(),
      });

      let attemptCount = 0;
      mockedPrisma.contact.findFirst.mockImplementation(async () => {
        attemptCount++;
        if (attemptCount === 1) {
          // First attempt: different timestamp
          return {
            id: mockContactId,
            updatedAt: mockUpdatedAtLater,
          } as any;
        } else if (attemptCount === 2) {
          // Second attempt: still different (simulating rapid updates)
          return {
            id: mockContactId,
            updatedAt: new Date(mockUpdatedAtLater.getTime() + 1000),
          } as any;
        } else {
          // Third attempt: matches
          return {
            id: mockContactId,
            updatedAt: mockUpdatedAt,
          } as any;
        }
      });

      // On third attempt, transaction succeeds
      mockedPrisma.$transaction.mockImplementationOnce(async (callback: any) => {
        const mockContact = {
          id: mockContactId,
          firstName: 'Updated',
          updatedAt: mockUpdatedAtLater,
        };
        
        mockedPrisma.contact.findFirst.mockResolvedValueOnce({
          id: mockContactId,
          updatedAt: mockUpdatedAt,
        } as any);
        
        mockedPrisma.contact.update.mockResolvedValueOnce(mockContact as any);
        
        return callback({
          contact: {
            findFirst: mockedPrisma.contact.findFirst,
            update: mockedPrisma.contact.update,
          },
        });
      });

      const response = await PATCH(request, {
        params: Promise.resolve({ id: mockContactId }),
      });

      // Should eventually succeed after retries
      expect(attemptCount).toBeGreaterThan(1);
    });
  });

  describe('Deadlock Handling', () => {
    it('should handle database deadlocks with retry', async () => {
      const request = new NextRequest(`http://localhost/api/contacts/${mockContactId}`, {
        method: 'PATCH',
      });
      request.json = jest.fn().mockResolvedValue({
        firstName: 'Updated',
      });

      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      // First attempt: deadlock
      mockedPrisma.contact.findFirst.mockResolvedValueOnce({
        id: mockContactId,
        updatedAt: mockUpdatedAt,
      } as any);

      mockedPrisma.$transaction.mockRejectedValueOnce(deadlockError);

      // Second attempt: success
      mockedPrisma.contact.findFirst.mockResolvedValueOnce({
        id: mockContactId,
        updatedAt: mockUpdatedAt,
      } as any);

      mockedPrisma.$transaction.mockImplementationOnce(async (callback: any) => {
        const mockContact = {
          id: mockContactId,
          firstName: 'Updated',
          updatedAt: mockUpdatedAtLater,
        };
        
        mockedPrisma.contact.findFirst.mockResolvedValueOnce({
          id: mockContactId,
          updatedAt: mockUpdatedAt,
        } as any);
        
        mockedPrisma.contact.update.mockResolvedValueOnce(mockContact as any);
        
        return callback({
          contact: {
            findFirst: mockedPrisma.contact.findFirst,
            update: mockedPrisma.contact.update,
          },
        });
      });

      const response = await PATCH(request, {
        params: Promise.resolve({ id: mockContactId }),
      });

      const responseData = await response.json();
      expect(response.status).toBe(200);
      expect(responseData.firstName).toBe('Updated');
    });

    it('should return 503 after max retries for deadlocks', async () => {
      const request = new NextRequest(`http://localhost/api/contacts/${mockContactId}`, {
        method: 'PATCH',
      });
      request.json = jest.fn().mockResolvedValue({
        firstName: 'Updated',
      });

      const deadlockError = new Prisma.PrismaClientKnownRequestError(
        'Deadlock detected',
        {
          code: 'P2034',
          clientVersion: '5.0.0',
        } as any
      );

      mockedPrisma.contact.findFirst.mockResolvedValue({
        id: mockContactId,
        updatedAt: mockUpdatedAt,
      } as any);

      mockedPrisma.$transaction.mockRejectedValue(deadlockError);

      const response = await PATCH(request, {
        params: Promise.resolve({ id: mockContactId }),
      });

      const responseData = await response.json();
      expect(response.status).toBe(503);
      expect(responseData.code).toBe('DEADLOCK');
    });
  });

  describe('Contact Not Found', () => {
    it('should return 404 when contact does not exist', async () => {
      const request = new NextRequest(`http://localhost/api/contacts/${mockContactId}`, {
        method: 'PATCH',
      });
      request.json = jest.fn().mockResolvedValue({
        firstName: 'Updated',
      });

      mockedPrisma.contact.findFirst.mockResolvedValue(null);

      const response = await PATCH(request, {
        params: Promise.resolve({ id: mockContactId }),
      });

      const responseData = await response.json();
      expect(response.status).toBe(404);
      expect(responseData.error).toContain('not found');
    });
  });
});









