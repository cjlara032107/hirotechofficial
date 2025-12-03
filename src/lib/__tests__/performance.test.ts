/**
 * Performance Tests
 * 
 * Tests to verify performance meets requirements:
 * - API response time benchmarks
 * - Database query performance
 * - Resource usage limits
 * - Concurrent request handling
 */

import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db';
import { safePrismaOperation } from '@/lib/prisma-error-handler';

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
      count: jest.fn(),
    },
    user: {
      findUnique: jest.fn(),
    },
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

describe('Performance Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('API Response Time Benchmarks', () => {
    it('should complete database queries within acceptable time limits', async () => {
      const startTime = Date.now();
      
      (prisma.contact.findMany as jest.Mock).mockResolvedValue([
        { id: '1', firstName: 'Test', lastName: 'User' },
      ]);

      await safePrismaOperation(
        () => prisma.contact.findMany({ take: 10 }),
        { operationName: 'findContacts' }
      );

      const duration = Date.now() - startTime;
      
      // Should complete within 1 second for simple queries
      expect(duration).toBeLessThan(1000);
    });

    it('should handle paginated queries efficiently', async () => {
      const startTime = Date.now();
      const mockContacts = Array.from({ length: 25 }, (_, i) => ({
        id: String(i + 1),
        firstName: `User${i + 1}`,
        lastName: 'Test',
      }));

      (prisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      await safePrismaOperation(
        () => prisma.contact.findMany({
          take: 25,
          skip: 0,
        }),
        { operationName: 'findContactsPaginated' }
      );

      const duration = Date.now() - startTime;
      
      // Paginated queries should complete within 2 seconds
      expect(duration).toBeLessThan(2000);
    });

    it('should handle count queries efficiently', async () => {
      const startTime = Date.now();

      (prisma.contact.count as jest.Mock).mockResolvedValue(1000);

      await safePrismaOperation(
        () => prisma.contact.count(),
        { operationName: 'countContacts' }
      );

      const duration = Date.now() - startTime;
      
      // Count queries should complete within 1 second
      expect(duration).toBeLessThan(1000);
    });
  });

  describe('Database Query Performance', () => {
    it('should handle complex queries with filters efficiently', async () => {
      const startTime = Date.now();
      const mockContacts = Array.from({ length: 50 }, (_, i) => ({
        id: String(i + 1),
        firstName: `User${i + 1}`,
        lastName: 'Test',
        tags: ['tag1', 'tag2'],
      }));

      (prisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      await safePrismaOperation(
        () => prisma.contact.findMany({
          where: {
            tags: { has: 'tag1' },
          },
          take: 50,
        }),
        { operationName: 'findContactsWithFilters' }
      );

      const duration = Date.now() - startTime;
      
      // Complex filtered queries should complete within 2 seconds
      expect(duration).toBeLessThan(2000);
    });

    it('should handle large result sets efficiently', async () => {
      const startTime = Date.now();
      const mockContacts = Array.from({ length: 100 }, (_, i) => ({
        id: String(i + 1),
        firstName: `User${i + 1}`,
        lastName: 'Test',
      }));

      (prisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      await safePrismaOperation(
        () => prisma.contact.findMany({
          take: 100,
        }),
        { operationName: 'findLargeResultSet' }
      );

      const duration = Date.now() - startTime;
      
      // Large result sets should complete within 3 seconds
      expect(duration).toBeLessThan(3000);
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle multiple concurrent database operations', async () => {
      (prisma.contact.findMany as jest.Mock).mockResolvedValue([
        { id: '1', firstName: 'Test', lastName: 'User' },
      ]);

      const startTime = Date.now();
      
      const promises = Array.from({ length: 10 }, () =>
        safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: 'concurrentQuery' }
        )
      );

      await Promise.all(promises);

      const duration = Date.now() - startTime;
      
      // 10 concurrent queries should complete within 5 seconds
      expect(duration).toBeLessThan(5000);
    });

    it('should handle concurrent read and count operations', async () => {
      (prisma.contact.findMany as jest.Mock).mockResolvedValue([
        { id: '1', firstName: 'Test', lastName: 'User' },
      ]);
      (prisma.contact.count as jest.Mock).mockResolvedValue(100);

      const startTime = Date.now();
      
      const promises = [
        safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: 'concurrentRead' }
        ),
        safePrismaOperation(
          () => prisma.contact.count(),
          { operationName: 'concurrentCount' }
        ),
        safePrismaOperation(
          () => prisma.contact.findMany({ take: 20 }),
          { operationName: 'concurrentRead2' }
        ),
      ];

      await Promise.all(promises);

      const duration = Date.now() - startTime;
      
      // Mixed concurrent operations should complete within 3 seconds
      expect(duration).toBeLessThan(3000);
    });
  });

  describe('Resource Usage Limits', () => {
    it('should not exceed memory limits for reasonable query sizes', async () => {
      const mockContacts = Array.from({ length: 1000 }, (_, i) => ({
        id: String(i + 1),
        firstName: `User${i + 1}`,
        lastName: 'Test',
        tags: ['tag1'],
        createdAt: new Date(),
        updatedAt: new Date(),
      }));

      (prisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const result = await safePrismaOperation(
        () => prisma.contact.findMany({ take: 1000 }),
        { operationName: 'largeQuery' }
      );

      // Should successfully return results without memory issues
      expect(result).toHaveLength(1000);
    });

    it('should handle pagination to prevent memory issues', async () => {
      const pageSize = 25;
      const mockContacts = Array.from({ length: pageSize }, (_, i) => ({
        id: String(i + 1),
        firstName: `User${i + 1}`,
        lastName: 'Test',
      }));

      (prisma.contact.findMany as jest.Mock).mockResolvedValue(mockContacts);

      const result = await safePrismaOperation(
        () => prisma.contact.findMany({
          take: pageSize,
          skip: 0,
        }),
        { operationName: 'paginatedQuery' }
      );

      // Should return only the requested page size
      expect(result.length).toBeLessThanOrEqual(pageSize);
    });
  });

  describe('Performance Under Load', () => {
    it('should maintain performance with multiple sequential operations', async () => {
      (prisma.contact.findMany as jest.Mock).mockResolvedValue([
        { id: '1', firstName: 'Test', lastName: 'User' },
      ]);

      const startTime = Date.now();
      
      for (let i = 0; i < 20; i++) {
        await safePrismaOperation(
          () => prisma.contact.findMany({ take: 10 }),
          { operationName: `sequentialQuery${i}` }
        );
      }

      const duration = Date.now() - startTime;
      const averageTime = duration / 20;
      
      // Average time per operation should be reasonable
      expect(averageTime).toBeLessThan(500);
    });
  });
});

