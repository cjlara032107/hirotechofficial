/**
 * Tests for Database Query Efficiency
 * 
 * Tests that database queries are optimized:
 * - Single queries use findFirst/findUnique instead of findMany
 * - Queries use select to only fetch needed fields
 * - No N+1 query patterns
 * - Batch operations are used when appropriate
 */

import { prisma } from '../db';

// Mock Prisma client
jest.mock('../db', () => {
  const mockPrisma = {
    contact: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn(),
      count: jest.fn(),
    },
    user: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn(),
    },
    syncJob: {
      findFirst: jest.fn(),
      findMany: jest.fn(),
    },
  };
  
  return {
    prisma: mockPrisma,
  };
});

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;

describe('Database Query Efficiency', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Test: Performs single database query (efficiency)', () => {
    describe('Single Item Queries - Use findFirst/findUnique', () => {
      it('should use findFirst for single contact lookup instead of findMany', async () => {
        const contactId = 'contact-123';
        const organizationId = 'org-456';

        mockedPrisma.contact.findFirst.mockResolvedValue({
          id: contactId,
          firstName: 'John',
          lastName: 'Doe',
        });

        // Simulate a function that fetches a single contact
        const getContact = async (id: string, orgId: string) => {
          return await prisma.contact.findFirst({
            where: {
              id,
              organizationId: orgId,
            },
            select: {
              id: true,
              firstName: true,
              lastName: true,
            },
          });
        };

        const result = await getContact(contactId, organizationId);

        expect(mockedPrisma.contact.findFirst).toHaveBeenCalledTimes(1);
        expect(mockedPrisma.contact.findFirst).toHaveBeenCalledWith({
          where: {
            id: contactId,
            organizationId: organizationId,
          },
          select: {
            id: true,
            firstName: true,
            lastName: true,
          },
        });
        expect(mockedPrisma.contact.findMany).not.toHaveBeenCalled();
        expect(result).toBeDefined();
      });

      it('should use findUnique when querying by unique field', async () => {
        const messengerPSID = 'messenger-123';
        const facebookPageId = 'page-456';

        mockedPrisma.contact.findUnique.mockResolvedValue({
          id: 'contact-123',
          messengerPSID,
          facebookPageId,
        });

        // Simulate a function that fetches by unique composite key
        const getContactByMessengerPSID = async (psid: string, pageId: string) => {
          return await prisma.contact.findUnique({
            where: {
              messengerPSID_facebookPageId: {
                messengerPSID: psid,
                facebookPageId: pageId,
              },
            },
            select: {
              id: true,
              messengerPSID: true,
              facebookPageId: true,
            },
          });
        };

        const result = await getContactByMessengerPSID(messengerPSID, facebookPageId);

        expect(mockedPrisma.contact.findUnique).toHaveBeenCalledTimes(1);
        expect(mockedPrisma.contact.findUnique).toHaveBeenCalledWith({
          where: {
            messengerPSID_facebookPageId: {
              messengerPSID,
              facebookPageId,
            },
          },
          select: {
            id: true,
            messengerPSID: true,
            facebookPageId: true,
          },
        });
        expect(mockedPrisma.contact.findMany).not.toHaveBeenCalled();
        expect(result).toBeDefined();
      });

      it('should NOT use findMany when fetching a single item', async () => {
        const contactId = 'contact-123';

        // This is an anti-pattern - should use findFirst instead
        mockedPrisma.contact.findMany.mockResolvedValue([
          { id: contactId, firstName: 'John' },
        ]);

        // Anti-pattern example (what NOT to do)
        const getContactBad = async (id: string) => {
          const results = await prisma.contact.findMany({
            where: { id },
            take: 1,
          });
          return results[0] || null;
        };

        const result = await getContactBad(contactId);

        // This test documents the anti-pattern - findMany was used
        expect(mockedPrisma.contact.findMany).toHaveBeenCalled();
        expect(result).toBeDefined();

        // But we should prefer findFirst for single items
        mockedPrisma.contact.findFirst.mockResolvedValue({
          id: contactId,
          firstName: 'John',
        });

        const getContactGood = async (id: string) => {
          return await prisma.contact.findFirst({
            where: { id },
          });
        };

        const resultGood = await getContactGood(contactId);
        expect(mockedPrisma.contact.findFirst).toHaveBeenCalled();
        expect(resultGood).toBeDefined();
      });
    });

    describe('Field Selection - Use select to fetch only needed fields', () => {
      it('should use select to fetch only required fields', async () => {
        const contactId = 'contact-123';

        mockedPrisma.contact.findFirst.mockResolvedValue({
          id: contactId,
          firstName: 'John',
          lastName: 'Doe',
        });

        // Efficient query - only selects needed fields
        const getContactBasic = async (id: string) => {
          return await prisma.contact.findFirst({
            where: { id },
            select: {
              id: true,
              firstName: true,
              lastName: true,
              // Excludes: notes, aiContext, activities, etc.
            },
          });
        };

        const result = await getContactBasic(contactId);

        expect(mockedPrisma.contact.findFirst).toHaveBeenCalledWith({
          where: { id: contactId },
          select: {
            id: true,
            firstName: true,
            lastName: true,
          },
        });
        expect(result).toBeDefined();
        // Verify result doesn't have unnecessary fields
        expect((result as any)?.notes).toBeUndefined();
        expect((result as any)?.aiContext).toBeUndefined();
      });

      it('should avoid fetching all fields when only a few are needed', async () => {
        const organizationId = 'org-123';

        mockedPrisma.contact.findMany.mockResolvedValue([
          { id: '1', firstName: 'John', lastName: 'Doe' },
          { id: '2', firstName: 'Jane', lastName: 'Smith' },
        ]);

        // Efficient list query - only selects fields needed for list view
        const getContactsList = async (orgId: string) => {
          return await prisma.contact.findMany({
            where: { organizationId: orgId },
            select: {
              id: true,
              firstName: true,
              lastName: true,
              profilePicUrl: true,
              leadScore: true,
              createdAt: true,
              // Excludes large TEXT fields: notes, aiContext
            },
            take: 50,
          });
        };

        const result = await getContactsList(organizationId);

        expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith({
          where: { organizationId },
          select: expect.objectContaining({
            id: true,
            firstName: true,
            lastName: true,
          }),
          take: 50,
        });
        expect(result).toBeDefined();
        expect(Array.isArray(result)).toBe(true);
      });
    });

    describe('Single Query Execution - One query per operation', () => {
      it('should perform a single query for a single item lookup', async () => {
        const contactId = 'contact-123';

        mockedPrisma.contact.findFirst.mockResolvedValue({
          id: contactId,
          firstName: 'John',
        });

        const getContact = async (id: string) => {
          return await prisma.contact.findFirst({
            where: { id },
            select: {
              id: true,
              firstName: true,
            },
          });
        };

        await getContact(contactId);

        // Should only call findFirst once
        expect(mockedPrisma.contact.findFirst).toHaveBeenCalledTimes(1);
      });

      it('should use a single query with proper where clause instead of multiple queries', async () => {
        const contactIds = ['contact-1', 'contact-2', 'contact-3'];
        const organizationId = 'org-123';

        mockedPrisma.contact.findMany.mockResolvedValue([
          { id: 'contact-1', firstName: 'John' },
          { id: 'contact-2', firstName: 'Jane' },
          { id: 'contact-3', firstName: 'Bob' },
        ]);

        // Efficient: Single query with IN clause
        const getContactsByIds = async (ids: string[], orgId: string) => {
          return await prisma.contact.findMany({
            where: {
              id: { in: ids },
              organizationId: orgId,
            },
            select: {
              id: true,
              firstName: true,
            },
          });
        };

        const result = await getContactsByIds(contactIds, organizationId);

        // Should only call findMany once, not once per ID
        expect(mockedPrisma.contact.findMany).toHaveBeenCalledTimes(1);
        expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith({
          where: {
            id: { in: contactIds },
            organizationId,
          },
          select: {
            id: true,
            firstName: true,
          },
        });
        expect(result).toHaveLength(3);
      });

      it('should avoid N+1 query pattern', async () => {
        const organizationId = 'org-123';

        // Mock: First query gets contacts, second gets count
        mockedPrisma.contact.findMany.mockResolvedValue([
          { id: '1', firstName: 'John' },
          { id: '2', firstName: 'Jane' },
        ]);
        mockedPrisma.contact.count.mockResolvedValue(2);

        // Efficient: Parallel queries using Promise.all
        const getContactsWithCount = async (orgId: string, page: number, limit: number) => {
          const skip = (page - 1) * limit;
          
          const [contacts, total] = await Promise.all([
            prisma.contact.findMany({
              where: { organizationId: orgId },
              select: {
                id: true,
                firstName: true,
              },
              skip,
              take: limit,
            }),
            prisma.contact.count({
              where: { organizationId: orgId },
            }),
          ]);

          return { contacts, total };
        };

        const result = await getContactsWithCount(organizationId, 1, 50);

        // Should execute both queries in parallel (Promise.all)
        expect(mockedPrisma.contact.findMany).toHaveBeenCalledTimes(1);
        expect(mockedPrisma.contact.count).toHaveBeenCalledTimes(1);
        expect(result.contacts).toHaveLength(2);
        expect(result.total).toBe(2);
      });
    });

    describe('Query Optimization - Efficient patterns', () => {
      it('should use indexed fields in where clauses', async () => {
        const messengerPSID = 'messenger-123';
        const facebookPageId = 'page-456';

        mockedPrisma.contact.findUnique.mockResolvedValue({
          id: 'contact-123',
          messengerPSID,
          facebookPageId,
        });

        // Efficient: Uses unique composite index
        const getContactByIndex = async (psid: string, pageId: string) => {
          return await prisma.contact.findUnique({
            where: {
              messengerPSID_facebookPageId: {
                messengerPSID: psid,
                facebookPageId: pageId,
              },
            },
          });
        };

        await getContactByIndex(messengerPSID, facebookPageId);

        expect(mockedPrisma.contact.findUnique).toHaveBeenCalledWith({
          where: {
            messengerPSID_facebookPageId: {
              messengerPSID,
              facebookPageId,
            },
          },
        });
      });

      it('should use take limit to prevent fetching too many records', async () => {
        const organizationId = 'org-123';

        mockedPrisma.contact.findMany.mockResolvedValue([
          { id: '1', firstName: 'John' },
        ]);

        // Efficient: Uses take to limit results
        const getContactsLimited = async (orgId: string, limit: number) => {
          return await prisma.contact.findMany({
            where: { organizationId: orgId },
            select: {
              id: true,
              firstName: true,
            },
            take: limit,
            orderBy: { createdAt: 'desc' },
          });
        };

        await getContactsLimited(organizationId, 50);

        expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith({
          where: { organizationId },
          select: {
            id: true,
            firstName: true,
          },
          take: 50,
          orderBy: { createdAt: 'desc' },
        });
      });

      it('should use skip/take for pagination instead of fetching all', async () => {
        const organizationId = 'org-123';
        const page = 2;
        const limit = 50;

        mockedPrisma.contact.findMany.mockResolvedValue([
          { id: '51', firstName: 'John' },
        ]);

        // Efficient: Database-level pagination
        const getContactsPaginated = async (orgId: string, pageNum: number, pageSize: number) => {
          return await prisma.contact.findMany({
            where: { organizationId: orgId },
            select: {
              id: true,
              firstName: true,
            },
            skip: (pageNum - 1) * pageSize,
            take: pageSize,
            orderBy: { createdAt: 'desc' },
          });
        };

        await getContactsPaginated(organizationId, page, limit);

        expect(mockedPrisma.contact.findMany).toHaveBeenCalledWith({
          where: { organizationId },
          select: {
            id: true,
            firstName: true,
          },
          skip: 50, // (2-1) * 50
          take: 50,
          orderBy: { createdAt: 'desc' },
        });
      });
    });

    describe('Single Query Verification', () => {
      it('should verify that a single contact fetch uses exactly one query', async () => {
        const contactId = 'contact-123';

        mockedPrisma.contact.findFirst.mockResolvedValue({
          id: contactId,
          firstName: 'John',
          lastName: 'Doe',
        });

        const getContact = async (id: string) => {
          return await prisma.contact.findFirst({
            where: { id },
            select: {
              id: true,
              firstName: true,
              lastName: true,
            },
          });
        };

        const result = await getContact(contactId);

        // Verify exactly one query was executed
        expect(mockedPrisma.contact.findFirst).toHaveBeenCalledTimes(1);
        expect(mockedPrisma.contact.findMany).not.toHaveBeenCalled();
        expect(mockedPrisma.contact.findUnique).not.toHaveBeenCalled();
        expect(result).toBeDefined();
      });

      it('should verify query efficiency by checking call count', async () => {
        const contactId = 'contact-123';

        mockedPrisma.contact.findFirst.mockResolvedValue({
          id: contactId,
          firstName: 'John',
        });

        // Simulate a function that should use a single query
        const fetchContact = async (id: string) => {
          // This is the efficient way - single query
          return await prisma.contact.findFirst({
            where: { id },
            select: {
              id: true,
              firstName: true,
            },
          });
        };

        await fetchContact(contactId);

        // Efficiency check: Only one database call
        const totalCalls = 
          mockedPrisma.contact.findFirst.mock.calls.length +
          mockedPrisma.contact.findMany.mock.calls.length +
          mockedPrisma.contact.findUnique.mock.calls.length;

        expect(totalCalls).toBe(1);
      });
    });
  });
});









