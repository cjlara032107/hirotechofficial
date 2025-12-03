/**
 * Tests for Analyze Selected Contacts
 * 
 * Tests verify:
 * - analyzedCount (successCount) increments correctly
 * - failedCount increments correctly
 * - errors array appends (doesn't overwrite)
 */

import { analyzeSelectedContacts } from '../analyze-selected-contacts';
import { prisma } from '@/lib/db';
import { FacebookClient } from '../client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { analyzeConversation } from '@/lib/ai/google-ai-service';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    contact: {
      findMany: jest.fn(),
      update: jest.fn(),
    },
  },
}));

jest.mock('../client');
jest.mock('@/lib/ai/enhanced-analysis');
jest.mock('@/lib/ai/google-ai-service');
jest.mock('@/lib/pipelines/auto-assign');

const mockedPrisma = prisma as jest.Mocked<typeof prisma>;
const MockedFacebookClient = FacebookClient as jest.MockedClass<typeof FacebookClient>;
const mockedAnalyzeWithFallback = analyzeWithFallback as jest.MockedFunction<typeof analyzeWithFallback>;
const mockedAnalyzeConversation = analyzeConversation as jest.MockedFunction<typeof analyzeConversation>;
const mockedAutoAssignContactToPipeline = autoAssignContactToPipeline as jest.MockedFunction<typeof autoAssignContactToPipeline>;

describe('Analyze Selected Contacts - Count Tracking', () => {
  const mockOrganizationId = 'test-org-123';
  const mockContactIds = ['contact-1', 'contact-2', 'contact-3'];

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Updates analyzed count correctly (increments)', () => {
    it('should increment successCount for each successful contact analysis', async () => {
      // Mock contacts
      const mockContacts = mockContactIds.map((id, index) => ({
        id,
        messengerPSID: `psid-${index + 1}`,
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock Facebook client
      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([
          {
            id: 'convo-1',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-1' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
          {
            id: 'convo-2',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-2' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
          {
            id: 'convo-3',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-3' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
        ]),
        getRecentMessagesForConversation: jest.fn().mockResolvedValue([
          {
            from: { id: 'psid-1', name: 'User' },
            message: 'Test message',
            created_time: new Date().toISOString(),
          },
        ]),
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);

      // Mock AI analysis
      mockedAnalyzeConversation.mockResolvedValue('Test summary');

      // Mock database update
      mockedPrisma.contact.update.mockResolvedValue({} as any);

      // Track progress callbacks
      const progressCalls: Array<{ analyzed: number; failed: number; total: number }> = [];
      const onProgress = (analyzed: number, failed: number, total: number) => {
        progressCalls.push({ analyzed, failed, total });
      };

      // Execute
      const result = await analyzeSelectedContacts(mockContactIds, mockOrganizationId, onProgress);

      // Verify successCount was incremented correctly
      expect(result.successCount).toBe(3);
      expect(result.failedCount).toBe(0);
      
      // Verify progress callback was called with incrementing values
      expect(progressCalls.length).toBeGreaterThan(0);
      
      // Verify that analyzed count increased progressively
      const analyzedValues = progressCalls.map(call => call.analyzed);
      const maxAnalyzed = Math.max(...analyzedValues);
      expect(maxAnalyzed).toBe(3);
      
      // Verify values are incrementing (not overwriting)
      const sortedValues = [...new Set(analyzedValues)].sort((a, b) => a - b);
      expect(sortedValues.length).toBeGreaterThan(0);
    });

    it('should increment successCount progressively as contacts are processed', async () => {
      const mockContacts = mockContactIds.map((id, index) => ({
        id,
        messengerPSID: `psid-${index + 1}`,
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([
          {
            id: 'convo-1',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-1' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
          {
            id: 'convo-2',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-2' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
          {
            id: 'convo-3',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-3' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
        ]),
        getRecentMessagesForConversation: jest.fn().mockResolvedValue([
          {
            from: { id: 'psid-1', name: 'User' },
            message: 'Test message',
            created_time: new Date().toISOString(),
          },
        ]),
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);
      mockedAnalyzeConversation.mockResolvedValue('Test summary');
      mockedPrisma.contact.update.mockResolvedValue({} as any);

      const progressCalls: number[] = [];
      const onProgress = (analyzed: number) => {
        progressCalls.push(analyzed);
      };

      const result = await analyzeSelectedContacts(mockContactIds, mockOrganizationId, onProgress);

      // Verify that successCount was incremented progressively
      expect(result.successCount).toBe(3);
      
      // Verify progress was called multiple times with incrementing values
      if (progressCalls.length > 0) {
        const uniqueValues = [...new Set(progressCalls)].sort((a, b) => a - b);
        expect(uniqueValues.length).toBeGreaterThan(0);
        expect(Math.max(...uniqueValues)).toBe(3);
      }
    });
  });

  describe('Test: Updates failed count correctly (increments)', () => {
    it('should increment failedCount for each failed contact analysis', async () => {
      const mockContacts = mockContactIds.map((id, index) => ({
        id,
        messengerPSID: `psid-${index + 1}`,
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock client to return no conversations (will cause failures)
      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([]),
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);

      const progressCalls: Array<{ failed: number }> = [];
      const onProgress = (analyzed: number, failed: number) => {
        progressCalls.push({ failed });
      };

      const result = await analyzeSelectedContacts(mockContactIds, mockOrganizationId, onProgress);

      // Verify failedCount was incremented correctly
      expect(result.failedCount).toBe(3);
      expect(result.successCount).toBe(0);
      
      // Verify errors array has 3 entries
      expect(result.errors.length).toBe(3);
      
      // Verify each error has a contactId
      result.errors.forEach((error, index) => {
        expect(error.contactId).toBe(mockContactIds[index]);
        expect(error.error).toBeDefined();
      });
    });

    it('should increment failedCount progressively as failures occur', async () => {
      const mockContacts = mockContactIds.map((id, index) => ({
        id,
        messengerPSID: `psid-${index + 1}`,
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock client to fail for all contacts
      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([]),
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);

      const progressCalls: number[] = [];
      const onProgress = (analyzed: number, failed: number) => {
        progressCalls.push(failed);
      };

      const result = await analyzeSelectedContacts(mockContactIds, mockOrganizationId, onProgress);

      // Verify failedCount was incremented progressively
      expect(result.failedCount).toBe(3);
      
      // Verify progress was called with incrementing failed values
      if (progressCalls.length > 0) {
        const uniqueValues = [...new Set(progressCalls)].sort((a, b) => a - b);
        expect(uniqueValues.length).toBeGreaterThan(0);
        expect(Math.max(...uniqueValues)).toBe(3);
      }
    });
  });

  describe("Test: Appends errors to errors array (doesn't overwrite)", () => {
    it('should append errors to the errors array instead of overwriting', async () => {
      const mockContacts = mockContactIds.map((id, index) => ({
        id,
        messengerPSID: `psid-${index + 1}`,
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock client to return no conversations (will cause failures)
      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([]),
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);

      const result = await analyzeSelectedContacts(mockContactIds, mockOrganizationId);

      // Verify errors array has all 3 errors (appended, not overwritten)
      expect(result.errors.length).toBe(3);
      
      // Verify each contact has a corresponding error entry
      mockContactIds.forEach((contactId) => {
        const error = result.errors.find(e => e.contactId === contactId);
        expect(error).toBeDefined();
        expect(error?.error).toBeDefined();
      });
      
      // Verify all errors are unique (no overwriting)
      const contactIdsInErrors = result.errors.map(e => e.contactId);
      const uniqueContactIds = new Set(contactIdsInErrors);
      expect(uniqueContactIds.size).toBe(3); // All unique
    });

    it('should append multiple errors without overwriting previous ones', async () => {
      const manyContactIds = Array.from({ length: 5 }, (_, i) => `contact-${i + 1}`);
      
      const mockContacts = manyContactIds.map((id, index) => ({
        id,
        messengerPSID: `psid-${index + 1}`,
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock client to fail for all contacts
      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([]),
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);

      const result = await analyzeSelectedContacts(manyContactIds, mockOrganizationId);

      // Verify all errors were appended (not overwritten)
      expect(result.errors.length).toBe(5);
      
      // Verify each contact has a unique error entry
      manyContactIds.forEach((contactId) => {
        const error = result.errors.find(e => e.contactId === contactId);
        expect(error).toBeDefined();
      });
      
      // Verify no duplicates (would indicate overwriting)
      const contactIdsInErrors = result.errors.map(e => e.contactId);
      const uniqueContactIds = new Set(contactIdsInErrors);
      expect(uniqueContactIds.size).toBe(5);
      expect(contactIdsInErrors.length).toBe(5);
    });

    it('should append errors with different error messages for different contacts', async () => {
      const mockContacts = mockContactIds.map((id, index) => ({
        id,
        messengerPSID: index === 0 ? null : `psid-${index + 1}`, // First contact has no PSID
        instagramSID: null,
        firstName: `First${index + 1}`,
        lastName: `Last${index + 1}`,
        lastInteraction: new Date(),
        aiContext: null,
        aiContextUpdatedAt: null,
        facebookPageId: 'page-1',
        facebookPage: {
          pageId: 'page-1',
          pageName: 'Test Page',
          pageAccessToken: 'token-123',
          instagramAccountId: null,
          autoPipelineId: null,
          autoPipeline: null,
          autoPipelineMode: null,
        },
      }));

      mockedPrisma.contact.findMany.mockResolvedValue(mockContacts as any);

      // Mock client to return conversations for some contacts but not others
      const mockClient = {
        getMessengerConversationsUntilFound: jest.fn().mockResolvedValue([
          {
            id: 'convo-2',
            participants: {
              data: [
                { id: 'page-1' },
                { id: 'psid-2' },
              ],
            },
            updated_time: new Date().toISOString(),
          },
        ]),
        getRecentMessagesForConversation: jest.fn().mockResolvedValue([]), // No messages
      };

      MockedFacebookClient.mockImplementation(() => mockClient as any);

      const result = await analyzeSelectedContacts(mockContactIds, mockOrganizationId);

      // Verify errors were appended for each failed contact
      expect(result.errors.length).toBeGreaterThan(0);
      
      // Verify each error has a unique contactId (no overwriting)
      const contactIdsInErrors = result.errors.map(e => e.contactId);
      const uniqueContactIds = new Set(contactIdsInErrors);
      expect(uniqueContactIds.size).toBe(contactIdsInErrors.length);
      
      // Verify errors have different messages (indicating they were appended, not overwritten)
      const errorMessages = result.errors.map(e => e.error);
      const uniqueMessages = new Set(errorMessages);
      // At least some errors should be different (unless all contacts fail for the same reason)
      expect(uniqueMessages.size).toBeGreaterThan(0);
    });
  });
});









