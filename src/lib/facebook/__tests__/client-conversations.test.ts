/**
 * Tests for FacebookClient conversation fetching methods
 * 
 * Tests the getMessengerConversations and getInstagramConversations methods to ensure:
 * - Fetches Messenger conversations successfully
 * - Fetches Instagram conversations successfully
 * - Returns empty arrays when no conversations found
 */

import { FacebookClient } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('FacebookClient - Conversation Fetching', () => {
  const mockAccessToken = 'test-access-token';
  const mockPageId = 'test-page-id-123';
  const mockIgAccountId = 'test-ig-account-id-456';
  let client: FacebookClient;

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console.log during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});

    client = new FacebookClient(mockAccessToken);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Fetches Messenger conversations successfully', () => {
    it('should fetch Messenger conversations with pagination', async () => {
      const mockConversationsPage1 = [
        {
          id: 'conv-1',
          participants: {
            data: [
              { id: 'user-1', name: 'User One' },
              { id: mockPageId, name: 'Page' },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
          message_count: 10,
        },
        {
          id: 'conv-2',
          participants: {
            data: [
              { id: 'user-2', name: 'User Two' },
              { id: mockPageId, name: 'Page' },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
          message_count: 5,
        },
      ];

      const mockConversationsPage2 = [
        {
          id: 'conv-3',
          participants: {
            data: [
              { id: 'user-3', name: 'User Three' },
              { id: mockPageId, name: 'Page' },
            ],
          },
          updated_time: '2024-01-03T00:00:00Z',
          message_count: 8,
        },
      ];

      // Mock first page response
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversationsPage1,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=next',
          },
        },
      });

      // Mock second page response (no next page)
      // Note: Second call uses nextUrl directly, not with params
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversationsPage2,
          paging: {},
        },
      });

      const result = await client.getMessengerConversations(mockPageId);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('conv-1');
      expect(result[1].id).toBe('conv-2');
      expect(result[2].id).toBe('conv-3');
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
      
      // Verify first call
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        1,
        `https://graph.facebook.com/v19.0/${mockPageId}/conversations`,
        {
          params: {
            access_token: mockAccessToken,
            fields: 'id,participants,updated_time,message_count',
            limit: 100,
          },
        }
      );
      
      // Verify second call uses nextUrl directly with timeout
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        2,
        'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=next',
        {
          timeout: 30000,
        }
      );
    });

    it('should fetch Messenger conversations with single page (no pagination)', async () => {
      const mockConversations = [
        {
          id: 'conv-1',
          participants: {
            data: [
              { id: 'user-1', name: 'User One' },
              { id: mockPageId, name: 'Page' },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
          message_count: 10,
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      const result = await client.getMessengerConversations(mockPageId);

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('conv-1');
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should handle custom limit parameter', async () => {
      const mockConversations = [
        {
          id: 'conv-1',
          participants: {
            data: [
              { id: 'user-1', name: 'User One' },
              { id: mockPageId, name: 'Page' },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
          message_count: 10,
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      await client.getMessengerConversations(mockPageId, 50);

      expect(mockedAxios.get).toHaveBeenCalledWith(
        `https://graph.facebook.com/v19.0/${mockPageId}/conversations`,
        {
          params: {
            access_token: mockAccessToken,
            fields: 'id,participants,updated_time,message_count',
            limit: 50,
          },
        }
      );
    });
  });

  describe('Test: Fetches Instagram conversations successfully', () => {
    it('should fetch Instagram conversations with pagination', async () => {
      const mockConversationsPage1 = [
        {
          id: 'ig-conv-1',
          participants: {
            data: [
              { id: 'ig-user-1', name: 'IG User One' },
              { id: mockIgAccountId, name: 'IG Account' },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
          message_count: 15,
        },
        {
          id: 'ig-conv-2',
          participants: {
            data: [
              { id: 'ig-user-2', name: 'IG User Two' },
              { id: mockIgAccountId, name: 'IG Account' },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
          message_count: 7,
        },
      ];

      const mockConversationsPage2 = [
        {
          id: 'ig-conv-3',
          participants: {
            data: [
              { id: 'ig-user-3', name: 'IG User Three' },
              { id: mockIgAccountId, name: 'IG Account' },
            ],
          },
          updated_time: '2024-01-03T00:00:00Z',
          message_count: 12,
        },
      ];

      // Mock first page response
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversationsPage1,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id-456/conversations?paging_token=next',
          },
        },
      });

      // Mock second page response (no next page)
      // Note: Second call uses nextUrl directly, not with params
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversationsPage2,
          paging: {},
        },
      });

      const result = await client.getInstagramConversations(mockIgAccountId);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('ig-conv-1');
      expect(result[1].id).toBe('ig-conv-2');
      expect(result[2].id).toBe('ig-conv-3');
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
      
      // Verify first call
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        1,
        `https://graph.facebook.com/v19.0/${mockIgAccountId}/conversations`,
        {
          params: {
            access_token: mockAccessToken,
            fields: 'id,participants,updated_time,message_count',
            limit: 100,
          },
        }
      );
      
      // Verify second call uses nextUrl directly with timeout
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        2,
        'https://graph.facebook.com/v19.0/test-ig-account-id-456/conversations?paging_token=next',
        {
          timeout: 30000,
        }
      );
    });

    it('should fetch Instagram conversations with single page (no pagination)', async () => {
      const mockConversations = [
        {
          id: 'ig-conv-1',
          participants: {
            data: [
              { id: 'ig-user-1', name: 'IG User One' },
              { id: mockIgAccountId, name: 'IG Account' },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
          message_count: 15,
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      const result = await client.getInstagramConversations(mockIgAccountId);

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('ig-conv-1');
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should handle custom limit parameter', async () => {
      const mockConversations = [
        {
          id: 'ig-conv-1',
          participants: {
            data: [
              { id: 'ig-user-1', name: 'IG User One' },
              { id: mockIgAccountId, name: 'IG Account' },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
          message_count: 15,
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      await client.getInstagramConversations(mockIgAccountId, 50);

      expect(mockedAxios.get).toHaveBeenCalledWith(
        `https://graph.facebook.com/v19.0/${mockIgAccountId}/conversations`,
        {
          params: {
            access_token: mockAccessToken,
            fields: 'id,participants,updated_time,message_count',
            limit: 50,
          },
        }
      );
    });
  });

  describe('Test: Returns empty arrays when no conversations found', () => {
    it('should return empty array when Messenger API returns no conversations', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {},
        },
      });

      const result = await client.getMessengerConversations(mockPageId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should return empty array when Messenger API returns null data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: null,
          paging: {},
        },
      });

      const result = await client.getMessengerConversations(mockPageId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when Messenger API returns undefined data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          paging: {},
        },
      });

      const result = await client.getMessengerConversations(mockPageId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when Instagram API returns no conversations', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {},
        },
      });

      const result = await client.getInstagramConversations(mockIgAccountId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should return empty array when Instagram API returns null data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: null,
          paging: {},
        },
      });

      const result = await client.getInstagramConversations(mockIgAccountId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when Instagram API returns undefined data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          paging: {},
        },
      });

      const result = await client.getInstagramConversations(mockIgAccountId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when Messenger pagination returns empty pages', async () => {
      // First page returns empty array with next page
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=next',
          },
        },
      });

      // Second page also returns empty array
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {},
        },
      });

      const result = await client.getMessengerConversations(mockPageId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when Instagram pagination returns empty pages', async () => {
      // First page returns empty array with next page
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id-456/conversations?paging_token=next',
          },
        },
      });

      // Second page also returns empty array
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {},
        },
      });

      const result = await client.getInstagramConversations(mockIgAccountId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });
  });
});

