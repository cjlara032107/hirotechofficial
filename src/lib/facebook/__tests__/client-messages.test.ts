/**
 * Tests for FacebookClient message extraction methods
 * 
 * Tests ensure:
 * - Extracts messages from Messenger conversation
 * - Extracts messages from Instagram conversation
 * - Returns empty array when conversation has no messages
 */

import { FacebookClient } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('FacebookClient - Message Extraction', () => {
  const mockAccessToken = 'test-access-token';
  const mockMessengerConversationId = 'messenger-conv-123';
  const mockInstagramConversationId = 'instagram-conv-456';
  let client: FacebookClient;

  beforeEach(() => {
    jest.clearAllMocks();
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});

    client = new FacebookClient(mockAccessToken);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Extracts messages from Messenger conversation', () => {
    it('should extract messages from Messenger conversation with single page', async () => {
      const mockMessages = [
        {
          id: 'msg-1',
          from: {
            id: 'user-123',
            name: 'John Doe',
          },
          message: 'Hello, I am interested in your product.',
          created_time: '2024-01-01T10:00:00+0000',
        },
        {
          id: 'msg-2',
          from: {
            id: 'page-456',
            name: 'Business Page',
          },
          message: 'Thank you for your interest!',
          created_time: '2024-01-01T10:05:00+0000',
        },
        {
          id: 'msg-3',
          from: {
            id: 'user-123',
            name: 'John Doe',
          },
          message: 'Can you tell me more about pricing?',
          created_time: '2024-01-01T10:10:00+0000',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessages,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('msg-1');
      expect(result[0].message).toBe('Hello, I am interested in your product.');
      expect(result[0].from.id).toBe('user-123');
      expect(result[0].from.name).toBe('John Doe');
      expect(result[1].id).toBe('msg-2');
      expect(result[2].id).toBe('msg-3');
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
      
      // Verify API call
      expect(mockedAxios.get).toHaveBeenCalledWith(
        `https://graph.facebook.com/v19.0/${mockMessengerConversationId}/messages`,
        {
          params: {
            access_token: mockAccessToken,
            fields: 'from,message,created_time',
            limit: 100,
          },
          timeout: 30000,
        }
      );
    });

    it('should extract messages from Messenger conversation with pagination', async () => {
      const mockMessagesPage1 = [
        {
          id: 'msg-1',
          from: {
            id: 'user-123',
            name: 'John Doe',
          },
          message: 'First message',
          created_time: '2024-01-01T10:00:00+0000',
        },
        {
          id: 'msg-2',
          from: {
            id: 'page-456',
            name: 'Business Page',
          },
          message: 'Second message',
          created_time: '2024-01-01T10:05:00+0000',
        },
      ];

      const mockMessagesPage2 = [
        {
          id: 'msg-3',
          from: {
            id: 'user-123',
            name: 'John Doe',
          },
          message: 'Third message',
          created_time: '2024-01-01T10:10:00+0000',
        },
      ];

      const nextPageUrl = `https://graph.facebook.com/v19.0/${mockMessengerConversationId}/messages?after=cursor`;

      // Mock first page response
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessagesPage1,
          paging: {
            next: nextPageUrl,
          },
        },
      });

      // Mock second page response (no next page)
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessagesPage2,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('msg-1');
      expect(result[1].id).toBe('msg-2');
      expect(result[2].id).toBe('msg-3');
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
      
      // Verify first call uses base URL with params
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        1,
        `https://graph.facebook.com/v19.0/${mockMessengerConversationId}/messages`,
        expect.objectContaining({
          params: expect.objectContaining({
            access_token: mockAccessToken,
            fields: 'from,message,created_time',
            limit: 100,
          }),
          timeout: 30000,
        })
      );
      
      // Verify second call uses pagination URL
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        2,
        nextPageUrl,
        expect.objectContaining({
          params: expect.objectContaining({
            access_token: mockAccessToken,
            fields: 'from,message,created_time',
            limit: 100,
          }),
          timeout: 30000,
        })
      );
    });

    it('should extract messages with correct structure from Messenger conversation', async () => {
      const mockMessages = [
        {
          id: 'msg-1',
          from: {
            id: 'user-123',
            name: 'John Doe',
          },
          message: 'Test message',
          created_time: '2024-01-01T10:00:00+0000',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessages,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toHaveLength(1);
      expect(result[0]).toHaveProperty('id');
      expect(result[0]).toHaveProperty('from');
      expect(result[0]).toHaveProperty('message');
      expect(result[0]).toHaveProperty('created_time');
      expect(result[0].from).toHaveProperty('id');
      expect(result[0].from).toHaveProperty('name');
    });
  });

  describe('Test: Extracts messages from Instagram conversation', () => {
    it('should extract messages from Instagram conversation with single page', async () => {
      const mockMessages = [
        {
          id: 'ig-msg-1',
          from: {
            id: 'ig-user-123',
            name: 'Jane Smith',
          },
          message: 'Hi, I saw your post!',
          created_time: '2024-01-01T11:00:00+0000',
        },
        {
          id: 'ig-msg-2',
          from: {
            id: 'ig-account-456',
            name: 'Business Account',
          },
          message: 'Thanks for reaching out!',
          created_time: '2024-01-01T11:05:00+0000',
        },
        {
          id: 'ig-msg-3',
          from: {
            id: 'ig-user-123',
            name: 'Jane Smith',
          },
          message: 'I would like to know more.',
          created_time: '2024-01-01T11:10:00+0000',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessages,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockInstagramConversationId);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('ig-msg-1');
      expect(result[0].message).toBe('Hi, I saw your post!');
      expect(result[0].from.id).toBe('ig-user-123');
      expect(result[0].from.name).toBe('Jane Smith');
      expect(result[1].id).toBe('ig-msg-2');
      expect(result[2].id).toBe('ig-msg-3');
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
      
      // Verify API call
      expect(mockedAxios.get).toHaveBeenCalledWith(
        `https://graph.facebook.com/v19.0/${mockInstagramConversationId}/messages`,
        {
          params: {
            access_token: mockAccessToken,
            fields: 'from,message,created_time',
            limit: 100,
          },
          timeout: 30000,
        }
      );
    });

    it('should extract messages from Instagram conversation with pagination', async () => {
      const mockMessagesPage1 = [
        {
          id: 'ig-msg-1',
          from: {
            id: 'ig-user-123',
            name: 'Jane Smith',
          },
          message: 'First Instagram message',
          created_time: '2024-01-01T11:00:00+0000',
        },
        {
          id: 'ig-msg-2',
          from: {
            id: 'ig-account-456',
            name: 'Business Account',
          },
          message: 'Second Instagram message',
          created_time: '2024-01-01T11:05:00+0000',
        },
      ];

      const mockMessagesPage2 = [
        {
          id: 'ig-msg-3',
          from: {
            id: 'ig-user-123',
            name: 'Jane Smith',
          },
          message: 'Third Instagram message',
          created_time: '2024-01-01T11:10:00+0000',
        },
      ];

      const nextPageUrl = `https://graph.facebook.com/v19.0/${mockInstagramConversationId}/messages?after=cursor`;

      // Mock first page response
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessagesPage1,
          paging: {
            next: nextPageUrl,
          },
        },
      });

      // Mock second page response (no next page)
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessagesPage2,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockInstagramConversationId);

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('ig-msg-1');
      expect(result[1].id).toBe('ig-msg-2');
      expect(result[2].id).toBe('ig-msg-3');
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
      
      // Verify first call uses base URL with params
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        1,
        `https://graph.facebook.com/v19.0/${mockInstagramConversationId}/messages`,
        expect.objectContaining({
          params: expect.objectContaining({
            access_token: mockAccessToken,
            fields: 'from,message,created_time',
            limit: 100,
          }),
          timeout: 30000,
        })
      );
      
      // Verify second call uses pagination URL
      expect(mockedAxios.get).toHaveBeenNthCalledWith(
        2,
        nextPageUrl,
        expect.objectContaining({
          params: expect.objectContaining({
            access_token: mockAccessToken,
            fields: 'from,message,created_time',
            limit: 100,
          }),
          timeout: 30000,
        })
      );
    });

    it('should extract messages with correct structure from Instagram conversation', async () => {
      const mockMessages = [
        {
          id: 'ig-msg-1',
          from: {
            id: 'ig-user-123',
            name: 'Jane Smith',
          },
          message: 'Test Instagram message',
          created_time: '2024-01-01T11:00:00+0000',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockMessages,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockInstagramConversationId);

      expect(result).toHaveLength(1);
      expect(result[0]).toHaveProperty('id');
      expect(result[0]).toHaveProperty('from');
      expect(result[0]).toHaveProperty('message');
      expect(result[0]).toHaveProperty('created_time');
      expect(result[0].from).toHaveProperty('id');
      expect(result[0].from).toHaveProperty('name');
    });
  });

  describe('Test: Returns empty array when conversation has no messages', () => {
    it('should return empty array when API returns no messages', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should return empty array when API returns null data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: null,
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when API returns undefined data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array for Instagram conversation with no messages', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {},
        },
      });

      const result = await client.getAllMessagesForConversation(mockInstagramConversationId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should return empty array when pagination returns empty pages', async () => {
      // First page returns empty array with next page
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {
            next: `https://graph.facebook.com/v19.0/${mockMessengerConversationId}/messages?after=cursor`,
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

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when error occurs and no messages were fetched', async () => {
      // Mock error on first request
      const apiError = {
        response: {
          data: {
            error: {
              code: 100,
              type: 'OAuthException',
              message: 'Invalid parameter',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(apiError);

      const result = await client.getAllMessagesForConversation(mockMessengerConversationId);

      // Should return empty array (allMessages starts as empty, catch block returns it)
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
      expect(Array.isArray(result)).toBe(true);
    });
  });
});

