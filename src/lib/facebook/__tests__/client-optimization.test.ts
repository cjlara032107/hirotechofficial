/**
 * Tests for FacebookClient optimization features:
 * - Request deduplication
 * - Conversation caching
 * - Batch API calls
 */

import { FacebookClient } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('FacebookClient Optimization Features', () => {
  const mockAccessToken = 'test-access-token';
  const mockPageId = 'test-page-id';
  let client: FacebookClient;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetAllMocks();
    mockedAxios.get.mockReset();
    mockedAxios.post.mockReset();
    client = new FacebookClient(mockAccessToken);
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Request Deduplication', () => {
    it('should deduplicate concurrent requests for the same conversation', async () => {
      const mockConversations = [
        {
          id: 'conv1',
          participants: { data: [{ id: 'user1' }] },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      // Make two concurrent requests for the same conversation
      const [result1, result2] = await Promise.all([
        client.getMessengerConversations(mockPageId),
        client.getMessengerConversations(mockPageId),
      ]);

      // Both should return the same data
      expect(result1).toEqual(mockConversations);
      expect(result2).toEqual(mockConversations);

      // Should only make one API call
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should deduplicate concurrent profile requests', async () => {
      const mockProfile = {
        first_name: 'John',
        last_name: 'Doe',
        profile_pic: 'https://example.com/pic.jpg',
      };

      mockedAxios.get.mockResolvedValueOnce({
        data: mockProfile,
      });

      const psid = 'test-psid';

      // Make two concurrent requests for the same profile
      const [result1, result2] = await Promise.all([
        client.getMessengerProfile(psid),
        client.getMessengerProfile(psid),
      ]);

      // Both should return the same data
      expect(result1).toEqual(mockProfile);
      expect(result2).toEqual(mockProfile);

      // Should only make one API call
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should handle errors in deduplicated requests correctly', async () => {
      const error = {
        response: {
          data: {
            error: {
              code: 190,
              type: 'OAuthException',
              message: 'Invalid access token',
            },
          },
        },
      };

      mockedAxios.get.mockRejectedValueOnce(error);

      const psid = 'test-psid';

      // Make two concurrent requests - both should fail with the same error
      const [promise1, promise2] = [
        client.getMessengerProfile(psid).catch((e) => e),
        client.getMessengerProfile(psid).catch((e) => e),
      ];

      const [error1, error2] = await Promise.all([promise1, promise2]);

      // Both should get the same error
      expect(error1.message).toContain('Invalid access token');
      expect(error2.message).toContain('Invalid access token');

      // Should only make one API call
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });
  });

  describe('Conversation Caching', () => {
    beforeEach(() => {
      // Clear cache before each test
      client.clearConversationCache();
    });

    it('should cache conversation results', async () => {
      const mockConversations = [
        {
          id: 'conv1',
          participants: { data: [{ id: 'user1' }] },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      // First request - should make API call
      const result1 = await client.getMessengerConversations(mockPageId);
      expect(result1).toEqual(mockConversations);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);

      // Second request - should use cache
      const result2 = await client.getMessengerConversations(mockPageId);
      expect(result2).toEqual(mockConversations);
      // Should still be only 1 API call (cached)
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should respect cache TTL', async () => {
      const mockConversations = [
        {
          id: 'conv1',
          participants: { data: [{ id: 'user1' }] },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValue({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      // First request
      await client.getMessengerConversations(mockPageId);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);

      // Mock Date.now to simulate time passing (6 minutes = cache expired)
      const originalNow = Date.now;
      jest.spyOn(Date, 'now').mockReturnValue(originalNow() + 6 * 60 * 1000);

      // Second request after cache expiry - should make new API call
      await client.getMessengerConversations(mockPageId);
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);

      Date.now = originalNow;
    });

    it('should allow bypassing cache', async () => {
      const mockConversations = [
        {
          id: 'conv1',
          participants: { data: [{ id: 'user1' }] },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValue({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      // First request with cache
      await client.getMessengerConversations(mockPageId, 100, true);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);

      // Second request bypassing cache
      await client.getMessengerConversations(mockPageId, 100, false);
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });

    it('should cache Instagram conversations separately', async () => {
      const mockMessengerConvos = [{ id: 'messenger-conv1' }];
      const mockInstagramConvos = [{ id: 'instagram-conv1' }];

      mockedAxios.get
        .mockResolvedValueOnce({
          data: { data: mockMessengerConvos, paging: {} },
        })
        .mockResolvedValueOnce({
          data: { data: mockInstagramConvos, paging: {} },
        });

      // Fetch Messenger conversations
      const messengerResult = await client.getMessengerConversations(mockPageId);
      expect(messengerResult).toEqual(mockMessengerConvos);

      // Fetch Instagram conversations
      const igAccountId = 'test-ig-account';
      const instagramResult = await client.getInstagramConversations(igAccountId);
      expect(instagramResult).toEqual(mockInstagramConvos);

      // Both should be cached separately
      const cachedMessenger = await client.getMessengerConversations(mockPageId);
      const cachedInstagram = await client.getInstagramConversations(igAccountId);

      expect(cachedMessenger).toEqual(mockMessengerConvos);
      expect(cachedInstagram).toEqual(mockInstagramConvos);

      // Should only have made 2 API calls total (one for each type)
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });
  });

  describe('Batch API Calls', () => {
    it('should batch Messenger profile requests', async () => {
      const psids = ['psid1', 'psid2', 'psid3'];
      const mockProfiles = [
        { first_name: 'John', last_name: 'Doe' },
        { first_name: 'Jane', last_name: 'Smith' },
        { first_name: 'Bob', last_name: 'Johnson' },
      ];

      // Mock batch response
      mockedAxios.post.mockResolvedValueOnce({
        data: [
          { code: 200, body: JSON.stringify(mockProfiles[0]) },
          { code: 200, body: JSON.stringify(mockProfiles[1]) },
          { code: 200, body: JSON.stringify(mockProfiles[2]) },
        ],
      });

      const results = await client.batchGetMessengerProfiles(psids);

      expect(results.size).toBe(3);
      expect(results.get('psid1')).toEqual(mockProfiles[0]);
      expect(results.get('psid2')).toEqual(mockProfiles[1]);
      expect(results.get('psid3')).toEqual(mockProfiles[2]);

      // Should make one batch request
      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    });

    it('should handle batches larger than 50 requests', async () => {
      const psids = Array.from({ length: 75 }, (_, i) => `psid${i}`);
      const mockProfiles = psids.map((_, i) => ({
        first_name: `User${i}`,
        last_name: 'Test',
      }));

      // Mock two batch responses (50 + 25)
      mockedAxios.post
        .mockResolvedValueOnce({
          data: Array.from({ length: 50 }, (_, i) => ({
            code: 200,
            body: JSON.stringify(mockProfiles[i]),
          })),
        })
        .mockResolvedValueOnce({
          data: Array.from({ length: 25 }, (_, i) => ({
            code: 200,
            body: JSON.stringify(mockProfiles[50 + i]),
          })),
        });

      const results = await client.batchGetMessengerProfiles(psids);

      expect(results.size).toBe(75);
      expect(mockedAxios.post).toHaveBeenCalledTimes(2);
    });

    it('should handle partial failures in batch requests', async () => {
      const psids = ['psid1', 'psid2', 'psid3'];
      const mockProfiles = [
        { first_name: 'John', last_name: 'Doe' },
        null, // Simulate failure
        { first_name: 'Bob', last_name: 'Johnson' },
      ];

      // Mock batch response with one failure
      mockedAxios.post.mockResolvedValueOnce({
        data: [
          { code: 200, body: JSON.stringify(mockProfiles[0]) },
          { code: 400, body: JSON.stringify({ error: 'Invalid user ID' }) },
          { code: 200, body: JSON.stringify(mockProfiles[2]) },
        ],
      });

      const results = await client.batchGetMessengerProfiles(psids);

      // Should only have 2 successful results
      expect(results.size).toBe(2);
      expect(results.get('psid1')).toEqual(mockProfiles[0]);
      expect(results.get('psid3')).toEqual(mockProfiles[2]);
      expect(results.has('psid2')).toBe(false);
    });

    it('should batch Instagram profile requests', async () => {
      const igUserIds = ['ig1', 'ig2', 'ig3'];
      const mockProfiles = [
        { name: 'User1', username: 'user1' },
        { name: 'User2', username: 'user2' },
        { name: 'User3', username: 'user3' },
      ];

      // Mock batch response
      mockedAxios.post.mockResolvedValueOnce({
        data: [
          { code: 200, body: JSON.stringify(mockProfiles[0]) },
          { code: 200, body: JSON.stringify(mockProfiles[1]) },
          { code: 200, body: JSON.stringify(mockProfiles[2]) },
        ],
      });

      const results = await client.batchGetInstagramProfiles(igUserIds);

      expect(results.size).toBe(3);
      expect(results.get('ig1')).toEqual(mockProfiles[0]);
      expect(results.get('ig2')).toEqual(mockProfiles[1]);
      expect(results.get('ig3')).toEqual(mockProfiles[2]);

      // Should make one batch request
      expect(mockedAxios.post).toHaveBeenCalledTimes(1);
    });

    it('should return empty map for empty input', async () => {
      const results = await client.batchGetMessengerProfiles([]);
      expect(results.size).toBe(0);
      expect(mockedAxios.post).not.toHaveBeenCalled();
    });
  });

  describe('Combined Features', () => {
    it('should use both caching and deduplication together', async () => {
      const mockConversations = [
        {
          id: 'conv1',
          participants: { data: [{ id: 'user1' }] },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });

      // First request - should make API call and cache
      const result1 = await client.getMessengerConversations(mockPageId);
      expect(result1).toEqual(mockConversations);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);

      // Second request - should use cache (no API call)
      const result2 = await client.getMessengerConversations(mockPageId);
      expect(result2).toEqual(mockConversations);
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);

      // Clear cache
      client.clearConversationCache(mockPageId, 'messenger');

      // Third request - should make new API call
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: mockConversations,
          paging: {},
        },
      });
      const result3 = await client.getMessengerConversations(mockPageId);
      expect(result3).toEqual(mockConversations);
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });
  });
});









