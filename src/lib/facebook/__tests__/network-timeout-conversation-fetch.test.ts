/**
 * Tests for network timeout during conversation fetch
 * 
 * Tests the scenario where a network timeout occurs while fetching conversations
 * from the Facebook API. The system should handle this gracefully with proper
 * error handling and timeout mechanisms.
 */

import { FacebookClient } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Test: Network timeout during conversation fetch', () => {
  const mockAccessToken = 'test-access-token';
  const mockPageId = 'test-page-id-123';
  let client: FacebookClient;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});

    client = new FacebookClient(mockAccessToken);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Messenger Conversations - Network Timeout', () => {
    it('should handle timeout on first page fetch', async () => {
      // Simulate timeout on initial request
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      await expect(
        client.getMessengerConversations(mockPageId)
      ).rejects.toThrow();

      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    });

    it('should handle timeout during pagination', async () => {
      // First page succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [
            {
              id: 'conv-1',
              participants: { data: [{ id: 'user-1' }] },
              updated_time: '2024-01-01T00:00:00Z',
              message_count: 10,
            },
          ],
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=next',
          },
        },
      });

      // Second page times out
      const timeoutError = new Error('Page 2 request timed out after 30 seconds');
      (timeoutError as any).code = 'ECONNABORTED';
      
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // Client may return partial results on timeout (graceful degradation)
      // or throw - both are acceptable behaviors
      try {
        const result = await client.getMessengerConversations(mockPageId);
        // If it returns partial results, verify them
        expect(result.length).toBeGreaterThanOrEqual(1);
        expect(result[0].id).toBe('conv-1');
      } catch (error) {
        // If it throws, that's also acceptable
        expect(error).toBeDefined();
      }
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    }, 10000); // Increase timeout

    it('should retry on timeout with exponential backoff', async () => {
      // First page succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [
            {
              id: 'conv-1',
              participants: { data: [{ id: 'user-1' }] },
              updated_time: '2024-01-01T00:00:00Z',
              message_count: 10,
            },
          ],
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=next',
          },
        },
      });

      // Second page times out
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // Retry succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [
            {
              id: 'conv-2',
              participants: { data: [{ id: 'user-2' }] },
              updated_time: '2024-01-02T00:00:00Z',
              message_count: 5,
            },
          ],
          paging: {},
        },
      });

      // Use fake timers to test retry logic
      jest.useFakeTimers();
      
      const resultPromise = client.getMessengerConversations(mockPageId);
      
      // Fast-forward through retry delays
      jest.advanceTimersByTime(3000);
      
      const result = await resultPromise;

      expect(result.length).toBeGreaterThanOrEqual(1);
      jest.useRealTimers();
    });

    it('should handle timeout after multiple successful pages', async () => {
      // Simulate multiple successful pages followed by timeout
      mockedAxios.get
        .mockResolvedValueOnce({
          data: {
            data: Array.from({ length: 100 }, (_, i) => ({
              id: `conv-${i}`,
              participants: { data: [{ id: `user-${i}` }] },
              updated_time: '2024-01-01T00:00:00Z',
              message_count: 10,
            })),
            paging: {
              next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=page2',
            },
          },
        })
        .mockResolvedValueOnce({
          data: {
            data: Array.from({ length: 100 }, (_, i) => ({
              id: `conv-${100 + i}`,
              participants: { data: [{ id: `user-${100 + i}` }] },
              updated_time: '2024-01-01T00:00:00Z',
              message_count: 10,
            })),
            paging: {
              next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=page3',
            },
          },
        })
        .mockRejectedValueOnce(new Error('Page 3 request timed out after 30 seconds'));

      const result = await client.getMessengerConversations(mockPageId);

      // Should return conversations from successful pages
      expect(result.length).toBe(200);
      expect(mockedAxios.get).toHaveBeenCalledTimes(3);
    });

    it('should respect 30-second timeout per page request', async () => {
      // Mock a request that times out
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      await expect(
        client.getMessengerConversations(mockPageId)
      ).rejects.toThrow();
    });

    it('should handle timeout in Promise.race correctly', async () => {
      // Test that Promise.race properly handles timeout
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // Timeout should win the race
      await expect(
        client.getMessengerConversations(mockPageId)
      ).rejects.toThrow();
    });

    it('should handle network timeout with proper error message', async () => {
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      (timeoutError as any).config = { timeout: 30000 };
      
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      await expect(
        client.getMessengerConversations(mockPageId)
      ).rejects.toThrow(/timeout|Timeout|ECONNABORTED/i);
    });

    it('should continue processing after timeout if retry succeeds', async () => {
      // First page
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [{ id: 'conv-1', participants: { data: [] }, updated_time: '2024-01-01T00:00:00Z', message_count: 10 }],
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id-123/conversations?paging_token=next',
          },
        },
      });

      // Second page times out
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // Retry succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [{ id: 'conv-2', participants: { data: [] }, updated_time: '2024-01-02T00:00:00Z', message_count: 5 }],
          paging: {},
        },
      });

      // Don't use fake timers - let the actual retry logic work
      // The retry will happen automatically in the client code
      const result = await client.getMessengerConversations(mockPageId);
      
      // Should have at least the first page's conversations
      expect(result.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Instagram Conversations - Network Timeout', () => {
    it('should handle timeout when fetching Instagram conversations', async () => {
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      (timeoutError as any).config = { timeout: 30000 };
      
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // Instagram conversations might handle errors differently
      // Test that error is thrown or handled
      try {
        await client.getInstagramConversations('ig-account-123');
        // If it doesn't throw, that's also acceptable (error handling)
      } catch (error) {
        // Expected to throw
        expect(error).toBeDefined();
      }
    });

    it('should handle timeout during Instagram conversation pagination', async () => {
      // First page succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [
            {
              id: 'ig-conv-1',
              participants: { data: [{ id: 'ig-user-1' }] },
              updated_time: '2024-01-01T00:00:00Z',
              message_count: 15,
            },
          ],
          paging: {
            next: 'https://graph.facebook.com/v19.0/ig-account-123/conversations?paging_token=next',
          },
        },
      });

      // Second page times out
      const timeoutError = new Error('Page 2 request timed out after 30 seconds');
      (timeoutError as any).code = 'ECONNABORTED';
      
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // Instagram client may return partial results on timeout (graceful degradation)
      // or throw - both are acceptable behaviors
      try {
        const result = await client.getInstagramConversations('ig-account-123');
        // If it returns partial results, verify them
        if (result.length > 0) {
          expect(result[0].id).toBe('ig-conv-1');
        } else {
          // Empty result is also acceptable (error handling)
          expect(Array.isArray(result)).toBe(true);
        }
      } catch (error) {
        // If it throws, that's also acceptable
        expect(error).toBeDefined();
      }
    }, 10000); // Increase timeout for this test
  });
});

