/**
 * Tests for FacebookClient error handling
 * 
 * Tests ensure:
 * - API errors are handled gracefully (returns partial results)
 * - Invalid access tokens throw FacebookApiError
 * - Network timeouts are handled gracefully
 */

import { FacebookClient, FacebookApiError } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('FacebookClient Error Handling', () => {
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

  describe('Test: Handles API errors gracefully (returns partial results)', () => {
    it('should return partial results when API error occurs after fetching some conversations', async () => {
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const partialConversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }],
          },
        },
      ];

      // First request succeeds with partial data
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: partialConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with API error (not rate limit)
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

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should return partial results instead of throwing
      expect(result).toEqual(partialConversations);
      expect(result.length).toBe(1);
    });

    it('should return partial results when network error occurs during pagination', async () => {
      const neededParticipantIds = new Set(['participant1']);
      const partialConversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }],
          },
        },
      ];

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: partialConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with network error (not rate limit)
      const networkError = new Error('Network Error');
      mockedAxios.get.mockRejectedValueOnce(networkError);

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should return partial results
      expect(result).toEqual(partialConversations);
      expect(result.length).toBe(1);
    });

    it('should return partial results for Instagram conversations on API error', async () => {
      const neededParticipantIds = new Set(['ig-participant1']);
      const partialConversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [{ id: 'ig-participant1' }],
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: partialConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with API error (not rate limit) - this will break pagination
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

      const result = await client.getInstagramConversationsUntilFound(
        'test-ig-id',
        neededParticipantIds
      );

      // Should return partial results (first page was successful)
      expect(result).toEqual(partialConversations);
      expect(result.length).toBe(1);
    });

    it('should throw FacebookApiError for rate limit errors instead of returning partial results', async () => {
      // Need participant2 which won't be in first page, forcing second request
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const firstPageConversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }], // Only participant1, not participant2
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds but doesn't have all participants (found 1, need 2)
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: firstPageConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with rate limit error - this will throw from pagination error handler
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 613,
              type: 'OAuthException',
              message: 'Rate limit exceeded',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);
    });

    it('should return empty array when first request fails with non-rate-limit error', async () => {
      const neededParticipantIds = new Set(['participant1']);

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request fails with API error (not rate limit)
      // This goes to the outer catch block which returns allConversations (empty at this point)
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

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should return empty array (no partial results yet, error happened on first request)
      expect(result).toEqual([]);
      expect(result.length).toBe(0);
    });
  });

  describe('Test: Handles invalid access token (throws FacebookApiError)', () => {
    it('should throw FacebookApiError when access token is invalid (code 190)', async () => {
      // Reset mocks for this test
      mockedAxios.get.mockReset();

      const invalidTokenError = {
        response: {
          data: {
            error: {
              code: 190,
              type: 'OAuthException',
              message: 'Invalid OAuth 2.0 Access Token',
            },
          },
        },
      };

      mockedAxios.get.mockRejectedValueOnce(invalidTokenError);

      await expect(client.getMessengerProfile('test-psid')).rejects.toThrow(FacebookApiError);

      // Reset mock for second assertion
      mockedAxios.get.mockReset();
      mockedAxios.get.mockRejectedValueOnce(invalidTokenError);

      await expect(client.getMessengerProfile('test-psid')).rejects.toThrow(
        'Invalid OAuth 2.0 Access Token'
      );
    });

    it('should throw FacebookApiError with correct code when token is expired', async () => {
      // Reset mocks for this test
      mockedAxios.get.mockReset();

      const expiredTokenError = {
        response: {
          data: {
            error: {
              code: 190,
              type: 'OAuthException',
              message: 'The access token has expired',
            },
          },
        },
      };

      mockedAxios.get.mockRejectedValueOnce(expiredTokenError);

      try {
        await client.getMessengerProfile('test-psid');
        fail('Should have thrown FacebookApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(FacebookApiError);
        const fbError = error as FacebookApiError;
        expect(fbError.code).toBe(190);
        expect(fbError.isTokenExpired).toBe(true);
        // The message should match what was in the error response
        expect(fbError.message).toBe('The access token has expired');
      }
    });

    it('should throw FacebookApiError when token is invalid for Instagram profile', async () => {
      // Reset mocks for this test
      mockedAxios.get.mockReset();

      const invalidTokenError = {
        response: {
          data: {
            error: {
              code: 190,
              type: 'OAuthException',
              message: 'Invalid OAuth 2.0 Access Token',
            },
          },
        },
      };

      mockedAxios.get.mockRejectedValueOnce(invalidTokenError);

      await expect(client.getInstagramProfile('test-ig-id')).rejects.toThrow(FacebookApiError);

      // Reset for second assertion
      mockedAxios.get.mockReset();
      mockedAxios.get.mockRejectedValueOnce(invalidTokenError);

      await expect(client.getInstagramProfile('test-ig-id')).rejects.toThrow(
        'Invalid OAuth 2.0 Access Token'
      );
    });

    it('should throw FacebookApiError when token is invalid for sending messages', async () => {
      const invalidTokenError = {
        response: {
          data: {
            error: {
              code: 190,
              type: 'OAuthException',
              message: 'Invalid OAuth 2.0 Access Token',
            },
          },
        },
      };

      mockedAxios.post.mockRejectedValueOnce(invalidTokenError);

      // sendMessengerMessage returns error object instead of throwing for most errors
      // but let's check that it handles token errors correctly
      const result = await client.sendMessengerMessage({
        recipientId: 'test-recipient',
        message: 'test message',
      });

      // sendMessengerMessage returns error object, not throws
      expect(result.success).toBe(false);
      expect(result.error).toBe('FACEBOOK_API_ERROR');
      expect(result.code).toBe(190);
    });

    it('should identify token expiration using isTokenExpired getter', async () => {
      const expiredTokenError = {
        response: {
          data: {
            error: {
              code: 190,
              type: 'OAuthException',
              message: 'Token expired',
            },
          },
        },
      };

      mockedAxios.get.mockRejectedValueOnce(expiredTokenError);

      try {
        await client.getMessengerProfile('test-psid');
        fail('Should have thrown FacebookApiError');
      } catch (error) {
        expect(error).toBeInstanceOf(FacebookApiError);
        const fbError = error as FacebookApiError;
        expect(fbError.isTokenExpired).toBe(true);
      }
    });
  });

  describe('Test: Handles network timeouts', () => {
    it('should handle timeout errors gracefully in getMessengerConversationsUntilFound', async () => {
      const neededParticipantIds = new Set(['participant1']);
      const partialConversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }],
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: partialConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request times out
      const timeoutError = new Error('timeout of 20000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should return partial results on timeout
      expect(result).toEqual(partialConversations);
      expect(result.length).toBe(1);
    });

    it('should handle timeout errors in getMessengerConversations', async () => {
      const conversations = [
        {
          id: 'conv1',
          participants: { data: [] },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request times out - getMessengerConversations has retry logic
      // We need to mock the retry attempts as well
      const timeoutError = new Error('timeout of 30000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      // Mock the timeout error for the initial request
      mockedAxios.get.mockRejectedValueOnce(timeoutError);
      // Mock retry attempts (2 retries)
      mockedAxios.get.mockRejectedValueOnce(timeoutError);
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      // getMessengerConversations should handle timeout and return partial results
      // The retry logic will exhaust and break, returning what we have
      const result = await client.getMessengerConversations(mockPageId);
      // Should return partial results (first page succeeded)
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(1);
    }, 10000); // Increase timeout for this test

    it('should handle timeout errors in getAllMessagesForConversation', async () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Test message',
          created_time: '2024-01-01T00:00:00+0000',
        },
      ];

      // getAllMessagesForConversation uses Promise.race with axios.get
      // The implementation uses Promise.race which means we need to mock axios.get
      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: messages,
          paging: {
            next: 'https://graph.facebook.com/v19.0/conv-id/messages?after=cursor',
          },
        },
      });

      // Second request times out - the error will be caught in the inner catch
      // and break the loop, returning what we have
      const timeoutError = new Error('Message page 2 request timed out after 30 seconds');
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      const result = await client.getAllMessagesForConversation('conv-id');

      // Should return partial results on timeout (first page succeeded, second timed out)
      expect(result).toEqual(messages);
      expect(result.length).toBe(1);
    });

    it('should handle timeout errors in getRecentMessagesForConversation', async () => {
      // getRecentMessagesForConversation returns empty array on any error
      const timeoutError = new Error('timeout of 15000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      const result = await client.getRecentMessagesForConversation('conv-id');

      // Should return empty array on timeout (catch block returns [])
      expect(result).toEqual([]);
      expect(result.length).toBe(0);
    });

    it('should handle timeout string in error message', async () => {
      const neededParticipantIds = new Set(['participant1']);
      const partialConversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }],
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: partialConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request times out (error message contains 'timeout')
      // This will be caught in pagination error handler and break the loop
      const timeoutError = new Error('Request timeout');
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should return partial results (first page succeeded, second timed out)
      expect(result).toEqual(partialConversations);
      expect(result.length).toBe(1);
    });

    it('should handle timeout for Instagram conversations', async () => {
      const neededParticipantIds = new Set(['ig-participant1']);
      const partialConversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [{ id: 'ig-participant1' }],
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: partialConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-id/conversations?after=cursor',
          },
        },
      });

      // Second request times out - this will break pagination and return partial results
      const timeoutError = new Error('timeout of 20000ms exceeded');
      (timeoutError as any).code = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValueOnce(timeoutError);

      const result = await client.getInstagramConversationsUntilFound(
        'test-ig-id',
        neededParticipantIds
      );

      // Should return partial results on timeout (first page succeeded)
      expect(result).toEqual(partialConversations);
      expect(result.length).toBe(1);
    });
  });

  describe('Test: Handles rate limiting (retries or throws)', () => {
    it('should throw FacebookApiError for Messenger rate limit error code 613', async () => {
      // Need participant2 which won't be in first page, forcing second request
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const firstPageConversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }], // Only participant1, not participant2
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds but doesn't have all participants
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: firstPageConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with rate limit error code 613
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 613,
              type: 'OAuthException',
              message: 'Rate limit exceeded',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);

      // Reset for second assertion
      mockedAxios.get.mockReset();
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: firstPageConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds)
      ).rejects.toThrow('Rate limited while paginating conversations');
    });

    it('should throw FacebookApiError for Messenger rate limit error code 4', async () => {
      const neededParticipantIds = new Set(['participant1']);

      // First request fails with rate limit error code 4
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 4,
              type: 'OAuthException',
              message: 'Application request limit reached',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);
    });

    it('should throw FacebookApiError for Messenger rate limit error code 17', async () => {
      const neededParticipantIds = new Set(['participant1']);

      // First request fails with rate limit error code 17
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 17,
              type: 'OAuthException',
              message: 'User request limit reached',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);
    });

    it('should throw FacebookApiError for Instagram rate limit error code 613', async () => {
      // Need ig-participant2 which won't be in first page, forcing second request
      const neededParticipantIds = new Set(['ig-participant1', 'ig-participant2']);
      const firstPageConversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [{ id: 'ig-participant1' }], // Only ig-participant1, not ig-participant2
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First request succeeds but doesn't have all participants
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: firstPageConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with rate limit error code 613
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 613,
              type: 'OAuthException',
              message: 'Rate limit exceeded',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getInstagramConversationsUntilFound('test-ig-id', neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);

      // Reset for second assertion
      mockedAxios.get.mockReset();
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: firstPageConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-id/conversations?after=cursor',
          },
        },
      });
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getInstagramConversationsUntilFound('test-ig-id', neededParticipantIds)
      ).rejects.toThrow('Rate limited while paginating Instagram conversations');
    });

    it('should throw FacebookApiError for Instagram rate limit error code 4', async () => {
      const neededParticipantIds = new Set(['ig-participant1']);

      // First request fails with rate limit error code 4
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 4,
              type: 'OAuthException',
              message: 'Application request limit reached',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getInstagramConversationsUntilFound('test-ig-id', neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);
    });

    it('should throw FacebookApiError for Instagram rate limit error code 17', async () => {
      const neededParticipantIds = new Set(['ig-participant1']);

      // First request fails with rate limit error code 17
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 17,
              type: 'OAuthException',
              message: 'User request limit reached',
            },
          },
        },
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getInstagramConversationsUntilFound('test-ig-id', neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);
    });

    it('should throw FacebookApiError when rate limit occurs during pagination for Messenger', async () => {
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const page1Conversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'participant1' }], // Only participant1, not participant2
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First page succeeds but doesn't have all participants (found 1, need 2)
      // This should trigger a second request
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page1Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second page fails with rate limit - this should throw from pagination error handler
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 613,
              type: 'OAuthException',
              message: 'Rate limit exceeded',
            },
          },
        },
        message: 'Request failed with status code 429',
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);

      // Verify that both requests were made
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });

    it('should throw FacebookApiError when rate limit occurs during pagination for Instagram', async () => {
      const neededParticipantIds = new Set(['ig-participant1', 'ig-participant2']);
      const page1Conversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [{ id: 'ig-participant1' }], // Only ig-participant1, not ig-participant2
          },
        },
      ];

      // Reset mocks for this test
      mockedAxios.get.mockReset();

      // First page succeeds but doesn't have all participants (found 1, need 2)
      // This should trigger a second request
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page1Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-id/conversations?after=cursor',
          },
        },
      });

      // Second page fails with rate limit - this should throw from pagination error handler
      const rateLimitError = {
        response: {
          data: {
            error: {
              code: 613,
              type: 'OAuthException',
              message: 'Rate limit exceeded',
            },
          },
        },
        message: 'Request failed with status code 429',
      };
      mockedAxios.get.mockRejectedValueOnce(rateLimitError);

      await expect(
        client.getInstagramConversationsUntilFound('test-ig-id', neededParticipantIds)
      ).rejects.toThrow(FacebookApiError);

      // Verify that both requests were made
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
    });
  });

  describe('Test: Separates Messenger and Instagram participant IDs correctly', () => {
    it('should correctly identify Messenger participants in getMessengerConversationsUntilFound', async () => {
      const messengerParticipantIds = new Set(['messenger-psid-1', 'messenger-psid-2']);
      const conversations = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'messenger-psid-1' },
              { id: mockPageId }, // Page ID should be excluded
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
        {
          id: 'conv2',
          participants: {
            data: [
              { id: 'messenger-psid-2' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: conversations,
          paging: {},
        },
      });

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        messengerParticipantIds
      );

      expect(result).toHaveLength(2);
      expect(result[0].participants.data).toContainEqual({ id: 'messenger-psid-1' });
      expect(result[1].participants.data).toContainEqual({ id: 'messenger-psid-2' });
    });

    it('should correctly identify Instagram participants in getInstagramConversationsUntilFound', async () => {
      const instagramParticipantIds = new Set(['ig-user-1', 'ig-user-2']);
      const igAccountId = 'test-ig-account-id';
      const conversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [
              { id: 'ig-user-1' },
              { id: igAccountId }, // Account ID should be excluded
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
        {
          id: 'ig-conv2',
          participants: {
            data: [
              { id: 'ig-user-2' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: conversations,
          paging: {},
        },
      });

      const result = await client.getInstagramConversationsUntilFound(
        igAccountId,
        instagramParticipantIds
      );

      expect(result).toHaveLength(2);
      expect(result[0].participants.data).toContainEqual({ id: 'ig-user-1' });
      expect(result[1].participants.data).toContainEqual({ id: 'ig-user-2' });
    });

    it('should not mix Messenger and Instagram participant IDs', async () => {
      const messengerIds = new Set(['messenger-psid-1']);
      const instagramIds = new Set(['ig-user-1']);
      const igAccountId = 'test-ig-account-id';

      // Messenger conversation should only contain Messenger participants
      const messengerConvs = [
        {
          id: 'msg-conv1',
          participants: {
            data: [
              { id: 'messenger-psid-1' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      // Instagram conversation should only contain Instagram participants
      const instagramConvs = [
        {
          id: 'ig-conv1',
          participants: {
            data: [
              { id: 'ig-user-1' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];

      mockedAxios.get
        .mockResolvedValueOnce({
          data: {
            data: messengerConvs,
            paging: {},
          },
        })
        .mockResolvedValueOnce({
          data: {
            data: instagramConvs,
            paging: {},
          },
        });

      const messengerResult = await client.getMessengerConversationsUntilFound(
        mockPageId,
        messengerIds
      );
      const instagramResult = await client.getInstagramConversationsUntilFound(
        igAccountId,
        instagramIds
      );

      // Messenger result should not contain Instagram IDs
      const messengerParticipantIds = new Set(
        messengerResult.flatMap(c => c.participants.data.map(p => p.id))
      );
      expect(messengerParticipantIds.has('ig-user-1')).toBe(false);
      expect(messengerParticipantIds.has('messenger-psid-1')).toBe(true);

      // Instagram result should not contain Messenger IDs
      const instagramParticipantIds = new Set(
        instagramResult.flatMap(c => c.participants.data.map(p => p.id))
      );
      expect(instagramParticipantIds.has('messenger-psid-1')).toBe(false);
      expect(instagramParticipantIds.has('ig-user-1')).toBe(true);
    });
  });

  describe('Test: Stops early if all participants found (optimization)', () => {
    it('should stop early when all Messenger participants are found in first page', async () => {
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const conversations = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'participant1' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
        {
          id: 'conv2',
          participants: {
            data: [
              { id: 'participant2' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should stop after first page since all participants found
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(2);
    });

    it('should stop early when all Messenger participants are found in second page', async () => {
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const page1Conversations = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'participant1' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];
      const page2Conversations = [
        {
          id: 'conv2',
          participants: {
            data: [
              { id: 'participant2' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];

      // First page - finds participant1
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page1Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second page - finds participant2, should stop
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page2Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor2',
          },
        },
      });

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should stop after second page since all participants found
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
      expect(result).toHaveLength(2);
    });

    it('should stop early when all Instagram participants are found in first page', async () => {
      const neededParticipantIds = new Set(['ig-user-1', 'ig-user-2']);
      const igAccountId = 'test-ig-account-id';
      const conversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [
              { id: 'ig-user-1' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
        {
          id: 'ig-conv2',
          participants: {
            data: [
              { id: 'ig-user-2' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id/conversations?after=cursor',
          },
        },
      });

      const result = await client.getInstagramConversationsUntilFound(
        igAccountId,
        neededParticipantIds
      );

      // Should stop after first page since all participants found
      expect(mockedAxios.get).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(2);
    });

    it('should stop early when all Instagram participants are found in second page', async () => {
      const neededParticipantIds = new Set(['ig-user-1', 'ig-user-2']);
      const igAccountId = 'test-ig-account-id';
      const page1Conversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [
              { id: 'ig-user-1' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];
      const page2Conversations = [
        {
          id: 'ig-conv2',
          participants: {
            data: [
              { id: 'ig-user-2' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];

      // First page - finds ig-user-1
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page1Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id/conversations?after=cursor',
          },
        },
      });

      // Second page - finds ig-user-2, should stop
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page2Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id/conversations?after=cursor2',
          },
        },
      });

      const result = await client.getInstagramConversationsUntilFound(
        igAccountId,
        neededParticipantIds
      );

      // Should stop after second page since all participants found
      expect(mockedAxios.get).toHaveBeenCalledTimes(2);
      expect(result).toHaveLength(2);
    });

    it('should continue pagination when not all Messenger participants are found', async () => {
      const neededParticipantIds = new Set(['participant1', 'participant2', 'participant3']);
      const page1Conversations = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'participant1' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];
      const page2Conversations = [
        {
          id: 'conv2',
          participants: {
            data: [
              { id: 'participant2' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];
      const page3Conversations = [
        {
          id: 'conv3',
          participants: {
            data: [
              { id: 'participant3' },
              { id: mockPageId },
            ],
          },
          updated_time: '2024-01-03T00:00:00Z',
        },
      ];

      // First page - finds participant1
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page1Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor1',
          },
        },
      });

      // Second page - finds participant2, but still missing participant3
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page2Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor2',
          },
        },
      });

      // Third page - finds participant3, should stop
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page3Conversations,
          paging: {},
        },
      });

      const result = await client.getMessengerConversationsUntilFound(
        mockPageId,
        neededParticipantIds
      );

      // Should continue until all participants found
      expect(mockedAxios.get).toHaveBeenCalledTimes(3);
      expect(result).toHaveLength(3);
    });

    it('should continue pagination when not all Instagram participants are found', async () => {
      const neededParticipantIds = new Set(['ig-user-1', 'ig-user-2', 'ig-user-3']);
      const igAccountId = 'test-ig-account-id';
      const page1Conversations = [
        {
          id: 'ig-conv1',
          participants: {
            data: [
              { id: 'ig-user-1' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-01T00:00:00Z',
        },
      ];
      const page2Conversations = [
        {
          id: 'ig-conv2',
          participants: {
            data: [
              { id: 'ig-user-2' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-02T00:00:00Z',
        },
      ];
      const page3Conversations = [
        {
          id: 'ig-conv3',
          participants: {
            data: [
              { id: 'ig-user-3' },
              { id: igAccountId },
            ],
          },
          updated_time: '2024-01-03T00:00:00Z',
        },
      ];

      // First page - finds ig-user-1
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page1Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id/conversations?after=cursor1',
          },
        },
      });

      // Second page - finds ig-user-2, but still missing ig-user-3
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page2Conversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-ig-account-id/conversations?after=cursor2',
          },
        },
      });

      // Third page - finds ig-user-3, should stop
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: page3Conversations,
          paging: {},
        },
      });

      const result = await client.getInstagramConversationsUntilFound(
        igAccountId,
        neededParticipantIds
      );

      // Should continue until all participants found
      expect(mockedAxios.get).toHaveBeenCalledTimes(3);
      expect(result).toHaveLength(3);
    });
  });
});

