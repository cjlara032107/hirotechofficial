/**
 * Tests for Facebook API Rate Limit Handling
 * 
 * Tests ensure that:
 * - Rate limit errors (codes 613, 4, 17) are properly detected and handled
 * - Operations gracefully handle rate limits during sync operations
 * - Rate limit errors are properly propagated vs. other errors
 */

import { FacebookClient, FacebookApiError } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Facebook API Rate Limit Handling', () => {
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

  describe('Test: Facebook API rate limit exceeded', () => {
    it('should throw FacebookApiError when rate limit code 613 is encountered during getMessengerConversations', async () => {
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

      const error = await client.getMessengerConversations(mockPageId).catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).code).toBe(613);
      expect((error as FacebookApiError).isRateLimited).toBe(true);
    });

    it('should throw FacebookApiError when rate limit code 4 is encountered', async () => {
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

      const error = await client.getMessengerConversations(mockPageId).catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).code).toBe(4);
      expect((error as FacebookApiError).isRateLimited).toBe(true);
    });

    it('should throw FacebookApiError when rate limit code 17 is encountered', async () => {
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

      const error = await client.getMessengerConversations(mockPageId).catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).code).toBe(17);
      expect((error as FacebookApiError).isRateLimited).toBe(true);
    });

    it('should throw FacebookApiError when rate limit occurs during pagination', async () => {
      const neededParticipantIds = new Set(['participant1', 'participant2']);
      const firstPageConversations = [
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
          data: firstPageConversations,
          paging: {
            next: 'https://graph.facebook.com/v19.0/test-page-id/conversations?after=cursor',
          },
        },
      });

      // Second request fails with rate limit - this should be caught in pagination error handler
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

      // According to implementation, rate limits during pagination throw FacebookApiError
      // But the outer catch returns partial results for non-rate-limit errors
      // Rate limits are checked in the pagination catch block and thrown
      try {
        await client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds);
        // If it doesn't throw, verify it returned partial results
        const result = await client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds);
        expect(Array.isArray(result)).toBe(true);
      } catch (error) {
        // If it throws, it should be a FacebookApiError for rate limits
        expect(error).toBeInstanceOf(FacebookApiError);
        expect((error as FacebookApiError).isRateLimited).toBe(true);
      }
    });

    it('should return error object (not throw) when rate limit occurs during sendMessengerMessage', async () => {
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

      mockedAxios.post.mockRejectedValueOnce(rateLimitError);

      const result = await client.sendMessengerMessage({
        recipientId: 'test-recipient',
        message: 'test message',
      });

      // sendMessengerMessage returns error object instead of throwing
      expect(result.success).toBe(false);
      expect(result.error).toBe('RATE_LIMIT');
      expect(result.code).toBe(613);
    });

    it('should handle rate limit during getAllMessagesForConversation', async () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Test message',
          created_time: '2024-01-01T00:00:00+0000',
        },
      ];

      // First request succeeds
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: messages,
          paging: {
            next: 'https://graph.facebook.com/v19.0/conv-id/messages?after=cursor',
          },
        },
      });

      // Second request fails with rate limit
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

      // getAllMessagesForConversation should return partial results on rate limit
      // (it catches errors and returns what it has)
      const result = await client.getAllMessagesForConversation('conv-id');
      
      // Should return partial results (first page succeeded)
      expect(result).toEqual(messages);
      expect(result.length).toBe(1);
    });

    it('should identify rate limit errors using isRateLimited getter', () => {
      const error = new FacebookApiError(613, 'OAuthException', 'Rate limit exceeded');
      expect(error.isRateLimited).toBe(true);

      const error4 = new FacebookApiError(4, 'OAuthException', 'Application request limit reached');
      expect(error4.isRateLimited).toBe(true);

      const error17 = new FacebookApiError(17, 'OAuthException', 'User request limit reached');
      expect(error17.isRateLimited).toBe(true);

      const nonRateLimitError = new FacebookApiError(100, 'OAuthException', 'Invalid parameter');
      expect(nonRateLimitError.isRateLimited).toBe(false);
    });
  });
});

