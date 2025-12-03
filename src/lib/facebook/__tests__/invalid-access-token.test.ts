/**
 * Tests for Invalid Access Token Handling
 * 
 * Tests ensure that:
 * - Invalid access tokens are properly detected (code 190)
 * - Expired tokens are identified correctly
 * - Operations fail gracefully with appropriate error messages
 * - Token expiration is properly tracked
 */

import { FacebookClient, FacebookApiError } from '../client';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Invalid Access Token Handling', () => {
  const mockAccessToken = 'invalid-access-token';
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

  describe('Test: Invalid access token', () => {
    it('should throw FacebookApiError when access token is invalid (code 190)', async () => {
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

      const error = await client.getMessengerProfile('test-psid').catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).code).toBe(190);
      expect((error as FacebookApiError).isTokenExpired).toBe(true);
    });

    it('should identify expired tokens correctly', async () => {
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

      const error = await client.getMessengerProfile('test-psid').catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).isTokenExpired).toBe(true);
      expect((error as FacebookApiError).message).toContain('expired');
    });

    it('should handle invalid token during getMessengerConversations', async () => {
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

      const error = await client.getMessengerConversations(mockPageId).catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).code).toBe(190);
      expect((error as FacebookApiError).isTokenExpired).toBe(true);
    });

    it('should handle invalid token during sendMessengerMessage', async () => {
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

      const result = await client.sendMessengerMessage({
        recipientId: 'test-recipient',
        message: 'test message',
      });

      // sendMessengerMessage returns error object instead of throwing
      expect(result.success).toBe(false);
      expect(result.error).toBe('FACEBOOK_API_ERROR');
      expect(result.code).toBe(190);
    });

    it('should handle invalid token during getAllMessagesForConversation', async () => {
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

      // getAllMessagesForConversation catches errors and returns empty array
      const result = await client.getAllMessagesForConversation('conv-id');

      expect(result).toEqual([]);
    });

    it('should handle invalid token during getInstagramProfile', async () => {
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

      const error = await client.getInstagramProfile('test-ig-id').catch(e => e);
      expect(error).toBeInstanceOf(FacebookApiError);
      expect((error as FacebookApiError).code).toBe(190);
      expect((error as FacebookApiError).isTokenExpired).toBe(true);
    });

    it('should use isTokenExpired getter to check token status', () => {
      const error = new FacebookApiError(190, 'OAuthException', 'Invalid OAuth 2.0 Access Token');
      expect(error.isTokenExpired).toBe(true);

      const nonTokenError = new FacebookApiError(100, 'OAuthException', 'Invalid parameter');
      expect(nonTokenError.isTokenExpired).toBe(false);
    });

    it('should handle token expiration during pagination', async () => {
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

      // Second request fails with token expiration
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

      // getMessengerConversationsUntilFound returns partial results for non-rate-limit errors
      // Token errors (190) are not rate limits, so it returns partial results
      const result = await client.getMessengerConversationsUntilFound(mockPageId, neededParticipantIds);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1); // Should have the first page's conversations
    });

    it('should differentiate between invalid token and other OAuth errors', async () => {
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

      const permissionError = {
        response: {
          data: {
            error: {
              code: 200,
              type: 'OAuthException',
              message: 'Permissions error',
            },
          },
        },
      };

      mockedAxios.get
        .mockRejectedValueOnce(invalidTokenError)
        .mockRejectedValueOnce(permissionError);

      const tokenError = await client.getMessengerProfile('test-psid').catch(e => e);
      expect(tokenError).toBeInstanceOf(FacebookApiError);
      expect((tokenError as FacebookApiError).isTokenExpired).toBe(true);

      const permError = await client.getMessengerProfile('test-psid').catch(e => e);
      expect(permError).toBeInstanceOf(FacebookApiError);
      expect((permError as FacebookApiError).isTokenExpired).toBe(false);
      expect((permError as FacebookApiError).isPermissionError).toBe(true);
    });
  });
});

