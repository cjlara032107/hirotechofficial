/**
 * Tests for AI Service Unavailable Handling
 * 
 * Tests ensure that:
 * - AI service unavailability is handled gracefully
 * - Operations fail gracefully when AI service is down
 * - Retry logic works correctly for transient failures
 * - Error messages are user-friendly
 */

// setImmediate is now polyfilled in jest.setup.js

// Mock OpenAI BEFORE imports
jest.mock('openai', () => {
  return jest.fn().mockImplementation(() => ({
    chat: {
      completions: {
        create: jest.fn(),
      },
    },
  }));
});

jest.mock('../api-key-manager', () => ({
  __esModule: true,
  default: {
    getNextKey: jest.fn(),
    recordSuccess: jest.fn(),
    markRateLimited: jest.fn(),
  },
}));

import { analyzeConversation } from '../google-ai-service';
import apiKeyManager from '../api-key-manager';
import OpenAI from 'openai';

const mockedApiKeyManager = apiKeyManager as jest.Mocked<typeof apiKeyManager>;
const MockedOpenAI = OpenAI as jest.MockedClass<typeof OpenAI>;

describe('AI Service Unavailable Handling', () => {
  const mockMessages = [
    { from: 'User', text: 'Hello, I need help' },
    { from: 'Agent', text: 'How can I assist you?' },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: AI service unavailable', () => {
    it('should return null when AI service is completely unavailable (network error)', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const mockCreate = jest.fn().mockRejectedValue(new Error('ECONNREFUSED: Connection refused'));
      MockedOpenAI.mockImplementation(() => ({
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      }) as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
      expect(mockCreate).toHaveBeenCalled();
    });

    it('should return null when AI service returns 503 Service Unavailable', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const serviceUnavailableError = {
        status: 503,
        message: 'Service Unavailable',
        response: {
          status: 503,
          data: { error: 'Service temporarily unavailable' },
        },
      };

      const mockCreate = jest.fn().mockRejectedValue(serviceUnavailableError);
      const mockClient = {
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      };

      MockedOpenAI.mockImplementation(() => mockClient as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
    });

    it('should return null when AI service returns 500 Internal Server Error', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const serverError = {
        status: 500,
        message: 'Internal Server Error',
        response: {
          status: 500,
          data: { error: 'Internal server error' },
        },
      };

      const mockCreate = jest.fn().mockRejectedValue(serverError);
      MockedOpenAI.mockImplementation(() => ({
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      }) as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
    });

    it('should return null when AI service times out', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const timeoutError = new Error('ETIMEDOUT: Request timeout');
      (timeoutError as any).code = 'ETIMEDOUT';

      const mockCreate = jest.fn().mockRejectedValue(timeoutError);
      MockedOpenAI.mockImplementation(() => ({
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      }) as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
    });

    it('should return null when no API key is available', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue(null);
      // Also mock environment variable check
      const originalEnv = process.env.NVIDIA_API_KEY;
      delete process.env.NVIDIA_API_KEY;

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();

      // Restore environment
      if (originalEnv) {
        process.env.NVIDIA_API_KEY = originalEnv;
      }
    });

    it('should handle AI service returning empty response', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const mockCreate = jest.fn().mockResolvedValue({
        choices: [],
        usage: {},
      });
      MockedOpenAI.mockImplementation(() => ({
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      }) as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
    });

    it('should handle AI service returning response with no content', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const mockCreate = jest.fn().mockResolvedValue({
        choices: [
          {
            message: {
              content: null,
            },
          },
        ],
        usage: {},
      });
      MockedOpenAI.mockImplementation(() => ({
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      }) as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
    });

    it('should handle AI service returning error in response object', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);

      const mockCreate = jest.fn().mockResolvedValue({
        error: {
          message: 'Service unavailable',
        },
        choices: [],
        usage: {},
      });
      MockedOpenAI.mockImplementation(() => ({
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      }) as any);

      const result = await analyzeConversation(mockMessages);

      expect(result).toBeNull();
    });

    it('should log appropriate error messages when service is unavailable', async () => {
      mockedApiKeyManager.getNextKey.mockResolvedValue('test-api-key');
      mockedApiKeyManager.recordSuccess.mockResolvedValue(undefined);
      const consoleErrorSpy = jest.spyOn(console, 'error');

      const serviceUnavailableError = {
        status: 503,
        message: 'Service Unavailable',
        response: {
          status: 503,
          data: { error: 'Service temporarily unavailable' },
        },
      };

      const mockCreate = jest.fn().mockRejectedValue(serviceUnavailableError);
      const mockClient = {
        chat: {
          completions: {
            create: mockCreate,
          },
        },
      };

      MockedOpenAI.mockImplementation(() => mockClient as any);

      await analyzeConversation(mockMessages);

      expect(consoleErrorSpy).toHaveBeenCalled();
      const errorCalls = consoleErrorSpy.mock.calls;
      expect(errorCalls.some(call => 
        call[0]?.toString().includes('Analysis failed') || 
        call[0]?.toString().includes('NVIDIA')
      )).toBe(true);
    });
  });
});

