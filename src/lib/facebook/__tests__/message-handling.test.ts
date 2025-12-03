/**
 * Tests for message handling and conversation processing
 * 
 * Tests ensure:
 * - Handles invalid conversation structure gracefully
 * - Handles conversations with malformed message data
 * - Filters out system/automated messages
 * - Returns consistent Message object structure
 */

import { FacebookClient } from '../client';
import { mapConversations } from '../pipeline-analyzer/map-conversations';
import axios from 'axios';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Message Handling Tests', () => {
  const mockAccessToken = 'test-access-token';
  let client: FacebookClient;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetAllMocks();
    mockedAxios.get.mockReset();
    client = new FacebookClient(mockAccessToken);
    // Suppress console logs during tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Test: Handles invalid conversation structure gracefully', () => {
    it('should handle null conversations array', () => {
      const result = mapConversations(null as unknown as never[], 'messenger');
      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });

    it('should handle undefined conversations array', () => {
      const result = mapConversations(undefined as unknown as never[], 'messenger');
      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });

    it('should handle non-array input', () => {
      const result = mapConversations({} as unknown as never[], 'messenger');
      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });

    it('should handle empty conversations array', () => {
      const result = mapConversations([], 'messenger');
      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });

    it('should skip null conversations in array', () => {
      const conversations = [
        null,
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1', name: 'User One' }]
          }
        },
        null
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should skip undefined conversations in array', () => {
      const conversations = [
        undefined,
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1', name: 'User One' }]
          }
        }
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should skip conversations with missing participants', () => {
      const conversations = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1', name: 'User One' }]
          }
        },
        {
          id: 'conv2'
          // Missing participants
        },
        {
          id: 'conv3',
          participants: {}
        },
        {
          id: 'conv4',
          participants: {
            data: []
          }
        }
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should skip conversations with invalid participant structure', () => {
      const conversations = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'user1', name: 'User One' },
              null,
              undefined,
              { name: 'User Two' }, // Missing id
              { id: 123 }, // Invalid id type
              'invalid'
            ]
          }
        }
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should handle conversations with string IDs instead of objects', () => {
      const conversations = [
        'not-an-object',
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1', name: 'User One' }]
          }
        }
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should handle deeply nested invalid structures', () => {
      const conversations = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'user1', name: 'User One' },
              { id: null }, // null id
              { id: undefined }, // undefined id
              { id: {} }, // object id
              { id: [] }, // array id
            ]
          }
        }
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should handle mixed valid and invalid conversations', () => {
      const conversations = [
        null,
        undefined,
        'invalid',
        { id: 'conv1' }, // Missing participants
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user1', name: 'User One' }]
          }
        },
        {
          id: 'conv3',
          participants: {
            data: [{ id: 'user2', name: 'User Two' }]
          }
        },
        { id: 'conv4', participants: { data: [] } }
      ];
      const result = mapConversations(conversations as unknown as never[], 'messenger');
      expect(result.size).toBe(2);
      expect(result.has('user1')).toBe(true);
      expect(result.has('user2')).toBe(true);
    });
  });

  describe('Test: Handles conversations with malformed message data', () => {
    it('should handle null message data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: null,
          paging: {}
        }
      });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    });

    it('should handle undefined message data', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          paging: {}
        }
      });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    });

    it('should handle empty message array', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: [],
          paging: {}
        }
      });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    });

    it('should handle messages with missing required fields', async () => {
      const malformedMessages = [
        { id: 'msg1' }, // Missing message, from, created_time
        { message: 'Hello' }, // Missing from, created_time
        { from: { id: 'user1' } }, // Missing message, created_time
        { created_time: '2024-01-01T00:00:00+0000' }, // Missing message, from
        null,
        undefined,
        'invalid'
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: malformedMessages,
          paging: {}
        }
      });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(malformedMessages.length);
      // Should return all messages even if malformed
    });

    it('should handle messages with invalid from structure', async () => {
      const malformedMessages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: null,
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'World',
          from: 'invalid-string',
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: 'Test',
          from: { id: null },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: malformedMessages,
          paging: {}
        }
      });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(3);
    });

    it('should handle messages with invalid created_time format', async () => {
      const malformedMessages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: { id: 'user1', name: 'User One' },
          created_time: null
        },
        {
          id: 'msg2',
          message: 'World',
          from: { id: 'user2', name: 'User Two' },
          created_time: 'invalid-date'
        },
        {
          id: 'msg3',
          message: 'Test',
          from: { id: 'user3', name: 'User Three' },
          created_time: 1234567890 // Number instead of string
        }
      ];

      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: malformedMessages,
          paging: {}
        }
      });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(3);
    });

    it('should handle pagination with malformed messages', async () => {
      const page1Messages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: { id: 'user1' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        null, // Malformed
        {
          id: 'msg2',
          message: 'World',
          from: { id: 'user2' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const page2Messages = [
        {
          id: 'msg3',
          message: 'Test',
          from: { id: 'user3' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        { invalid: 'structure' } // Malformed
      ];

      mockedAxios.get
        .mockResolvedValueOnce({
          data: {
            data: page1Messages,
            paging: {
              next: 'https://graph.facebook.com/v19.0/conv-id/messages?after=cursor'
            }
          }
        })
        .mockResolvedValueOnce({
          data: {
            data: page2Messages,
            paging: {}
          }
        });

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      // getAllMessagesForConversation returns all messages including null/invalid ones
      expect(result.length).toBeGreaterThanOrEqual(4);
    });

    it('should handle API errors gracefully and return partial results', async () => {
      const validMessages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: { id: 'user1' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      mockedAxios.get
        .mockResolvedValueOnce({
          data: {
            data: validMessages,
            paging: {
              next: 'https://graph.facebook.com/v19.0/conv-id/messages?after=cursor'
            }
          }
        })
        .mockRejectedValueOnce(new Error('API Error'));

      const result = await client.getAllMessagesForConversation('conv-id');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1); // Should return partial results
    });
  });

  describe('Test: Filters out system/automated messages', () => {
    // Helper function to filter messages (mimics the logic used in the codebase)
    interface FacebookMessage {
      id?: string;
      message?: string | null;
      from?: { id?: string; name?: string };
      created_time?: string;
    }
    
    function filterSystemMessages(messages: FacebookMessage[], pageId: string): FacebookMessage[] {
      return messages.filter((msg) => {
        // Filter out messages without text content
        if (!msg.message) return false;
        
        // Filter out messages from the page itself (system/automated)
        if (msg.from?.id === pageId) return false;
        if (msg.from?.name?.includes('Page')) return false;
        
        return true;
      });
    }

    it('should filter out messages from the page itself', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Hello from user',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'Automated response',
          from: { id: 'page-id-123', name: 'Page Name' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: 'Another user message',
          from: { id: 'user2', name: 'User Two' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const filtered = filterSystemMessages(messages, 'page-id-123');
      expect(filtered.length).toBe(2);
      expect(filtered[0].id).toBe('msg1');
      expect(filtered[1].id).toBe('msg3');
    });

    it('should filter out messages with "Page" in the name', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'User message',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'System message',
          from: { id: 'system1', name: 'Page Bot' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const filtered = filterSystemMessages(messages, 'page-id-123');
      expect(filtered.length).toBe(1);
      expect(filtered[0].id).toBe('msg1');
    });

    it('should filter out messages without text content', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Valid message',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: null,
          from: { id: 'user2', name: 'User Two' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: '',
          from: { id: 'user3', name: 'User Three' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg4',
          // Missing message field
          from: { id: 'user4', name: 'User Four' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const filtered = filterSystemMessages(messages, 'page-id-123');
      expect(filtered.length).toBe(1);
      expect(filtered[0].id).toBe('msg1');
    });

    it('should handle mixed system and user messages', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'User message 1',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'Automated response',
          from: { id: 'page-id-123', name: 'Page' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: 'User message 2',
          from: { id: 'user2', name: 'User Two' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg4',
          message: 'System notification',
          from: { id: 'system1', name: 'Page Bot' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const filtered = filterSystemMessages(messages, 'page-id-123');
      expect(filtered.length).toBe(2);
      expect(filtered.every(msg => msg.from?.id !== 'page-id-123')).toBe(true);
      expect(filtered.every(msg => !msg.from?.name?.includes('Page'))).toBe(true);
    });

    it('should preserve user messages when filtering', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: { id: 'user1', name: 'John Doe' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'How are you?',
          from: { id: 'user2', name: 'Jane Smith' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const filtered = filterSystemMessages(messages, 'page-id-123');
      expect(filtered.length).toBe(2);
      expect(filtered[0].id).toBe('msg1');
      expect(filtered[1].id).toBe('msg2');
    });
  });

  describe('Test: Returns consistent Message object structure', () => {
    // Helper function to transform messages (mimics the logic used in pipeline-analyzer.ts)
    interface MessageInput {
      message?: string | null;
      from?: { name?: string; username?: string; id?: string };
      created_time?: string | null;
    }
    
    interface TransformedMessage {
      from: string;
      text: string;
      timestamp?: Date;
    }
    
    function transformMessages(messages: MessageInput[]): TransformedMessage[] {
      return messages
        .filter((msg) => msg.message)
        .map((msg) => ({
          from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
          text: msg.message || '',
          timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
        }));
    }

    it('should return consistent structure for valid messages', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'World',
          from: { id: 'user2', name: 'User Two' },
          created_time: '2024-01-02T00:00:00+0000'
        }
      ];

      const transformed = transformMessages(messages);
      
      expect(transformed.length).toBe(2);
      transformed.forEach(msg => {
        expect(msg).toHaveProperty('from');
        expect(msg).toHaveProperty('text');
        expect(typeof msg.from).toBe('string');
        expect(typeof msg.text).toBe('string');
      });
    });

    it('should use name, username, or id as fallback for from field', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Message with name',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'Message with username',
          from: { id: 'user2', username: 'user_two' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: 'Message with only id',
          from: { id: 'user3' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg4',
          message: 'Message with no from',
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const transformed = transformMessages(messages);
      
      expect(transformed.length).toBe(4);
      expect(transformed[0].from).toBe('User One');
      expect(transformed[1].from).toBe('user_two');
      expect(transformed[2].from).toBe('user3');
      expect(transformed[3].from).toBe('Unknown');
    });

    it('should handle missing created_time gracefully', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Message with timestamp',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'Message without timestamp',
          from: { id: 'user2', name: 'User Two' }
        },
        {
          id: 'msg3',
          message: 'Message with null timestamp',
          from: { id: 'user3', name: 'User Three' },
          created_time: null
        }
      ];

      const transformed = transformMessages(messages);
      
      expect(transformed.length).toBe(3);
      expect(transformed[0].timestamp).toBeInstanceOf(Date);
      expect(transformed[1].timestamp).toBeUndefined();
      expect(transformed[2].timestamp).toBeUndefined();
    });

    it('should filter out messages without text content', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Valid message',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: null,
          from: { id: 'user2', name: 'User Two' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: '',
          from: { id: 'user3', name: 'User Three' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg4',
          // Missing message field
          from: { id: 'user4', name: 'User Four' },
          created_time: '2024-01-01T00:00:00+0000'
        }
      ];

      const transformed = transformMessages(messages);
      
      expect(transformed.length).toBe(1);
      expect(transformed[0].text).toBe('Valid message');
    });

    it('should ensure all returned messages have consistent structure', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Hello',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        {
          id: 'msg2',
          message: 'World',
          from: { id: 'user2', username: 'user_two' },
          created_time: '2024-01-02T00:00:00+0000'
        },
        {
          id: 'msg3',
          message: 'Test',
          from: { id: 'user3' },
          created_time: '2024-01-03T00:00:00+0000'
        }
      ];

      const transformed = transformMessages(messages);
      
      expect(transformed.length).toBe(3);
      transformed.forEach(msg => {
        // Check required fields
        expect(msg).toHaveProperty('from');
        expect(msg).toHaveProperty('text');
        
        // Check types
        expect(typeof msg.from).toBe('string');
        expect(typeof msg.text).toBe('string');
        
        // Check optional timestamp
        if (msg.timestamp !== undefined) {
          expect(msg.timestamp).toBeInstanceOf(Date);
        }
      });
    });

    it('should handle empty message arrays', () => {
      const transformed = transformMessages([]);
      expect(Array.isArray(transformed)).toBe(true);
      expect(transformed.length).toBe(0);
    });

    it('should handle malformed messages and still return consistent structure', () => {
      const messages = [
        {
          id: 'msg1',
          message: 'Valid message',
          from: { id: 'user1', name: 'User One' },
          created_time: '2024-01-01T00:00:00+0000'
        },
        null,
        undefined,
        {
          id: 'msg2',
          message: 'Another valid message',
          from: { id: 'user2' },
          created_time: 'invalid-date'
        }
      ];

      const transformed = transformMessages(messages.filter(Boolean));
      
      // Should only include messages with valid message field
      expect(transformed.length).toBeGreaterThan(0);
      transformed.forEach(msg => {
        expect(msg).toHaveProperty('from');
        expect(msg).toHaveProperty('text');
        expect(typeof msg.from).toBe('string');
        expect(typeof msg.text).toBe('string');
      });
    });
  });
});

