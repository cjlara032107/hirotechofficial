/**
 * Jest tests for mapConversations function
 * 
 * Checklist Requirements:
 * - Test: Maps conversations correctly by participant ID
 * - Test: Handles conversations with invalid participant structure (skips gracefully)
 * - Test: Handles empty conversations array (returns empty Map)
 * 
 * Additional Tests:
 * - Handles duplicate participant IDs (uses first occurrence)
 * - Validates platform parameter ('messenger' | 'instagram')
 */

import { mapConversations, mapConversations_v1, mapConversations_v2, mapConversations_v3, type Conversation } from '../map-conversations';

// Mock console.warn to avoid noise in test output
const originalWarn = console.warn;
beforeAll(() => {
  console.warn = jest.fn();
});

afterAll(() => {
  console.warn = originalWarn;
});

describe('mapConversations', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // CHECKLIST ITEM 1: Maps conversations correctly by participant ID
  describe('Test: Maps conversations correctly by participant ID', () => {
    it('should map conversations with single participant per conversation', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1', name: 'User One' }]
          }
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user2', name: 'User Two' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(2);
      expect(result.get('user1')).toEqual(conversations[0]);
      expect(result.get('user2')).toEqual(conversations[1]);
    });

    it('should map conversations with multiple participants per conversation', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'user1', name: 'User One' },
              { id: 'user2', name: 'User Two' }
            ]
          }
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user3', name: 'User Three' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(3);
      expect(result.get('user1')).toEqual(conversations[0]);
      expect(result.get('user2')).toEqual(conversations[0]);
      expect(result.get('user3')).toEqual(conversations[1]);
    });

    it('should work for both messenger and instagram platforms', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const messengerResult = mapConversations(conversations, 'messenger');
      const instagramResult = mapConversations(conversations, 'instagram');

      expect(messengerResult.size).toBe(1);
      expect(instagramResult.size).toBe(1);
      expect(messengerResult.get('user1')).toEqual(conversations[0]);
      expect(instagramResult.get('user1')).toEqual(conversations[0]);
    });
  });

  // CHECKLIST ITEM 2: Handles conversations with invalid participant structure (skips gracefully)
  describe('Test: Handles conversations with invalid participant structure (skips gracefully)', () => {
    it('should skip conversations with null participants', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: null
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[1]);
    });

    it('should skip conversations with missing participants property', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const conversations: any[] = [
        {
          id: 'conv1'
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[1]);
    });

    it('should skip conversations with empty participants.data array', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: []
          }
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[1]);
    });

    it('should skip conversations with missing participants.data property', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: {}
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[1]);
    });

    it('should skip null or undefined conversations', () => {
      const conversations: any[] = [
        null,
        undefined,
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[2]);
    });

    it('should skip non-object conversations', () => {
      const conversations: any[] = [
        'not an object',
        123,
        true,
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[3]);
    });

    it('should skip participants with missing or invalid id', () => {
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: {
            data: [
              null,
              undefined,
              { name: 'No ID' },
              { id: null },
              { id: 123 },
              { id: 'user1' }
            ]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.get('user1')).toEqual(conversations[0]);
    });

    it('should not throw errors when processing invalid structures', () => {
      const conversations: any[] = [
        null,
        undefined,
        'string',
        123,
        { invalid: 'structure' },
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      expect(() => {
        const result = mapConversations(conversations, 'messenger');
        expect(result.size).toBe(1);
      }).not.toThrow();
    });
  });

  // CHECKLIST ITEM 3: Handles empty conversations array (returns empty Map)
  describe('Test: Handles empty conversations array (returns empty Map)', () => {
    it('should return empty Map for empty array', () => {
      const conversations: Conversation[] = [];

      const result = mapConversations(conversations, 'messenger');

      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });

    it('should return empty Map for empty array on instagram platform', () => {
      const conversations: Conversation[] = [];

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = mapConversations(conversations as any, 'instagram');

      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });

    it('should return empty Map when all conversations are invalid', () => {
      const conversations: any[] = [
        null,
        undefined,
        'invalid',
        { id: 'conv1' },
        { id: 'conv2', participants: {} },
        { id: 'conv3', participants: { data: [] } }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBe(0);
    });
  });

  // Additional tests
  describe('Handles duplicate participant IDs (uses first occurrence)', () => {
    it('should use first occurrence when same participant ID appears in multiple conversations', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'user1', name: 'First Conversation User' }
            ]
          }
        },
        {
          id: 'conv2',
          participants: {
            data: [
              { id: 'user1', name: 'Second Conversation User' }
            ]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
      expect(result.get('user1')?.id).toBe('conv1');
      expect(result.get('user1')?.participants?.data?.[0]?.name).toBe('First Conversation User');
    });

    it('should handle duplicate participant IDs within the same conversation', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'user1', name: 'First' },
              { id: 'user1', name: 'Duplicate' }
            ]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
      expect(result.get('user1')?.id).toBe('conv1');
    });

    it('should use first occurrence across multiple conversations with same participant', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user2' }, { id: 'user1' }]
          }
        },
        {
          id: 'conv3',
          participants: {
            data: [{ id: 'user1' }, { id: 'user3' }]
          }
        }
      ];

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = mapConversations(conversations as any, 'instagram');

      expect(result.size).toBe(3);
      expect(result.get('user1')?.id).toBe('conv1');
      expect(result.get('user2')?.id).toBe('conv2');
      expect(result.get('user3')?.id).toBe('conv3');
    });
  });

  describe('Handles conversations with missing participants array', () => {
    it('should skip conversations with missing participants property', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        {
          id: 'conv2'
        },
        {
          id: 'conv3',
          participants: {
            data: [{ id: 'user2' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(2);
      expect(result.has('user1')).toBe(true);
      expect(result.has('user2')).toBe(true);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('has no valid participants')
      );
    });

    it('should skip conversations with participants but no data array', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        {
          id: 'conv2',
          participants: {}
        },
        {
          id: 'conv3',
          participants: {
            data: []
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should handle conversations with participants.data as undefined', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        {
          id: 'conv2',
          participants: {
            data: undefined
          }
        }
      ];

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = mapConversations(conversations as any, 'instagram');

      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
    });

    it('should return empty map when all conversations have missing participants', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1'
        },
        {
          id: 'conv2',
          participants: {}
        },
        {
          id: 'conv3',
          participants: {
            data: []
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(0);
      expect(console.warn).toHaveBeenCalled();
    });
  });

  describe('Handles null/undefined conversations', () => {
    it('should skip null conversations in the array', () => {
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        null,
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user2' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(2);
      expect(result.has('user1')).toBe(true);
      expect(result.has('user2')).toBe(true);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Skipping invalid conversation')
      );
    });

    it('should skip undefined conversations in the array', () => {
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        undefined,
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user2' }]
          }
        }
      ];

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = mapConversations(conversations as any, 'instagram');

      expect(result.size).toBe(2);
      expect(result.has('user1')).toBe(true);
      expect(result.has('user2')).toBe(true);
    });

    it('should handle array with only null/undefined values', () => {
      const conversations: any[] = [null, undefined, null];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(0);
    });

    it('should handle non-object conversations', () => {
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        },
        'not an object',
        123,
        true,
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user2' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(2);
      expect(result.has('user1')).toBe(true);
      expect(result.has('user2')).toBe(true);
    });

    it('should handle null/undefined as the conversations parameter', () => {
      const result1 = mapConversations(null as any, 'messenger');
      const result2 = mapConversations(undefined as any, 'instagram');

      expect(result1.size).toBe(0);
      expect(result2.size).toBe(0);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Invalid conversations input')
      );
    });
  });

  describe("Validates platform parameter ('messenger' | 'instagram')", () => {
    it('should accept valid platform "messenger"', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
      expect(console.warn).not.toHaveBeenCalledWith(
        expect.stringContaining('Invalid platform')
      );
    });

    it('should accept valid platform "instagram"', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = mapConversations(conversations as any, 'instagram');

      expect(result.size).toBe(1);
      expect(result.has('user1')).toBe(true);
      expect(console.warn).not.toHaveBeenCalledWith(
        expect.stringContaining('Invalid platform')
      );
    });

    it('should reject invalid platform values', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const result1 = mapConversations(conversations, 'facebook' as any);
      const result2 = mapConversations(conversations, 'whatsapp' as any);
      const result3 = mapConversations(conversations, '' as any);
      const result4 = mapConversations(conversations, null as any);

      expect(result1.size).toBe(0);
      expect(result2.size).toBe(0);
      expect(result3.size).toBe(0);
      expect(result4.size).toBe(0);
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Invalid platform')
      );
    });

    it('should validate platform for all implementation versions', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv1',
          participants: {
            data: [{ id: 'user1' }]
          }
        }
      ];

      const invalidPlatform = 'invalid' as any;

      const result1 = mapConversations_v1(conversations, invalidPlatform);
      const result2 = mapConversations_v2(conversations, invalidPlatform);
      const result3 = mapConversations_v3(conversations, invalidPlatform);

      expect(result1.size).toBe(0);
      expect(result2.size).toBe(0);
      expect(result3.size).toBe(0);
    });
  });

  describe('Integration tests', () => {
    it('should handle complex real-world scenario', () => {
      const conversations: any[] = [
        {
          id: 'conv1',
          participants: {
            data: [
              { id: 'user1', name: 'Alice' },
              { id: 'user2', name: 'Bob' }
            ]
          }
        },
        null,
        {
          id: 'conv2',
          participants: {
            data: [{ id: 'user1', name: 'Alice Duplicate' }]
          }
        },
        {
          id: 'conv3'
        },
        {
          id: 'conv4',
          participants: {
            data: [{ id: 'user3', name: 'Charlie' }]
          }
        },
        undefined,
        {
          id: 'conv5',
          participants: {
            data: []
          }
        }
      ];

      const result = mapConversations(conversations, 'messenger');

      expect(result.size).toBe(3);
      expect(result.get('user1')?.id).toBe('conv1');
      expect(result.get('user2')?.id).toBe('conv1');
      expect(result.get('user3')?.id).toBe('conv4');
    });
  });
});
