/**
 * TASK-008: Create Conversation Mapping Utility
 * 
 * Maps conversations to participant IDs for O(1) lookup during analysis.
 * Handles invalid structures gracefully and uses first occurrence for duplicates.
 */

// Type definitions based on Facebook API structure
export interface ConversationParticipant {
  id: string;
  name?: string;
}

export interface Conversation {
  id: string;
  participants?: {
    data?: ConversationParticipant[];
  };
  [key: string]: unknown;
}

export type Platform = 'messenger' | 'instagram';

/**
 * Version 1: Imperative approach with explicit validation
 * - Uses traditional for loop for clarity
 * - Validates each conversation before processing
 * - Logs warnings for invalid structures
 */
export function mapConversations_v1(
  conversations: Conversation[],
  platform: Platform
): Map<string, Conversation> {
  const result = new Map<string, Conversation>();

  // Validate platform parameter
  if (platform !== 'messenger' && platform !== 'instagram') {
    console.warn(`[Map Conversations] Invalid platform: ${platform}. Must be 'messenger' or 'instagram'`);
    return result;
  }

  if (!Array.isArray(conversations)) {
    console.warn(`[Map Conversations] Invalid conversations input for platform ${platform}`);
    return result;
  }

  for (let i = 0; i < conversations.length; i++) {
    const conversation = conversations[i];
    
    if (!conversation || typeof conversation !== 'object') {
      console.warn(`[Map Conversations] Skipping invalid conversation at index ${i}`);
      continue;
    }

    const participants = conversation.participants?.data;
    
    if (!Array.isArray(participants) || participants.length === 0) {
      console.warn(`[Map Conversations] Conversation ${conversation.id} has no valid participants`);
      continue;
    }

    for (const participant of participants) {
      if (participant?.id && typeof participant.id === 'string') {
        // Use first occurrence (don't overwrite if already exists)
        if (!result.has(participant.id)) {
          result.set(participant.id, conversation);
        }
      }
    }
  }

  return result;
}

/**
 * Version 2: Functional approach with reduce
 * - Uses reduce for functional programming style
 * - Filters invalid conversations upfront
 * - More concise but potentially less readable
 */
export function mapConversations_v2(
  conversations: Conversation[],
  platform: Platform
): Map<string, Conversation> {
  // Validate platform parameter
  if (platform !== 'messenger' && platform !== 'instagram') {
    console.warn(`[Map Conversations] Invalid platform: ${platform}. Must be 'messenger' or 'instagram'`);
    return new Map();
  }

  if (!Array.isArray(conversations)) {
    console.warn(`[Map Conversations] Invalid conversations input for platform ${platform}`);
    return new Map();
  }

  return conversations
    .filter((conversation): conversation is Conversation => {
      if (!conversation || typeof conversation !== 'object') {
        console.warn(`[Map Conversations] Skipping invalid conversation`);
        return false;
      }
      const hasValidParticipants = Array.isArray(conversation.participants?.data) && 
                                   conversation.participants.data.length > 0;
      if (!hasValidParticipants) {
        console.warn(`[Map Conversations] Conversation ${conversation.id} has no valid participants`);
        return false;
      }
      return true;
    })
    .reduce((map, conversation) => {
      const participants = conversation.participants!.data!;
      participants.forEach(participant => {
        if (participant?.id && typeof participant.id === 'string' && !map.has(participant.id)) {
          map.set(participant.id, conversation);
        }
      });
      return map;
    }, new Map<string, Conversation>());
}

/**
 * Version 3: Early validation with forEach and helper
 * - Separates validation logic into helper function
 * - Uses forEach for iteration
 * - Most readable with clear separation of concerns
 */
function isValidParticipant(participant: unknown): participant is ConversationParticipant {
  return (
    typeof participant === 'object' &&
    participant !== null &&
    'id' in participant &&
    typeof (participant as ConversationParticipant).id === 'string'
  );
}

function hasValidParticipants(conversation: unknown): conversation is Conversation & { participants: { data: ConversationParticipant[] } } {
  return (
    typeof conversation === 'object' &&
    conversation !== null &&
    'participants' in conversation &&
    typeof (conversation as Conversation).participants === 'object' &&
    (conversation as Conversation).participants !== null &&
    'data' in (conversation as Conversation).participants! &&
    Array.isArray((conversation as Conversation).participants!.data) &&
    (conversation as Conversation).participants!.data!.length > 0
  );
}

export function mapConversations_v3(
  conversations: Conversation[],
  platform: Platform
): Map<string, Conversation> {
  const result = new Map<string, Conversation>();

  // Validate platform parameter
  if (platform !== 'messenger' && platform !== 'instagram') {
    console.warn(`[Map Conversations] Invalid platform: ${platform}. Must be 'messenger' or 'instagram'`);
    return result;
  }

  if (!Array.isArray(conversations)) {
    console.warn(`[Map Conversations] Invalid conversations input for platform ${platform}`);
    return result;
  }

  conversations.forEach((conversation, index) => {
    if (!hasValidParticipants(conversation)) {
      console.warn(`[Map Conversations] Conversation at index ${index} (${conversation?.id || 'unknown'}) has invalid structure`);
      return;
    }

    conversation.participants.data.forEach(participant => {
      if (isValidParticipant(participant) && !result.has(participant.id)) {
        result.set(participant.id, conversation);
      }
    });
  });

  return result;
}

// Export default (will be replaced with best implementation after testing)
export const mapConversations = mapConversations_v1;

