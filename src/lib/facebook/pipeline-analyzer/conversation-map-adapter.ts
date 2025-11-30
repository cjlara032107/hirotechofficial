/**
 * Adapter: Converts TASK-008 conversation map to legacy format
 * 
 * This adapter bridges TASK-008 (Map<string, Conversation>) with existing code
 * that expects Map<string, { conversationId: string; updatedTime: string }>.
 * 
 * Allows gradual migration while maintaining backward compatibility.
 */

import { mapConversations } from './map-conversations';

// Type definitions matching TASK-008
interface Conversation {
  id: string;
  updated_time?: string;
  participants?: {
    data?: Array<{ id: string; name?: string }>;
  };
  [key: string]: unknown;
}

type Platform = 'messenger' | 'instagram';

interface LegacyConversationMap {
  conversationId: string;
  updatedTime: string;
}

/**
 * Converts TASK-008 conversation map to legacy format expected by existing code
 * 
 * @param conversations - Array of conversation objects
 * @param platform - Platform type ('messenger' | 'instagram')
 * @returns Map with participant ID as key and { conversationId, updatedTime } as value
 */
export function mapConversationsToLegacyFormat(
  conversations: Conversation[],
  platform: Platform
): Map<string, LegacyConversationMap> {
  const conversationMap = mapConversations(conversations, platform);
  const legacyMap = new Map<string, LegacyConversationMap>();
  
  for (const [participantId, conversation] of conversationMap.entries()) {
    legacyMap.set(participantId, {
      conversationId: conversation.id,
      updatedTime: (conversation.updated_time as string | undefined) || new Date().toISOString(),
    });
  }
  
  return legacyMap;
}

/**
 * Helper: Get conversation ID from map (for existing code compatibility)
 */
export function getConversationId(
  map: Map<string, LegacyConversationMap>,
  participantId: string
): string | undefined {
  return map.get(participantId)?.conversationId;
}

/**
 * Helper: Get updated time from map (for existing code compatibility)
 */
export function getUpdatedTime(
  map: Map<string, LegacyConversationMap>,
  participantId: string
): string | undefined {
  return map.get(participantId)?.updatedTime;
}

