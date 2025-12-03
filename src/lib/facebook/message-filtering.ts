/**
 * Utilities for filtering and processing messages from conversations
 */

/**
 * Filters out system messages and messages without text content
 * @param messages - Array of messages from Facebook API
 * @param pageId - The Facebook page ID to identify system messages
 * @returns Filtered array of user messages only
 */
export function filterSystemMessages(
  messages: Array<{
    message?: string;
    from?: { id?: string; name?: string; username?: string };
  }>,
  pageId?: string
): Array<{
  from: string;
  text: string;
  timestamp?: Date;
  isFromBusiness?: boolean;
}> {
  if (!messages || messages.length === 0) {
    return [];
  }

  return messages
    .filter((msg) => {
      // Filter out messages without text content
      if (!msg.message || !msg.message.trim()) {
        return false;
      }

      // Filter out messages from the page itself (system/automated)
      if (pageId && msg.from?.id === pageId) {
        return false;
      }
      if (msg.from?.name?.includes('Page')) {
        return false;
      }

      return true;
    })
    .map((msg) => ({
      from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
      text: msg.message || '',
      timestamp: undefined, // Will be set by caller if available
      isFromBusiness: false,
    }));
}

/**
 * Filters out system messages from database Message records
 * @param messages - Array of Message records from database
 * @returns Filtered array of user messages only (isFromBusiness = false)
 */
export function filterSystemMessagesFromDB(
  messages: Array<{
    content: string;
    isFromBusiness: boolean;
    createdAt: Date;
  }>
): Array<{
  content: string;
  isFromBusiness: boolean;
  createdAt: Date;
}> {
  if (!messages || messages.length === 0) {
    return [];
  }

  return messages.filter((msg) => {
    // Filter out messages without content
    if (!msg.content || !msg.content.trim()) {
      return false;
    }

    // Filter out system/business messages
    if (msg.isFromBusiness) {
      return false;
    }

    return true;
  });
}

/**
 * Checks if a conversation has any user messages (non-system messages)
 * @param messages - Array of messages
 * @param pageId - Optional Facebook page ID for API messages
 * @returns true if there are user messages, false otherwise
 */
export function hasUserMessages(
  messages: Array<{
    message?: string;
    from?: { id?: string; name?: string };
    isFromBusiness?: boolean;
    content?: string;
  }>,
  pageId?: string
): boolean {
  if (!messages || messages.length === 0) {
    return false;
  }

  return messages.some((msg) => {
    // Check if message has content
    const hasContent = (msg.message || msg.content || '').trim().length > 0;
    if (!hasContent) {
      return false;
    }

    // Check if it's a user message (not from business/system)
    if (msg.isFromBusiness !== undefined) {
      return !msg.isFromBusiness;
    }

    // For API messages, check if from page
    if (pageId && msg.from?.id === pageId) {
      return false;
    }
    if (msg.from?.name?.includes('Page')) {
      return false;
    }

    return true;
  });
}









