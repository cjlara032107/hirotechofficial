/**
 * Default/fallback best contact times when insufficient message data is available.
 * Based on general best practices for business communication.
 */

import { formatBestContactTimesForStorage } from './best-contact-times';

export interface DefaultContactTimesOptions {
  /**
   * Whether to mark these as default/fallback times (lower confidence)
   */
  markAsDefault?: boolean;
}

/**
 * Generate default best contact times based on general best practices.
 * These are used when a contact doesn't have enough message history.
 * 
 * Best practices:
 * - Weekdays (Monday-Friday) are generally better than weekends
 * - Morning hours (9 AM - 12 PM) and afternoon hours (2 PM - 5 PM) are optimal
 * - Avoid early morning (before 9 AM) and late evening (after 6 PM)
 */
export function getDefaultBestContactTimes(
  options: DefaultContactTimesOptions = {}
): Record<string, unknown> {
  const { markAsDefault = true } = options;

  // Default best contact times based on general business communication best practices
  const defaultTimes = [
    {
      dayOfWeek: 'Monday',
      timeRange: '9:00 AM - 11:00 AM',
      confidence: markAsDefault ? 50 : 60, // Lower confidence for defaults
      averageReplyTime: undefined,
      messageCount: 0,
      isDefault: markAsDefault,
    },
    {
      dayOfWeek: 'Tuesday',
      timeRange: '9:00 AM - 11:00 AM',
      confidence: markAsDefault ? 50 : 60,
      averageReplyTime: undefined,
      messageCount: 0,
      isDefault: markAsDefault,
    },
    {
      dayOfWeek: 'Wednesday',
      timeRange: '2:00 PM - 4:00 PM',
      confidence: markAsDefault ? 50 : 60,
      averageReplyTime: undefined,
      messageCount: 0,
      isDefault: markAsDefault,
    },
    {
      dayOfWeek: 'Thursday',
      timeRange: '2:00 PM - 4:00 PM',
      confidence: markAsDefault ? 50 : 60,
      averageReplyTime: undefined,
      messageCount: 0,
      isDefault: markAsDefault,
    },
    {
      dayOfWeek: 'Friday',
      timeRange: '9:00 AM - 11:00 AM',
      confidence: markAsDefault ? 45 : 55, // Slightly lower for Friday
      averageReplyTime: undefined,
      messageCount: 0,
      isDefault: markAsDefault,
    },
  ];

  return {
    bestContactTimes: defaultTimes,
    totalMessagesAnalyzed: 0,
    averageReplyTime: undefined,
    fastestReplyTime: undefined,
    slowestReplyTime: undefined,
    computedAt: new Date().toISOString(),
    isDefault: markAsDefault,
    note: markAsDefault 
      ? 'These are default best contact times based on general best practices. More accurate times will be available once you have at least 2 messages with this contact.'
      : undefined,
  };
}









