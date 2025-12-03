/**
 * Utility functions to check if current time matches a contact's best contact time
 * Supports multiple architecture patterns for queue management and rate limiting
 * All time checks are performed in Philippine Time (PHT, UTC+8)
 */

import { nowPHT, getDayNamePHT, isTimeInWindowPHT, getHoursMinutesPHT, createDatePHT } from '@/lib/utils/timezone';

interface BestContactTimeWindow {
  dayOfWeek: string; // "Monday", "Tuesday", etc.
  timeRange: string; // "9:00 AM - 10:00 AM" or "09:00-10:00"
  confidence?: number;
  averageReplyTime?: number;
  messageCount?: number;
}

interface BestContactTimesData {
  bestContactTimes?: BestContactTimeWindow[];
  totalMessagesAnalyzed?: number;
  averageReplyTime?: number;
  fastestReplyTime?: number;
  slowestReplyTime?: number;
  computedAt?: string;
}

/**
 * Parse time range string to hour and minute
 * Supports formats: "9:00 AM - 10:00 AM", "09:00-10:00", "9:00 AM-10:00 AM"
 */
function parseTimeRange(timeRange: string): { startHour: number; startMinute: number; endHour: number; endMinute: number } | null {
  try {
    // Normalize the time range string
    const normalized = timeRange.replace(/\s+/g, ' ').trim();
    
    // Try to match different formats
    // Format 1: "9:00 AM - 10:00 AM" or "9:00 AM-10:00 AM"
    const format1Match = normalized.match(/(\d{1,2}):(\d{2})\s*(AM|PM)\s*-\s*(\d{1,2}):(\d{2})\s*(AM|PM)/i);
    if (format1Match) {
      const startHour12 = parseInt(format1Match[1], 10);
      const startMinute = parseInt(format1Match[2], 10);
      const startPeriod = format1Match[3].toUpperCase();
      const endHour12 = parseInt(format1Match[4], 10);
      const endMinute = parseInt(format1Match[5], 10);
      const endPeriod = format1Match[6].toUpperCase();
      
      let startHour = startHour12;
      if (startPeriod === 'PM' && startHour12 !== 12) startHour += 12;
      if (startPeriod === 'AM' && startHour12 === 12) startHour = 0;
      
      let endHour = endHour12;
      if (endPeriod === 'PM' && endHour12 !== 12) endHour += 12;
      if (endPeriod === 'AM' && endHour12 === 12) endHour = 0;
      
      return { startHour, startMinute, endHour, endMinute };
    }
    
    // Format 2: "09:00-10:00" (24-hour format)
    const format2Match = normalized.match(/(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})/);
    if (format2Match) {
      return {
        startHour: parseInt(format2Match[1], 10),
        startMinute: parseInt(format2Match[2], 10),
        endHour: parseInt(format2Match[3], 10),
        endMinute: parseInt(format2Match[4], 10),
      };
    }
    
    return null;
  } catch (error) {
    console.error('[BestContactTimeChecker] Error parsing time range:', error, timeRange);
    return null;
  }
}

/**
 * Check if a day name matches the current day in Philippine timezone
 */
function isDayMatch(dayOfWeek: string, currentDate: Date): boolean {
  const currentDayName = getDayNamePHT(currentDate);
  return dayOfWeek.toLowerCase() === currentDayName.toLowerCase();
}

/**
 * Check if current time is within a time window (using PHT)
 */
function isTimeInWindow(
  currentDate: Date,
  startHour: number,
  startMinute: number,
  endHour: number,
  endMinute: number
): boolean {
  // Use PHT timezone for time comparison
  return isTimeInWindowPHT(startHour, startMinute, endHour, endMinute, currentDate);
}

/**
 * Check if current time matches any of the contact's best contact times
 * Returns true if current time is within any best contact time window
 * All times are checked in Philippine Time (PHT)
 */
export function isWithinBestContactTime(
  bestContactTimesData: BestContactTimesData | null | undefined,
  currentDate: Date = nowPHT()
): boolean {
  // If no best contact times data, return false (don't send)
  if (!bestContactTimesData || !bestContactTimesData.bestContactTimes) {
    return false;
  }

  const windows = bestContactTimesData.bestContactTimes;
  if (!Array.isArray(windows) || windows.length === 0) {
    return false;
  }

  // Check each window
  for (const window of windows) {
    if (!window.dayOfWeek || !window.timeRange) {
      continue;
    }

    // Check if day matches
    if (!isDayMatch(window.dayOfWeek, currentDate)) {
      continue;
    }

    // Parse and check time range
    const timeRange = parseTimeRange(window.timeRange);
    if (!timeRange) {
      console.warn('[BestContactTimeChecker] Could not parse time range:', window.timeRange);
      continue;
    }

    // Check if current time is within this window
    if (isTimeInWindow(
      currentDate,
      timeRange.startHour,
      timeRange.startMinute,
      timeRange.endHour,
      timeRange.endMinute
    )) {
      return true;
    }
  }

  return false;
}

/**
 * Get the next best contact time window (for queue scheduling)
 * Returns the next window that will occur, or null if none found
 */
export function getNextBestContactTimeWindow(
  bestContactTimesData: BestContactTimesData | null | undefined,
  currentDate: Date = nowPHT()
): { window: BestContactTimeWindow; nextOccurrence: Date } | null {
  if (!bestContactTimesData || !bestContactTimesData.bestContactTimes) {
    return null;
  }

  const windows = bestContactTimesData.bestContactTimes;
  if (!Array.isArray(windows) || windows.length === 0) {
    return null;
  }

  const dayNames = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const currentDayName = getDayNamePHT(currentDate);
  const currentTime = getHoursMinutesPHT(currentDate);
  const currentTimeMinutes = currentTime.hour * 60 + currentTime.minute;

  let nextWindow: { window: BestContactTimeWindow; nextOccurrence: Date } | null = null;
  let minTimeUntilNext = Infinity;

  // Check each window
  for (const window of windows) {
    if (!window.dayOfWeek || !window.timeRange) {
      continue;
    }

    const timeRange = parseTimeRange(window.timeRange);
    if (!timeRange) {
      continue;
    }

    const startTimeMinutes = timeRange.startHour * 60 + timeRange.startMinute;
    const dayIndex = dayNames.findIndex(d => d.toLowerCase() === window.dayOfWeek.toLowerCase());
    if (dayIndex === -1) continue;

    // Calculate days until this day of week (using PHT)
    const currentDayNamePHT = getDayNamePHT(currentDate);
    const currentDayIndexPHT = dayNames.findIndex(d => d.toLowerCase() === currentDayNamePHT.toLowerCase());
    const currentDayIndex = currentDayIndexPHT === -1 ? 0 : currentDayIndexPHT;
    
    let daysUntil = dayIndex - currentDayIndex;
    if (daysUntil < 0) daysUntil += 7;
    if (daysUntil === 0 && startTimeMinutes <= currentTimeMinutes) {
      // Today's window already passed, check next week
      daysUntil = 7;
    }

    // Create next occurrence in PHT, then convert to Date
    const nextOccurrence = createDatePHT(timeRange.startHour, timeRange.startMinute, currentDate);
    // Adjust for days until
    if (daysUntil > 0) {
      nextOccurrence.setDate(nextOccurrence.getDate() + daysUntil);
    }

    const timeUntilNext = nextOccurrence.getTime() - currentDate.getTime();
    if (timeUntilNext < minTimeUntilNext) {
      minTimeUntilNext = timeUntilNext;
      nextWindow = { window, nextOccurrence };
    }
  }

  return nextWindow;
}

/**
 * Architecture Option 1: Simple Check
 * Just check if current time matches - used in cron job
 */
export function shouldSendNow(
  bestContactTimesData: BestContactTimesData | null | undefined,
  currentDate: Date = nowPHT()
): boolean {
  return isWithinBestContactTime(bestContactTimesData, currentDate);
}

/**
 * Architecture Option 2: Queue-Based with Priority
 * Returns priority score (0-100) based on how close we are to best contact time
 * Higher score = higher priority
 */
export function getContactPriorityScore(
  bestContactTimesData: BestContactTimesData | null | undefined,
  currentDate: Date = nowPHT()
): number {
  if (!bestContactTimesData || !bestContactTimesData.bestContactTimes) {
    return 0; // No best contact times = lowest priority
  }

  // If currently in a best contact time window, return high priority
  if (isWithinBestContactTime(bestContactTimesData, currentDate)) {
    return 100;
  }

  // Calculate priority based on time until next window
  const nextWindow = getNextBestContactTimeWindow(bestContactTimesData, currentDate);
  if (!nextWindow) {
    return 0;
  }

  const timeUntilNext = nextWindow.nextOccurrence.getTime() - currentDate.getTime();
  const hoursUntilNext = timeUntilNext / (1000 * 60 * 60);

  // Priority decreases as time until next window increases
  // Within 1 hour = 90-100, within 6 hours = 50-90, within 24 hours = 10-50, >24 hours = 0-10
  if (hoursUntilNext <= 1) {
    return 90 + (1 - hoursUntilNext) * 10;
  } else if (hoursUntilNext <= 6) {
    return 50 + (6 - hoursUntilNext) / 5 * 40;
  } else if (hoursUntilNext <= 24) {
    return 10 + (24 - hoursUntilNext) / 18 * 40;
  } else {
    return Math.max(0, 10 - (hoursUntilNext - 24) / 24 * 10);
  }
}

/**
 * Architecture Option 3: Batch Processing with Time Windows
 * Groups contacts by their next best contact time window
 * Returns contacts grouped by when they should be processed
 */
export interface ContactTimeGroup {
  nextOccurrence: Date;
  window: BestContactTimeWindow;
  contactIds: string[];
}

export function groupContactsByBestTime(
  contacts: Array<{ id: string; bestContactTimes: BestContactTimesData | null | undefined }>,
  currentDate: Date = nowPHT()
): ContactTimeGroup[] {
  const groups: Map<string, ContactTimeGroup> = new Map();

  for (const contact of contacts) {
    const nextWindow = getNextBestContactTimeWindow(contact.bestContactTimes, currentDate);
    if (!nextWindow) {
      continue; // Skip contacts without best contact times
    }

    const key = `${nextWindow.nextOccurrence.toISOString()}_${nextWindow.window.timeRange}`;
    if (!groups.has(key)) {
      groups.set(key, {
        nextOccurrence: nextWindow.nextOccurrence,
        window: nextWindow.window,
        contactIds: [],
      });
    }

    groups.get(key)!.contactIds.push(contact.id);
  }

  // Sort by next occurrence time
  return Array.from(groups.values()).sort(
    (a, b) => a.nextOccurrence.getTime() - b.nextOccurrence.getTime()
  );
}






