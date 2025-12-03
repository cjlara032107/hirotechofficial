/**
 * Timezone utilities for Philippine Time (PHT, UTC+8)
 * All date/time operations in the application should use these utilities
 * to ensure consistent Philippine timezone handling.
 */

export const PHILIPPINE_TIMEZONE = 'Asia/Manila';
export const PHT_UTC_OFFSET_HOURS = 8;

/**
 * Get current date/time in Philippine timezone
 */
export function getNowInPHT(): Date {
  return new Date(new Date().toLocaleString('en-US', { timeZone: PHILIPPINE_TIMEZONE }));
}

/**
 * Convert a UTC date to Philippine time
 */
export function toPHT(date: Date): Date {
  // Get the date as a string in PHT, then create a new Date object
  // This preserves the local time values but in PHT context
  const phtString = date.toLocaleString('en-US', { timeZone: PHILIPPINE_TIMEZONE });
  return new Date(phtString);
}

/**
 * Get current date/time as a Date object representing Philippine time
 * This is the main function to use instead of new Date()
 */
export function nowPHT(): Date {
  return getNowInPHT();
}

/**
 * Format a date/time in Philippine timezone with 12-hour format
 * Returns format like "9:00 AM" or "2:30 PM"
 */
export function formatTimePHT(date: Date, options?: Intl.DateTimeFormatOptions): string {
  return date.toLocaleTimeString('en-US', {
    timeZone: PHILIPPINE_TIMEZONE,
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    ...options,
  });
}

/**
 * Format a date/time range in Philippine timezone
 * Returns format like "9:00 AM - 11:00 AM"
 */
export function formatTimeRangePHT(startDate: Date, endDate: Date): string {
  const start = formatTimePHT(startDate);
  const end = formatTimePHT(endDate);
  return `${start} - ${end}`;
}

/**
 * Format a date in Philippine timezone
 * Returns format like "January 15, 2025"
 */
export function formatDatePHT(date: Date, options?: Intl.DateTimeFormatOptions): string {
  return date.toLocaleDateString('en-US', {
    timeZone: PHILIPPINE_TIMEZONE,
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    ...options,
  });
}

/**
 * Format date and time in Philippine timezone
 * Returns format like "January 15, 2025, 9:00 AM"
 */
export function formatDateTimePHT(date: Date, options?: Intl.DateTimeFormatOptions): string {
  return date.toLocaleString('en-US', {
    timeZone: PHILIPPINE_TIMEZONE,
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    ...options,
  });
}

/**
 * Get hours and minutes from a Date object in Philippine timezone
 */
export function getHoursMinutesPHT(date: Date): { hour: number; minute: number } {
  const phtDate = new Date(date.toLocaleString('en-US', { timeZone: PHILIPPINE_TIMEZONE }));
  return {
    hour: phtDate.getHours(),
    minute: phtDate.getMinutes(),
  };
}

/**
 * Get day of week in Philippine timezone
 * Returns 0-6 where 0 = Sunday, 1 = Monday, etc.
 */
export function getDayOfWeekPHT(date: Date): number {
  const phtDate = new Date(date.toLocaleString('en-US', { timeZone: PHILIPPINE_TIMEZONE }));
  return phtDate.getDay();
}

/**
 * Get day name in Philippine timezone
 * Returns "Monday", "Tuesday", etc.
 */
export function getDayNamePHT(date: Date): string {
  const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const dayIndex = getDayOfWeekPHT(date);
  return dayNames[dayIndex];
}

/**
 * Create a Date object for a specific time in Philippine timezone
 * @param hour - Hour in 24-hour format (0-23)
 * @param minute - Minute (0-59)
 * @param date - Optional date to use (defaults to today)
 */
export function createDatePHT(hour: number, minute: number, date?: Date): Date {
  const baseDate = date ? new Date(date) : new Date();
  const phtString = baseDate.toLocaleString('en-US', { timeZone: PHILIPPINE_TIMEZONE });
  const phtDate = new Date(phtString);
  phtDate.setHours(hour, minute, 0, 0);
  
  // Convert back to UTC equivalent for the PHT time
  // We need to adjust for the 8-hour offset
  const utcDate = new Date(phtDate.getTime() - PHT_UTC_OFFSET_HOURS * 60 * 60 * 1000);
  return utcDate;
}

/**
 * Check if current time in PHT is within a time window
 * @param startHour - Start hour in 24-hour format (0-23)
 * @param startMinute - Start minute (0-59)
 * @param endHour - End hour in 24-hour format (0-23)
 * @param endMinute - End minute (0-59)
 */
export function isTimeInWindowPHT(
  startHour: number,
  startMinute: number,
  endHour: number,
  endMinute: number,
  currentDate?: Date
): boolean {
  const now = currentDate ? getHoursMinutesPHT(currentDate) : getHoursMinutesPHT(nowPHT());
  const currentTimeMinutes = now.hour * 60 + now.minute;
  const startTimeMinutes = startHour * 60 + startMinute;
  const endTimeMinutes = endHour * 60 + endMinute;

  // Handle time windows that cross midnight
  if (endTimeMinutes < startTimeMinutes) {
    // Window crosses midnight (e.g., 22:00 - 02:00)
    return currentTimeMinutes >= startTimeMinutes || currentTimeMinutes <= endTimeMinutes;
  } else {
    // Normal window (e.g., 09:00 - 17:00)
    return currentTimeMinutes >= startTimeMinutes && currentTimeMinutes <= endTimeMinutes;
  }
}

/**
 * Convert UTC cron schedule to PHT equivalent
 * For example, to run at midnight PHT (which is 4 PM UTC previous day):
 * - PHT midnight = UTC 16:00 (previous day)
 * - Cron: "0 16 * * *" (runs at 4 PM UTC = midnight PHT)
 */
export function getCronForPHT(hourPHT: number, minutePHT: number = 0): string {
  // PHT is UTC+8, so we subtract 8 hours
  let utcHour = hourPHT - PHT_UTC_OFFSET_HOURS;
  let dayOffset = 0;

  if (utcHour < 0) {
    utcHour += 24;
    dayOffset = -1; // Previous day
  }

  // Note: Cron doesn't support day offsets easily, so we return the UTC hour
  // The caller should adjust the day pattern if needed
  return `${minutePHT} ${utcHour} * * *`;
}




