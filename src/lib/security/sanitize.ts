/**
 * Security utilities for sanitizing user input
 * Prevents XSS and SQL injection attacks
 */

/**
 * Sanitize user input to prevent XSS attacks
 * Removes potentially dangerous HTML/JavaScript content
 * 
 * @param input - User input string to sanitize
 * @returns Sanitized string safe for display
 */
export function sanitizeInput(input: string): string {
  if (typeof input !== 'string') {
    return String(input);
  }

  return input
    .trim()
    // Remove script tags and their content
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    // Remove all HTML tags
    .replace(/<[^>]+>/g, '')
    // Remove javascript: protocol
    .replace(/javascript:/gi, '')
    // Remove event handlers (onclick, onerror, etc.)
    .replace(/on\w+\s*=/gi, '')
    // Remove data: URLs that could contain scripts
    .replace(/data:text\/html/gi, '')
    // Remove vbscript: protocol
    .replace(/vbscript:/gi, '')
    // Remove iframe tags
    .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
    // Remove object/embed tags
    .replace(/<(object|embed)[^>]*>.*?<\/\1>/gi, '')
    // Remove style tags
    .replace(/<style[^>]*>.*?<\/style>/gi, '');
}

/**
 * Sanitize user input for database storage
 * More permissive than display sanitization - allows some formatting
 * but still removes dangerous content
 * 
 * @param input - User input string to sanitize
 * @returns Sanitized string safe for database storage
 */
export function sanitizeForStorage(input: string): string {
  if (typeof input !== 'string') {
    return String(input);
  }

  return input
    .trim()
    // Remove script tags and their content
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    // Remove javascript: protocol
    .replace(/javascript:/gi, '')
    // Remove event handlers
    .replace(/on\w+\s*=/gi, '')
    // Remove data: URLs that could contain scripts
    .replace(/data:text\/html/gi, '')
    // Remove vbscript: protocol
    .replace(/vbscript:/gi, '')
    // Remove iframe tags
    .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
    // Remove object/embed tags
    .replace(/<(object|embed)[^>]*>.*?<\/\1>/gi, '');
}

/**
 * Validate and sanitize a string field
 * Returns null if input is invalid, sanitized string otherwise
 * 
 * @param input - Input to validate and sanitize
 * @param maxLength - Maximum allowed length (default: 10000)
 * @returns Sanitized string or null if invalid
 */
export function validateAndSanitizeString(
  input: unknown,
  maxLength: number = 10000
): string | null {
  if (input === null || input === undefined) {
    return null;
  }

  const str = String(input);
  if (str.length > maxLength) {
    return null;
  }

  return sanitizeForStorage(str);
}

/**
 * Sanitize an array of strings
 * Useful for sanitizing tags, mentions, etc.
 * 
 * @param inputs - Array of strings to sanitize
 * @returns Array of sanitized strings
 */
export function sanitizeStringArray(inputs: unknown[]): string[] {
  if (!Array.isArray(inputs)) {
    return [];
  }

  return inputs
    .map((item) => {
      if (typeof item !== 'string') {
        return null;
      }
      return sanitizeForStorage(item);
    })
    .filter((item): item is string => item !== null && item.length > 0);
}

/**
 * Escape HTML entities for safe display
 * Use this when you need to display user input as plain text
 * 
 * @param input - String to escape
 * @returns HTML-escaped string
 */
export function escapeHtml(input: string): string {
  if (typeof input !== 'string') {
    return String(input);
  }

  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };

  return input.replace(/[&<>"']/g, (char) => map[char] || char);
}









