/**
 * Utility functions for formatting user-friendly error messages
 * Converts technical errors into clear, actionable messages for users
 */

export function formatUserFriendlyError(error: unknown): string {
  if (!error) {
    return 'An unexpected error occurred. Please try again.';
  }

  // Handle objects with message property
  let errorMessage: string;
  if (error instanceof Error) {
    errorMessage = error.message;
  } else if (typeof error === 'object' && error !== null && 'message' in error) {
    errorMessage = String((error as { message: unknown }).message);
  } else {
    errorMessage = String(error);
  }

  // Handle [object Object] case
  if (errorMessage === '[object Object]') {
    return 'An unexpected error occurred. Please try again.';
  }

  const lowerMessage = errorMessage.toLowerCase();

  // Network and connection errors
  if (
    lowerMessage.includes('fetch') ||
    lowerMessage.includes('network') ||
    lowerMessage.includes('connection') ||
    lowerMessage.includes('econnrefused') ||
    lowerMessage.includes('failed to fetch')
  ) {
    return 'Unable to connect to the server. Please check your internet connection and try again.';
  }

  // Timeout errors
  if (lowerMessage.includes('timeout') || lowerMessage.includes('timed out')) {
    return 'The request took too long to complete. Please try again in a moment.';
  }

  // Authentication and authorization errors
  if (
    lowerMessage.includes('unauthorized') ||
    lowerMessage.includes('401') ||
    lowerMessage.includes('forbidden') ||
    lowerMessage.includes('403')
  ) {
    return 'You do not have permission to access this resource. Please login again or contact your administrator.';
  }

  // Token expiration
  if (
    lowerMessage.includes('token expired') ||
    lowerMessage.includes('token_expired') ||
    lowerMessage.includes('access token expired') ||
    lowerMessage.includes('190')
  ) {
    return 'Your Facebook connection has expired. Please reconnect your Facebook page in Settings.';
  }

  // Rate limiting
  if (
    lowerMessage.includes('rate limit') ||
    lowerMessage.includes('too many requests') ||
    lowerMessage.includes('429')
  ) {
    return 'Too many requests. Please wait a moment and try again.';
  }

  // Database errors
  if (
    lowerMessage.includes('database') ||
    lowerMessage.includes('prisma') ||
    lowerMessage.includes('p2002') ||
    lowerMessage.includes('unique constraint')
  ) {
    if (lowerMessage.includes('p2002') || lowerMessage.includes('unique constraint')) {
      return 'This item already exists. Please check and try again.';
    }
    return 'A database error occurred. Please try again, or contact support if the problem persists.';
  }

  // JSON parse errors (usually means server returned HTML instead of JSON)
  if (
    lowerMessage.includes('json') ||
    lowerMessage.includes('unexpected token') ||
    lowerMessage.includes('<!doctype')
  ) {
    return 'The server returned an unexpected response. Please refresh the page and try again.';
  }

  // Facebook API errors
  if (lowerMessage.includes('facebook') || lowerMessage.includes('graph api')) {
    if (lowerMessage.includes('permission') || lowerMessage.includes('insufficient')) {
      return 'Your Facebook page connection is missing required permissions. Please reconnect your page in Settings.';
    }
    return 'A Facebook API error occurred. Please try again, or reconnect your Facebook page if the problem persists.';
  }

  // Generic server errors
  if (lowerMessage.includes('500') || lowerMessage.includes('internal server error')) {
    return 'A server error occurred. Please try again in a moment. If the problem persists, contact support.';
  }

  // Not found errors
  if (lowerMessage.includes('404') || lowerMessage.includes('not found')) {
    return 'The requested item could not be found. It may have been deleted or moved.';
  }

  // Validation errors
  if (lowerMessage.includes('validation') || lowerMessage.includes('invalid')) {
    return 'The information provided is invalid. Please check your input and try again.';
  }

  // SQL query detection - remove SQL statements
  if (
    lowerMessage.includes('select') ||
    lowerMessage.includes('insert') ||
    lowerMessage.includes('update') ||
    lowerMessage.includes('delete') ||
    lowerMessage.includes('from ') ||
    lowerMessage.includes('where ')
  ) {
    return 'A database error occurred. Please try again, or contact support if the problem persists.';
  }

  // Default fallback - remove technical details
  const sanitized = errorMessage
    .replace(/at\s+.*/g, '') // Remove stack trace lines
    .replace(/\(.*?\)/g, '') // Remove file paths
    .replace(/\d+\.\d+\.\d+\.\d+/g, '') // Remove IP addresses
    .replace(/[a-zA-Z0-9]{20,}/g, '') // Remove long tokens/IDs
    .replace(/SELECT\s+.*?FROM/gi, '') // Remove SQL SELECT statements
    .replace(/FROM\s+\w+/gi, '') // Remove SQL FROM clauses
    .replace(/WHERE\s+.*/gi, '') // Remove SQL WHERE clauses
    .trim();

  if (sanitized.length < 10) {
    return 'An unexpected error occurred. Please try again.';
  }

  // If we still have a technical message, provide a generic one
  if (
    sanitized.includes('Error:') ||
    sanitized.includes('Exception:') ||
    sanitized.includes('TypeError:') ||
    sanitized.includes('ReferenceError:')
  ) {
    return 'An unexpected error occurred. Please refresh the page and try again.';
  }

  return sanitized.substring(0, 200); // Limit length
}

/**
 * Formats error messages specifically for sync operations
 */
export function formatSyncError(error: unknown): string {
  const baseMessage = formatUserFriendlyError(error);
  const errorMessage = error instanceof Error ? error.message : String(error);
  const lowerMessage = errorMessage.toLowerCase();

  // Add sync-specific context
  if (lowerMessage.includes('conversation') || lowerMessage.includes('message')) {
    return `Unable to sync conversations: ${baseMessage}`;
  }

  if (lowerMessage.includes('contact')) {
    return `Unable to sync contacts: ${baseMessage}`;
  }

  return `Sync failed: ${baseMessage}`;
}

/**
 * Formats error messages specifically for analysis operations
 */
export function formatAnalysisError(error: unknown): string {
  const baseMessage = formatUserFriendlyError(error);
  const errorMessage = error instanceof Error ? error.message : String(error);
  const lowerMessage = errorMessage.toLowerCase();

  if (lowerMessage.includes('ai') || lowerMessage.includes('openai') || lowerMessage.includes('nvidia')) {
    return `AI analysis failed: ${baseMessage}`;
  }

  return `Analysis failed: ${baseMessage}`;
}

