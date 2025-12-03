/**
 * Formatted error object structure
 */
export interface FormattedError {
  platform: string;
  id: string;
  error: string;
  code?: number;
}

/**
 * Truncation indicator object
 */
export interface TruncationIndicator {
  platform: string;
  id: string;
  error: string;
  code?: never;
}

/**
 * Input error type - can be an object with error properties, a string, or null/undefined
 */
type InputError = 
  | { platform?: string; id?: string; error?: string; code?: number }
  | string
  | null
  | undefined;

/**
 * Aggregates and formats errors from contact processing for inclusion in job status.
 * 
 * This is a pure function that:
 * - Formats errors to a consistent structure: `{ platform: string, id: string, error: string, code?: number }`
 * - Limits array size to maxErrors (default 100)
 * - Adds truncation indicator when limit exceeded
 * - Handles empty errors array
 * - Handles mixed error types (objects and strings)
 * 
 * @param errors - Array of error objects or strings
 * @param maxErrors - Maximum number of errors to include (default: 100)
 * @returns Array of formatted error objects, with optional truncation indicator
 * 
 * @example
 * ```typescript
 * const errors = [
 *   { platform: 'Messenger', id: '123', error: 'Rate limited', code: 613 },
 *   'Simple string error',
 *   { platform: 'Instagram', id: '456', error: 'Invalid token' }
 * ];
 * const formatted = aggregateErrors(errors, 2);
 * // Returns: [
 * //   { platform: 'Messenger', id: '123', error: 'Rate limited', code: 613 },
 * //   { platform: 'Unknown', id: 'unknown', error: 'Simple string error' },
 * //   { platform: 'System', id: 'truncated', error: '... and 1 more error(s) truncated' }
 * // ]
 * ```
 */
export function aggregateErrors(
  errors: InputError[],
  maxErrors: number = 100
): Array<FormattedError | TruncationIndicator> {
  // Handle empty array or null/undefined
  if (!errors || errors.length === 0) {
    return [];
  }

  // Ensure maxErrors is a valid positive integer
  const validMaxErrors = Math.max(0, Math.floor(maxErrors));

  // Filter out null/undefined values and format errors to consistent structure
  const formatted: FormattedError[] = errors
    .filter((error) => error != null) // Filter out null/undefined
    .map((error) => {
      // Handle string errors
      if (typeof error === 'string') {
        return {
          platform: 'Unknown',
          id: 'unknown',
          error: error,
        };
      }

      // Handle object errors
      return {
        platform: error.platform || 'Unknown',
        id: error.id || 'unknown',
        error: error.error || 'Unknown error',
        code: error.code,
      };
    });

  // If all errors were filtered out, return empty array
  if (formatted.length === 0) {
    return [];
  }

  // Check if truncation is needed
  if (formatted.length <= validMaxErrors) {
    return formatted;
  }

  // Truncate and add indicator
  const truncated = formatted.slice(0, validMaxErrors);
  const remainingCount = formatted.length - validMaxErrors;
  
  const truncationIndicator: TruncationIndicator = {
    platform: 'System',
    id: 'truncated',
    error: `... and ${remainingCount} more error(s) truncated`,
  };

  return [...truncated, truncationIndicator];
}

