/**
 * Numeric Input Validation Utilities
 * Centralized validation for all numeric inputs with range checking
 */

export interface NumericValidationOptions {
  min?: number;
  max?: number;
  integer?: boolean;
  positive?: boolean;
  allowZero?: boolean;
  fieldName?: string;
}

export interface NumericValidationResult {
  valid: boolean;
  errors: string[];
  value?: number;
}

/**
 * Validate a single numeric value
 */
export function validateNumeric(
  value: unknown,
  options: NumericValidationOptions = {}
): NumericValidationResult {
  const errors: string[] = [];
  const {
    min,
    max,
    integer = false,
    positive = false,
    allowZero = true,
    fieldName = 'Value',
  } = options;

  // Check if value is a number
  if (typeof value !== 'number') {
    // Try to parse string numbers
    if (typeof value === 'string') {
      const parsed = Number(value);
      if (isNaN(parsed)) {
        errors.push(`${fieldName} must be a valid number`);
        return { valid: false, errors };
      }
      return validateNumeric(parsed, options);
    }
    errors.push(`${fieldName} must be a number`);
    return { valid: false, errors };
  }

  // Check for NaN or Infinity
  if (isNaN(value) || !isFinite(value)) {
    errors.push(`${fieldName} must be a finite number`);
    return { valid: false, errors };
  }

  // Check if integer is required
  if (integer && !Number.isInteger(value)) {
    errors.push(`${fieldName} must be an integer`);
  }

  // Check if positive is required
  if (positive && value <= 0) {
    if (value === 0 && !allowZero) {
      errors.push(`${fieldName} must be greater than zero`);
    } else if (value < 0) {
      errors.push(`${fieldName} must be positive`);
    }
  }

  // Check minimum value
  if (min !== undefined && value < min) {
    errors.push(`${fieldName} must be at least ${min}`);
  }

  // Check maximum value
  if (max !== undefined && value > max) {
    errors.push(`${fieldName} must be at most ${max}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    value,
  };
}

/**
 * Validate multiple numeric values at once
 */
export function validateNumericFields(
  fields: Record<string, { value: unknown; options: NumericValidationOptions }>
): NumericValidationResult {
  const allErrors: string[] = [];
  const validatedValues: Record<string, number> = {};

  for (const [key, { value, options }] of Object.entries(fields)) {
    const result = validateNumeric(value, { ...options, fieldName: key });
    if (!result.valid) {
      allErrors.push(...result.errors);
    } else if (result.value !== undefined) {
      validatedValues[key] = result.value;
    }
  }

  return {
    valid: allErrors.length === 0,
    errors: allErrors,
  };
}

/**
 * Common numeric validation presets
 */
export const NumericPresets = {
  /**
   * Validate a percentage (0-100)
   */
  percentage: (value: unknown, fieldName = 'Percentage'): NumericValidationResult =>
    validateNumeric(value, { min: 0, max: 100, fieldName }),

  /**
   * Validate a positive integer
   */
  positiveInteger: (value: unknown, fieldName = 'Value'): NumericValidationResult =>
    validateNumeric(value, { integer: true, positive: true, allowZero: false, fieldName }),

  /**
   * Validate a non-negative integer (0 or positive)
   */
  nonNegativeInteger: (value: unknown, fieldName = 'Value'): NumericValidationResult =>
    validateNumeric(value, { integer: true, min: 0, fieldName }),

  /**
   * Validate a timestamp (positive integer, reasonable range)
   */
  timestamp: (value: unknown, fieldName = 'Timestamp'): NumericValidationResult =>
    validateNumeric(value, {
      integer: true,
      positive: true,
      min: 0,
      max: 4102444800000, // Year 2100 in milliseconds
      fieldName,
    }),

  /**
   * Validate a count/limit (positive integer with max)
   */
  count: (
    value: unknown,
    max: number = 10000,
    fieldName = 'Count'
  ): NumericValidationResult =>
    validateNumeric(value, { integer: true, positive: true, min: 1, max, fieldName }),

  /**
   * Validate a score (0-100)
   */
  score: (value: unknown, fieldName = 'Score'): NumericValidationResult =>
    validateNumeric(value, { min: 0, max: 100, fieldName }),

  /**
   * Validate a rate limit (positive integer, reasonable range)
   */
  rateLimit: (value: unknown, fieldName = 'Rate Limit'): NumericValidationResult =>
    validateNumeric(value, {
      integer: true,
      positive: true,
      min: 1,
      max: 100000,
      fieldName,
    }),

  /**
   * Validate time interval in minutes
   */
  timeIntervalMinutes: (value: unknown, fieldName = 'Time Interval'): NumericValidationResult =>
    validateNumeric(value, {
      integer: true,
      positive: true,
      min: 1,
      max: 1440, // Max 24 hours in minutes
      fieldName,
    }),

  /**
   * Validate time interval in hours
   */
  timeIntervalHours: (value: unknown, fieldName = 'Time Interval'): NumericValidationResult =>
    validateNumeric(value, {
      integer: true,
      positive: true,
      min: 1,
      max: 168, // Max 1 week in hours
      fieldName,
    }),

  /**
   * Validate time interval in days
   */
  timeIntervalDays: (value: unknown, fieldName = 'Time Interval'): NumericValidationResult =>
    validateNumeric(value, {
      integer: true,
      positive: true,
      min: 1,
      max: 365, // Max 1 year in days
      fieldName,
    }),

  /**
   * Validate hour of day (0-23)
   */
  hourOfDay: (value: unknown, fieldName = 'Hour'): NumericValidationResult =>
    validateNumeric(value, {
      integer: true,
      min: 0,
      max: 23,
      fieldName,
    }),

  /**
   * Validate page number (positive integer, min 1)
   */
  pageNumber: (value: unknown, fieldName = 'Page'): NumericValidationResult =>
    validateNumeric(value, { integer: true, positive: true, min: 1, max: 10000, fieldName }),

  /**
   * Validate limit/per page (positive integer, reasonable range)
   */
  limit: (value: unknown, max: number = 100, fieldName = 'Limit'): NumericValidationResult =>
    validateNumeric(value, { integer: true, positive: true, min: 1, max, fieldName }),
};









