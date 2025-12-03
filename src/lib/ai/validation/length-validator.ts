/**
 * Response Length Validation Utility
 * TASK-008: Validate that AI responses meet minimum length requirements
 */

export interface LengthValidationResult {
  valid: boolean;
  length: number;
  meetsMinimum: boolean;
  exceedsMaximum: boolean;
}

/**
 * Implementation v1: Direct validation with early returns
 * Approach: Simple if-else chain with early returns for clarity
 */
export function validateResponseLength_v1(
  response: string,
  minLength: number = 500,
  maxLength?: number
): LengthValidationResult {
  const length = response.length;
  const max = maxLength ?? 100000;
  
  const meetsMinimum = length >= minLength;
  const exceedsMaximum = length > max;
  const valid = meetsMinimum && !exceedsMaximum;
  
  return {
    valid,
    length,
    meetsMinimum,
    exceedsMaximum,
  };
}

/**
 * Implementation v2: Functional approach with helper functions
 * Approach: Break down validation into smaller, composable checks
 */
function checkMinimum(length: number, min: number): boolean {
  return length >= min;
}

function checkMaximum(length: number, max: number): boolean {
  return length > max;
}

export function validateResponseLength_v2(
  response: string,
  minLength: number = 500,
  maxLength?: number
): LengthValidationResult {
  const length = response.length;
  const max = maxLength ?? 100000;
  
  const meetsMinimum = checkMinimum(length, minLength);
  const exceedsMaximum = checkMaximum(length, max);
  
  return {
    valid: meetsMinimum && !exceedsMaximum,
    length,
    meetsMinimum,
    exceedsMaximum,
  };
}

/**
 * Implementation v3: Object-oriented approach with validation rules
 * Approach: Use a validation rules object for extensibility
 */
interface ValidationRules {
  minLength: number;
  maxLength: number;
}

function createRules(minLength: number, maxLength?: number): ValidationRules {
  return {
    minLength,
    maxLength: maxLength ?? 100000,
  };
}

export function validateResponseLength_v3(
  response: string,
  minLength: number = 500,
  maxLength?: number
): LengthValidationResult {
  const length = response.length;
  const rules = createRules(minLength, maxLength);
  
  const meetsMinimum = length >= rules.minLength;
  const exceedsMaximum = length > rules.maxLength;
  
  return {
    valid: meetsMinimum && !exceedsMaximum,
    length,
    meetsMinimum,
    exceedsMaximum,
  };
}

// Default export: Use v1 (to be updated after performance testing)
export const validateResponseLength = validateResponseLength_v1;









