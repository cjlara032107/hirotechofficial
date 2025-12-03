import { z } from 'zod';

/**
 * Validates if a string is a valid UUID format
 * @param id - The string to validate
 * @returns true if valid UUID, false otherwise
 */
export function isValidUUID(id: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(id);
}

/**
 * Validates if a string is a valid CUID format
 * CUIDs are used by Prisma and start with 'c' followed by alphanumeric characters
 * Standard CUIDs are 25 characters, but we accept 20+ to handle variations
 * @param id - The string to validate
 * @returns true if valid CUID, false otherwise
 */
export function isValidCUID(id: string): boolean {
  // CUID format: starts with 'c' (lowercase) followed by at least 19 alphanumeric characters
  // Standard CUIDs are 25 chars (c + 24 chars), but we accept 20+ for flexibility
  const cuidRegex = /^c[0-9a-z]{19,}$/i;
  return cuidRegex.test(id) && id.length >= 20;
}

/**
 * Validates if a string is a valid UUID or CUID format
 * @param id - The string to validate
 * @returns true if valid UUID or CUID, false otherwise
 */
export function isValidID(id: string): boolean {
  return isValidUUID(id) || isValidCUID(id);
}

/**
 * Zod schema for UUID validation
 */
export const uuidSchema = z.string().uuid('Invalid UUID format');

/**
 * Validates a UUID or CUID and returns an error response if invalid
 * This function accepts both UUID and CUID formats since Prisma uses CUIDs
 * @param id - The ID string to validate (UUID or CUID)
 * @returns null if valid, or an object with error property if invalid
 */
export function validateUUID(id: string): { error: { message: string; status: number } } | null {
  if (!isValidID(id)) {
    return {
      error: {
        message: 'Invalid ID format. Must be a valid UUID or CUID.',
        status: 400,
      },
    };
  }
  return null;
}

