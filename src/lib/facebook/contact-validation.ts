/**
 * Validation utilities for Facebook contact IDs (PSID and SID)
 */

/**
 * Validates a Messenger PSID format
 * PSIDs are typically numeric strings (can be very long, e.g., 15+ digits)
 * @param psid - The PSID to validate
 * @returns true if valid, false otherwise
 */
export function isValidPSID(psid: string | null | undefined): boolean {
  if (!psid || typeof psid !== 'string') {
    return false;
  }
  
  // PSID should be a non-empty string of digits
  // Can be very long (15+ digits), so we check it's all digits
  const trimmed = psid.trim();
  if (trimmed.length === 0) {
    return false;
  }
  
  // PSID should be numeric (all digits)
  return /^\d+$/.test(trimmed);
}

/**
 * Validates an Instagram SID format
 * SIDs are typically numeric strings (can be very long, e.g., 15+ digits)
 * @param sid - The SID to validate
 * @returns true if valid, false otherwise
 */
export function isValidSID(sid: string | null | undefined): boolean {
  if (!sid || typeof sid !== 'string') {
    return false;
  }
  
  // SID should be a non-empty string of digits
  const trimmed = sid.trim();
  if (trimmed.length === 0) {
    return false;
  }
  
  // SID should be numeric (all digits)
  return /^\d+$/.test(trimmed);
}

/**
 * Validates that a contact has at least one valid ID
 * @param messengerPSID - Messenger PSID (optional)
 * @param instagramSID - Instagram SID (optional)
 * @returns true if at least one valid ID exists, false otherwise
 */
export function hasValidContactId(
  messengerPSID: string | null | undefined,
  instagramSID: string | null | undefined
): boolean {
  return isValidPSID(messengerPSID) || isValidSID(instagramSID);
}

/**
 * Normalizes a PSID or SID by trimming whitespace
 * @param id - The ID to normalize
 * @returns Normalized ID or null if invalid
 */
export function normalizeContactId(id: string | null | undefined): string | null {
  if (!id || typeof id !== 'string') {
    return null;
  }
  
  const trimmed = id.trim();
  return trimmed.length > 0 ? trimmed : null;
}









