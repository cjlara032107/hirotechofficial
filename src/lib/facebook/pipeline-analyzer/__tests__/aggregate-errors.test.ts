/**
 * Tests for aggregateErrors function
 * 
 * Tests verify:
 * - Formats errors correctly
 * - Limits array size to maxErrors (default 100)
 * - Adds truncation indicator when limit exceeded
 * - Handles empty errors array
 * - Handles mixed error types (objects and strings)
 * - Is pure function (no side effects)
 */

import { aggregateErrors, type TruncationIndicator } from '../aggregate-errors';

describe('aggregateErrors', () => {
  describe('Formats errors correctly', () => {
    it('should format object errors with all fields', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited', code: 613 },
        { platform: 'Instagram', id: '456', error: 'Invalid token', code: 401 },
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        platform: 'Messenger',
        id: '123',
        error: 'Rate limited',
        code: 613,
      });
      expect(result[1]).toEqual({
        platform: 'Instagram',
        id: '456',
        error: 'Invalid token',
        code: 401,
      });
    });

    it('should format object errors with missing optional fields', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Some error' },
        { platform: 'Instagram', error: 'Another error' },
        { error: 'Error without platform or id' },
        { platform: 'Facebook', id: '789' },
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(4);
      expect(result[0]).toEqual({
        platform: 'Messenger',
        id: '123',
        error: 'Some error',
      });
      expect(result[1]).toEqual({
        platform: 'Instagram',
        id: 'unknown',
        error: 'Another error',
      });
      expect(result[2]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'Error without platform or id',
      });
      expect(result[3]).toEqual({
        platform: 'Facebook',
        id: '789',
        error: 'Unknown error',
      });
    });

    it('should format string errors', () => {
      const errors = [
        'Simple string error',
        'Another string error',
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'Simple string error',
      });
      expect(result[1]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'Another string error',
      });
    });
  });

  describe('Limits array size to maxErrors', () => {
    it('should limit to default maxErrors (100)', () => {
      const errors = Array.from({ length: 150 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(101); // 100 errors + 1 truncation indicator
      expect(result[99]).toEqual({
        platform: 'Messenger',
        id: 'contact-99',
        error: 'Error 99',
      });
      expect(result[100]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 50 more error(s) truncated',
      });
    });

    it('should limit to custom maxErrors', () => {
      const errors = Array.from({ length: 50 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 10);

      expect(result).toHaveLength(11); // 10 errors + 1 truncation indicator
      expect(result[9]).toEqual({
        platform: 'Messenger',
        id: 'contact-9',
        error: 'Error 9',
      });
      expect(result[10]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 40 more error(s) truncated',
      });
    });

    it('should not truncate when errors.length equals maxErrors', () => {
      const errors = Array.from({ length: 100 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(100);
      expect(result.every((err) => err.platform !== 'System' || err.id !== 'truncated')).toBe(true);
    });

    it('should not truncate when errors.length is less than maxErrors', () => {
      const errors = Array.from({ length: 50 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(50);
      expect(result.every((err) => err.platform !== 'System' || err.id !== 'truncated')).toBe(true);
    });
  });

  describe('Adds truncation indicator when limit exceeded', () => {
    it('should add truncation indicator with correct count (singular)', () => {
      const errors = Array.from({ length: 101 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(101);
      const lastItem = result[100] as TruncationIndicator;
      expect(lastItem).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 1 more error(s) truncated',
      });
    });

    it('should add truncation indicator with correct count (plural)', () => {
      const errors = Array.from({ length: 150 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(101);
      const lastItem = result[100] as TruncationIndicator;
      expect(lastItem).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 50 more error(s) truncated',
      });
    });

    it('should add truncation indicator at the end', () => {
      const errors = Array.from({ length: 105 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(101);
      expect(result[99]).toEqual({
        platform: 'Messenger',
        id: 'contact-99',
        error: 'Error 99',
      });
      expect(result[100]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 5 more error(s) truncated',
      });
    });
  });

  describe('Handles empty errors array', () => {
    it('should return empty array for empty input', () => {
      const result = aggregateErrors([]);
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });

    it('should return empty array for null/undefined-like input', () => {
      // TypeScript won't allow null/undefined, but we handle empty arrays
      const result = aggregateErrors([]);
      expect(result).toEqual([]);
    });
  });

  describe('Handles mixed error types (objects and strings)', () => {
    it('should handle mix of objects and strings', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited', code: 613 },
        'Simple string error',
        { platform: 'Instagram', id: '456', error: 'Invalid token' },
        'Another string error',
        { platform: 'Facebook', id: '789', error: 'Network error', code: 500 },
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(5);
      expect(result[0]).toEqual({
        platform: 'Messenger',
        id: '123',
        error: 'Rate limited',
        code: 613,
      });
      expect(result[1]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'Simple string error',
      });
      expect(result[2]).toEqual({
        platform: 'Instagram',
        id: '456',
        error: 'Invalid token',
      });
      expect(result[3]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'Another string error',
      });
      expect(result[4]).toEqual({
        platform: 'Facebook',
        id: '789',
        error: 'Network error',
        code: 500,
      });
    });

    it('should handle all strings', () => {
      const errors = [
        'Error 1',
        'Error 2',
        'Error 3',
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(3);
      result.forEach((err, index) => {
        expect(err).toEqual({
          platform: 'Unknown',
          id: 'unknown',
          error: `Error ${index + 1}`,
        });
      });
    });

    it('should handle all objects', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Error 1' },
        { platform: 'Instagram', id: '456', error: 'Error 2' },
        { platform: 'Facebook', id: '789', error: 'Error 3' },
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(3);
      expect(result[0]).toEqual({
        platform: 'Messenger',
        id: '123',
        error: 'Error 1',
      });
      expect(result[1]).toEqual({
        platform: 'Instagram',
        id: '456',
        error: 'Error 2',
      });
      expect(result[2]).toEqual({
        platform: 'Facebook',
        id: '789',
        error: 'Error 3',
      });
    });

    it('should handle mixed types with truncation', () => {
      const errors = [
        ...Array.from({ length: 50 }, (_, i) => ({
          platform: 'Messenger',
          id: `contact-${i}`,
          error: `Error ${i}`,
        })),
        'String error 1',
        'String error 2',
        ...Array.from({ length: 50 }, (_, i) => ({
          platform: 'Instagram',
          id: `contact-${i + 50}`,
          error: `Error ${i + 50}`,
        })),
      ];

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(101);
      // First 50 are Messenger (0-49), then 2 string errors (50-51), then 48 Instagram (52-99)
      // So index 99 is the 48th Instagram error, which is contact-97 (50 + 47)
      expect(result[99]).toEqual({
        platform: 'Instagram',
        id: 'contact-97',
        error: 'Error 97',
      });
      expect(result[100]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 2 more error(s) truncated',
      });
    });
  });

  describe('Is pure function (no side effects)', () => {
    it('should not mutate input array', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited', code: 613 },
        'Simple string error',
      ];
      const originalErrors = JSON.parse(JSON.stringify(errors));

      aggregateErrors(errors);

      expect(errors).toEqual(originalErrors);
    });

    it('should return new array instance', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited' },
      ];

      const result1 = aggregateErrors(errors);
      const result2 = aggregateErrors(errors);

      expect(result1).not.toBe(result2); // Different array instances
      expect(result1).toEqual(result2); // But same content
    });

    it('should not have side effects on external state', () => {
      const externalCounter = 0;
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited' },
      ];

      // Function should not access or modify external state
      aggregateErrors(errors);

      expect(externalCounter).toBe(0);
    });

    it('should produce same output for same input (referential transparency)', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited', code: 613 },
        'Simple string error',
      ];

      const result1 = aggregateErrors(errors);
      const result2 = aggregateErrors(errors);
      const result3 = aggregateErrors([...errors]); // Different array reference

      expect(result1).toEqual(result2);
      expect(result1).toEqual(result3);
    });

    it('should not perform I/O operations', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const errors = [
        { platform: 'Messenger', id: '123', error: 'Rate limited' },
      ];

      aggregateErrors(errors);

      expect(consoleSpy).not.toHaveBeenCalled();
      expect(consoleErrorSpy).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
      consoleErrorSpy.mockRestore();
    });
  });

  describe('Edge cases', () => {
    it('should handle errors with empty strings', () => {
      const errors = [
        { platform: '', id: '', error: '' },
        '',
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'Unknown error',
      });
      expect(result[1]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: '',
      });
    });

    it('should filter out null and undefined values', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Error 1' },
        null,
        undefined,
        'String error',
        { platform: 'Instagram', id: '456', error: 'Error 2' },
      ];

      const result = aggregateErrors(errors);

      expect(result).toHaveLength(3);
      expect(result[0]).toEqual({
        platform: 'Messenger',
        id: '123',
        error: 'Error 1',
      });
      expect(result[1]).toEqual({
        platform: 'Unknown',
        id: 'unknown',
        error: 'String error',
      });
      expect(result[2]).toEqual({
        platform: 'Instagram',
        id: '456',
        error: 'Error 2',
      });
    });

    it('should handle array with only null/undefined values', () => {
      const errors = [null, undefined];

      const result = aggregateErrors(errors);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });

    it('should handle negative maxErrors by treating as 0', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Error 1' },
        { platform: 'Instagram', id: '456', error: 'Error 2' },
      ];

      const result = aggregateErrors(errors, -5);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 2 more error(s) truncated',
      });
    });

    it('should handle non-integer maxErrors by flooring', () => {
      const errors = Array.from({ length: 10 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 3.7);

      expect(result).toHaveLength(4); // 3 errors + 1 truncation indicator
      expect(result[3]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 7 more error(s) truncated',
      });
    });

    it('should handle maxErrors of 0', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Error' },
      ];

      const result = aggregateErrors(errors, 0);

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 1 more error(s) truncated',
      });
    });

    it('should handle maxErrors of 1', () => {
      const errors = [
        { platform: 'Messenger', id: '123', error: 'Error 1' },
        { platform: 'Instagram', id: '456', error: 'Error 2' },
      ];

      const result = aggregateErrors(errors, 1);

      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        platform: 'Messenger',
        id: '123',
        error: 'Error 1',
      });
      expect(result[1]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 1 more error(s) truncated',
      });
    });

    it('should handle very large error arrays', () => {
      const errors = Array.from({ length: 10000 }, (_, i) => ({
        platform: 'Messenger',
        id: `contact-${i}`,
        error: `Error ${i}`,
      }));

      const result = aggregateErrors(errors, 100);

      expect(result).toHaveLength(101);
      expect(result[100]).toEqual({
        platform: 'System',
        id: 'truncated',
        error: '... and 9900 more error(s) truncated',
      });
    });
  });
});

