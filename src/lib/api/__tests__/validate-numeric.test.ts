/**
 * Tests for numeric validation utilities
 */

import { validateNumeric, NumericPresets } from '../validate-numeric';

describe('validateNumeric', () => {
  describe('basic validation', () => {
    it('should accept valid numbers', () => {
      const result = validateNumeric(42);
      expect(result.valid).toBe(true);
      expect(result.value).toBe(42);
    });

    it('should reject non-numbers', () => {
      const result = validateNumeric('not a number');
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject NaN', () => {
      const result = validateNumeric(NaN);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('finite'));
    });

    it('should reject Infinity', () => {
      const result = validateNumeric(Infinity);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('finite'));
    });
  });

  describe('range validation', () => {
    it('should accept values within range', () => {
      const result = validateNumeric(50, { min: 0, max: 100 });
      expect(result.valid).toBe(true);
    });

    it('should reject values below minimum', () => {
      const result = validateNumeric(-10, { min: 0, max: 100 });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('at least'));
    });

    it('should reject values above maximum', () => {
      const result = validateNumeric(150, { min: 0, max: 100 });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('at most'));
    });
  });

  describe('integer validation', () => {
    it('should accept integers when integer is required', () => {
      const result = validateNumeric(42, { integer: true });
      expect(result.valid).toBe(true);
    });

    it('should reject floats when integer is required', () => {
      const result = validateNumeric(42.5, { integer: true });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('integer'));
    });
  });

  describe('positive validation', () => {
    it('should accept positive numbers', () => {
      const result = validateNumeric(42, { positive: true });
      expect(result.valid).toBe(true);
    });

    it('should reject negative numbers', () => {
      const result = validateNumeric(-10, { positive: true });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('positive'));
    });

    it('should reject zero when allowZero is false', () => {
      const result = validateNumeric(0, { positive: true, allowZero: false });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(expect.stringContaining('greater than zero'));
    });

    it('should accept zero when allowZero is true', () => {
      const result = validateNumeric(0, { positive: true, allowZero: true });
      expect(result.valid).toBe(true);
    });
  });

  describe('string parsing', () => {
    it('should parse valid numeric strings', () => {
      const result = validateNumeric('42');
      expect(result.valid).toBe(true);
      expect(result.value).toBe(42);
    });

    it('should reject invalid numeric strings', () => {
      const result = validateNumeric('not a number');
      expect(result.valid).toBe(false);
    });
  });
});

describe('NumericPresets', () => {
  describe('percentage', () => {
    it('should accept valid percentages', () => {
      expect(NumericPresets.percentage(50).valid).toBe(true);
      expect(NumericPresets.percentage(0).valid).toBe(true);
      expect(NumericPresets.percentage(100).valid).toBe(true);
    });

    it('should reject invalid percentages', () => {
      expect(NumericPresets.percentage(-10).valid).toBe(false);
      expect(NumericPresets.percentage(150).valid).toBe(false);
    });
  });

  describe('positiveInteger', () => {
    it('should accept positive integers', () => {
      expect(NumericPresets.positiveInteger(1).valid).toBe(true);
      expect(NumericPresets.positiveInteger(100).valid).toBe(true);
    });

    it('should reject zero and negative', () => {
      expect(NumericPresets.positiveInteger(0).valid).toBe(false);
      expect(NumericPresets.positiveInteger(-1).valid).toBe(false);
    });

    it('should reject floats', () => {
      expect(NumericPresets.positiveInteger(1.5).valid).toBe(false);
    });
  });

  describe('pageNumber', () => {
    it('should accept valid page numbers', () => {
      expect(NumericPresets.pageNumber(1).valid).toBe(true);
      expect(NumericPresets.pageNumber(100).valid).toBe(true);
    });

    it('should reject invalid page numbers', () => {
      expect(NumericPresets.pageNumber(0).valid).toBe(false);
      expect(NumericPresets.pageNumber(-1).valid).toBe(false);
    });
  });

  describe('limit', () => {
    it('should accept valid limits', () => {
      expect(NumericPresets.limit(1).valid).toBe(true);
      expect(NumericPresets.limit(50).valid).toBe(true);
      expect(NumericPresets.limit(100, 100).valid).toBe(true);
    });

    it('should reject limits exceeding max', () => {
      expect(NumericPresets.limit(101, 100).valid).toBe(false);
    });
  });

  describe('rateLimit', () => {
    it('should accept valid rate limits', () => {
      expect(NumericPresets.rateLimit(1).valid).toBe(true);
      expect(NumericPresets.rateLimit(1000).valid).toBe(true);
      expect(NumericPresets.rateLimit(100000).valid).toBe(true);
    });

    it('should reject invalid rate limits', () => {
      expect(NumericPresets.rateLimit(0).valid).toBe(false);
      expect(NumericPresets.rateLimit(-1).valid).toBe(false);
      expect(NumericPresets.rateLimit(100001).valid).toBe(false);
    });
  });

  describe('hourOfDay', () => {
    it('should accept valid hours', () => {
      expect(NumericPresets.hourOfDay(0).valid).toBe(true);
      expect(NumericPresets.hourOfDay(12).valid).toBe(true);
      expect(NumericPresets.hourOfDay(23).valid).toBe(true);
    });

    it('should reject invalid hours', () => {
      expect(NumericPresets.hourOfDay(-1).valid).toBe(false);
      expect(NumericPresets.hourOfDay(24).valid).toBe(false);
    });
  });
});









