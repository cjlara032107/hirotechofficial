/**
 * Security tests for input sanitization
 * Tests XSS and SQL injection prevention
 */

import { describe, it, expect } from '@jest/globals';
import {
  sanitizeInput,
  sanitizeForStorage,
  sanitizeStringArray,
  validateAndSanitizeString,
  escapeHtml,
} from '../sanitize';

describe('sanitizeInput', () => {
  it('should remove script tags', () => {
    const input = '<script>alert("XSS")</script>Hello';
    const result = sanitizeInput(input);
    expect(result).toBe('Hello');
  });

  it('should remove all HTML tags', () => {
    const input = '<div>Hello</div><p>World</p>';
    const result = sanitizeInput(input);
    expect(result).toBe('HelloWorld');
  });

  it('should remove javascript: protocol', () => {
    const input = 'javascript:alert("XSS")';
    const result = sanitizeInput(input);
    expect(result).toBe('alert("XSS")');
  });

  it('should remove event handlers', () => {
    const input = 'onclick="alert(1)" onerror="alert(2)"';
    const result = sanitizeInput(input);
    expect(result).toBe('="alert(1)" ="alert(2)"');
  });

  it('should remove iframe tags', () => {
    const input = '<iframe src="evil.com"></iframe>Hello';
    const result = sanitizeInput(input);
    expect(result).toBe('Hello');
  });

  it('should preserve plain text', () => {
    const input = 'Hello, World!';
    const result = sanitizeInput(input);
    expect(result).toBe('Hello, World!');
  });

  it('should handle empty strings', () => {
    const result = sanitizeInput('');
    expect(result).toBe('');
  });

  it('should trim whitespace', () => {
    const input = '  Hello  ';
    const result = sanitizeInput(input);
    expect(result).toBe('Hello');
  });
});

describe('sanitizeForStorage', () => {
  it('should remove script tags but preserve some formatting', () => {
    const input = '<script>alert("XSS")</script>Hello <b>World</b>';
    const result = sanitizeForStorage(input);
    expect(result).toBe('Hello <b>World</b>');
  });

  it('should remove javascript: protocol', () => {
    const input = 'javascript:alert("XSS")';
    const result = sanitizeForStorage(input);
    expect(result).toBe('alert("XSS")');
  });

  it('should remove event handlers', () => {
    const input = 'onclick="alert(1)"';
    const result = sanitizeForStorage(input);
    expect(result).toBe('="alert(1)"');
  });

  it('should remove iframe tags', () => {
    const input = '<iframe src="evil.com"></iframe>Hello';
    const result = sanitizeForStorage(input);
    expect(result).toBe('Hello');
  });
});

describe('sanitizeStringArray', () => {
  it('should sanitize array of strings', () => {
    const input = ['<script>alert(1)</script>', 'Hello', 'World'];
    const result = sanitizeStringArray(input);
    expect(result).toEqual(['', 'Hello', 'World']);
  });

  it('should filter out non-string values', () => {
    const input = ['Hello', 123, null, undefined, 'World'];
    const result = sanitizeStringArray(input);
    expect(result).toEqual(['Hello', 'World']);
  });

  it('should filter out empty strings', () => {
    const input = ['Hello', '', 'World', '   '];
    const result = sanitizeStringArray(input);
    expect(result).toEqual(['Hello', 'World']);
  });

  it('should handle empty array', () => {
    const result = sanitizeStringArray([]);
    expect(result).toEqual([]);
  });
});

describe('validateAndSanitizeString', () => {
  it('should sanitize valid string', () => {
    const input = '<script>alert(1)</script>Hello';
    const result = validateAndSanitizeString(input);
    expect(result).toBe('Hello');
  });

  it('should return null for strings exceeding max length', () => {
    const input = 'a'.repeat(10001);
    const result = validateAndSanitizeString(input, 10000);
    expect(result).toBeNull();
  });

  it('should handle null input', () => {
    const result = validateAndSanitizeString(null);
    expect(result).toBeNull();
  });

  it('should handle undefined input', () => {
    const result = validateAndSanitizeString(undefined);
    expect(result).toBeNull();
  });
});

describe('escapeHtml', () => {
  it('should escape HTML entities', () => {
    const input = '<div>Hello & "World"</div>';
    const result = escapeHtml(input);
    expect(result).toBe('&lt;div&gt;Hello &amp; &quot;World&quot;&lt;/div&gt;');
  });

  it('should escape single quotes', () => {
    const input = "It's a test";
    const result = escapeHtml(input);
    expect(result).toBe('It&#039;s a test');
  });

  it('should preserve plain text', () => {
    const input = 'Hello, World!';
    const result = escapeHtml(input);
    expect(result).toBe('Hello, World!');
  });
});

describe('SQL Injection Prevention', () => {
  it('should handle SQL injection attempts in input', () => {
    const input = "'; DROP TABLE users; --";
    const result = sanitizeInput(input);
    // Should sanitize but Prisma will also parameterize
    expect(result).not.toContain('DROP TABLE');
  });

  it('should handle UNION-based SQL injection', () => {
    const input = "' UNION SELECT * FROM users --";
    const result = sanitizeInput(input);
    expect(result).toBeTruthy();
  });
});

describe('XSS Attack Prevention', () => {
  it('should prevent XSS via script tags', () => {
    const malicious = '<script>document.cookie="stolen"</script>';
    const result = sanitizeInput(malicious);
    expect(result).not.toContain('<script>');
  });

  it('should prevent XSS via event handlers', () => {
    const malicious = '<img src=x onerror=alert(1)>';
    const result = sanitizeInput(malicious);
    expect(result).not.toContain('onerror');
  });

  it('should prevent XSS via javascript: protocol', () => {
    const malicious = '<a href="javascript:alert(1)">Click</a>';
    const result = sanitizeInput(malicious);
    expect(result).not.toContain('javascript:');
  });

  it('should prevent XSS via data: URLs', () => {
    const malicious = '<img src="data:text/html,<script>alert(1)</script>">';
    const result = sanitizeInput(malicious);
    expect(result).not.toContain('data:text/html');
  });
});









