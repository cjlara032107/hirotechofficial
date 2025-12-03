/**
 * Tests for User-Friendly Error Messages
 * 
 * Test cases:
 * 1. Error messages are clear and actionable
 * 2. Technical errors are translated to user-friendly messages
 * 3. Network errors show helpful guidance
 * 4. Authentication errors provide clear next steps
 * 5. Rate limit errors explain what happened
 * 6. Token expiration errors are actionable
 */

import { formatUserFriendlyError } from '../error-messages';

describe('User-Friendly Error Messages', () => {
  describe('Test: Error messages are clear and actionable', () => {
    it('should format network errors with helpful guidance', () => {
      const error = new Error('Failed to fetch');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).toContain('connection');
      expect(friendly).not.toContain('Failed to fetch');
      expect(friendly.length).toBeGreaterThan(20);
    });

    it('should format timeout errors with actionable advice', () => {
      const error = new Error('Request timeout');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/timeout|try again|wait/i);
      expect(friendly).not.toContain('Request timeout');
    });

    it('should format generic errors without technical jargon', () => {
      const error = new Error('ECONNREFUSED 127.0.0.1:5432');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('ECONNREFUSED');
      expect(friendly).not.toContain('127.0.0.1');
      expect(friendly).not.toContain('5432');
    });
  });

  describe('Test: Technical errors are translated to user-friendly messages', () => {
    it('should translate Prisma errors to user-friendly messages', () => {
      const error = new Error('P2002: Unique constraint failed');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('P2002');
      expect(friendly).not.toContain('Unique constraint');
      expect(friendly.toLowerCase()).toMatch(/already exists|duplicate/i);
    });

    it('should translate JSON parse errors to user-friendly messages', () => {
      const error = new Error('Unexpected token < in JSON at position 0');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('Unexpected token');
      expect(friendly).not.toContain('JSON at position');
      expect(friendly.toLowerCase()).toMatch(/server|response|error/i);
    });

    it('should translate database connection errors', () => {
      const error = new Error('Can\'t reach database server');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/database|connection|unavailable/i);
      expect(friendly).not.toContain('Can\'t reach');
    });
  });

  describe('Test: Network errors show helpful guidance', () => {
    it('should provide guidance for network failures', () => {
      const error = new Error('Network request failed');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/internet|connection|network/i);
      expect(friendly.toLowerCase()).toMatch(/check|verify|try/i);
    });

    it('should handle fetch errors gracefully', () => {
      const error = new Error('fetch failed');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).toBeTruthy();
      expect(friendly.length).toBeGreaterThan(10);
      expect(friendly).not.toContain('fetch failed');
    });
  });

  describe('Test: Authentication errors provide clear next steps', () => {
    it('should guide users when token expires', () => {
      const error = new Error('Token expired');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/token|expired|session/i);
      expect(friendly.toLowerCase()).toMatch(/reconnect|login|refresh/i);
    });

    it('should guide users when unauthorized', () => {
      const error = new Error('Unauthorized');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/permission|access|authorized/i);
      expect(friendly.toLowerCase()).toMatch(/login|account|session/i);
    });
  });

  describe('Test: Rate limit errors explain what happened', () => {
    it('should explain rate limiting clearly', () => {
      const error = new Error('Rate limit exceeded');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/rate limit|too many|wait/i);
      expect(friendly.toLowerCase()).toMatch(/try again|later|moment/i);
    });

    it('should provide actionable advice for rate limits', () => {
      const error = { message: 'Rate limit exceeded', retryAfter: 60 };
      const friendly = formatUserFriendlyError(error as Error);
      
      expect(friendly.toLowerCase()).toMatch(/wait|try again|moment/i);
    });
  });

  describe('Test: Token expiration errors are actionable', () => {
    it('should provide clear steps for token expiration', () => {
      const error = new Error('Facebook access token expired');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly.toLowerCase()).toMatch(/facebook|token|expired/i);
      expect(friendly.toLowerCase()).toMatch(/reconnect|connect|refresh/i);
    });

    it('should not expose technical token details', () => {
      const error = new Error('Invalid token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
      expect(friendly).not.toContain('Invalid token:');
    });
  });

  describe('Test: Error messages avoid technical jargon', () => {
    it('should avoid stack traces in user messages', () => {
      const error = new Error('Error occurred');
      error.stack = 'Error: Error occurred\n    at Object.<anonymous> (/path/to/file.ts:123:45)';
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('/path/to/file.ts');
      expect(friendly).not.toContain('at Object');
      expect(friendly).not.toContain('123:45');
    });

    it('should avoid internal error codes', () => {
      const error = new Error('Error 500: Internal Server Error');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('Error 500');
      expect(friendly).not.toContain('Internal Server Error');
    });

    it('should avoid database query details', () => {
      const error = new Error('SELECT * FROM contacts WHERE id = $1');
      const friendly = formatUserFriendlyError(error);
      
      expect(friendly).not.toContain('SELECT');
      expect(friendly).not.toContain('FROM contacts');
      expect(friendly).not.toContain('WHERE id');
    });
  });
});









