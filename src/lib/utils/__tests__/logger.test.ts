/**
 * Tests for structured logger utility
 */

import { Logger, logger, type LogLevel } from '../logger';

describe('Logger', () => {
  let mockConsoleDebug: jest.SpyInstance;
  let mockConsoleLog: jest.SpyInstance;
  let mockConsoleWarn: jest.SpyInstance;
  let mockConsoleError: jest.SpyInstance;

  beforeEach(() => {
    // Mock console methods
    mockConsoleDebug = jest.spyOn(console, 'debug').mockImplementation(() => {});
    mockConsoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    mockConsoleWarn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    mockConsoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    // Restore console methods
    mockConsoleDebug.mockRestore();
    mockConsoleLog.mockRestore();
    mockConsoleWarn.mockRestore();
    mockConsoleError.mockRestore();
  });

  describe('Log levels', () => {
    it('should log debug messages when level is debug', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'debug';
      
      testLogger.debug('Debug message');
      expect(mockConsoleDebug).toHaveBeenCalled();
    });

    it('should log info messages when level is info', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      testLogger.info('Info message');
      expect(mockConsoleLog).toHaveBeenCalled();
    });

    it('should log warn messages when level is warn', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'warn';
      
      testLogger.warn('Warning message');
      expect(mockConsoleWarn).toHaveBeenCalled();
    });

    it('should log error messages when level is error', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'error';
      
      testLogger.error('Error message');
      expect(mockConsoleError).toHaveBeenCalled();
    });

    it('should not log debug messages when level is info', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      testLogger.debug('Debug message');
      expect(mockConsoleDebug).not.toHaveBeenCalled();
    });

    it('should not log info messages when level is warn', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'warn';
      
      testLogger.info('Info message');
      expect(mockConsoleLog).not.toHaveBeenCalled();
    });
  });

  describe('Context logging', () => {
    it('should include context in log messages', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      testLogger.info('Test message', { userId: '123', action: 'test' });
      
      const logCall = mockConsoleLog.mock.calls[0][0];
      expect(logCall).toContain('Test message');
      expect(logCall).toContain('userId');
      expect(logCall).toContain('action');
    });

    it('should handle complex context objects', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      testLogger.info('Test message', {
        nested: { value: 'test' },
        array: [1, 2, 3],
        number: 42,
      });
      
      expect(mockConsoleLog).toHaveBeenCalled();
      const logCall = mockConsoleLog.mock.calls[0][0];
      expect(logCall).toContain('Test message');
    });
  });

  describe('Error logging', () => {
    it('should log error with Error object', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'error';
      
      const error = new Error('Test error');
      testLogger.error('Error occurred', error);
      
      expect(mockConsoleError).toHaveBeenCalled();
      const logCall = mockConsoleError.mock.calls[0][0];
      expect(logCall).toContain('Error occurred');
      expect(logCall).toContain('Test error');
    });

    it('should log error with string', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'error';
      
      testLogger.error('Error occurred', 'String error');
      
      expect(mockConsoleError).toHaveBeenCalled();
    });

    it('should log error with context', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'error';
      
      const error = new Error('Test error');
      testLogger.error('Error occurred', error, { operation: 'test', userId: '123' });
      
      expect(mockConsoleError).toHaveBeenCalled();
      const logCall = mockConsoleError.mock.calls[0][0];
      expect(logCall).toContain('operation');
      expect(logCall).toContain('userId');
    });
  });

  describe('Child logger', () => {
    it('should create child logger with additional context', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      const childLogger = testLogger.child({ userId: '123', organizationId: '456' });
      childLogger.info('Test message', { action: 'test' });
      
      expect(mockConsoleLog).toHaveBeenCalled();
      const logCall = mockConsoleLog.mock.calls[0][0];
      expect(logCall).toContain('userId');
      expect(logCall).toContain('organizationId');
      expect(logCall).toContain('action');
    });

    it('should allow child context to be overridden', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      const childLogger = testLogger.child({ userId: '123' });
      childLogger.info('Test message', { userId: '456' }); // Override userId
      
      expect(mockConsoleLog).toHaveBeenCalled();
      const logCall = mockConsoleLog.mock.calls[0][0];
      // Child context should be overridden by explicit context
      expect(logCall).toContain('userId');
    });
  });

  describe('Timestamp formatting', () => {
    it('should include timestamp in log messages', () => {
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      
      testLogger.info('Test message');
      
      const logCall = mockConsoleLog.mock.calls[0][0];
      // Should contain ISO timestamp format
      expect(logCall).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
  });

  describe('Environment-based behavior', () => {
    it('should use JSON format in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      // @ts-expect-error - accessing private property for testing
      testLogger.isDevelopment = false;
      
      testLogger.info('Test message', { userId: '123' });
      
      const logCall = mockConsoleLog.mock.calls[0][0];
      // Should be JSON format
      expect(() => JSON.parse(logCall)).not.toThrow();
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should use readable format in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const testLogger = new Logger();
      // @ts-expect-error - accessing private property for testing
      testLogger.minLevel = 'info';
      // @ts-expect-error - accessing private property for testing
      testLogger.isDevelopment = true;
      
      testLogger.info('Test message', { userId: '123' });
      
      const logCall = mockConsoleLog.mock.calls[0][0];
      // Should be readable format (not JSON)
      expect(() => JSON.parse(logCall)).toThrow();
      expect(logCall).toContain('Test message');
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Singleton logger', () => {
    it('should export a singleton logger instance', () => {
      expect(logger).toBeInstanceOf(Logger);
      expect(logger.info).toBeDefined();
      expect(logger.error).toBeDefined();
      expect(logger.warn).toBeDefined();
      expect(logger.debug).toBeDefined();
    });
  });
});









