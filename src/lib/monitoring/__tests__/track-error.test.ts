/**
 * Tests for error tracking utilities
 */

import { trackError, trackDatabaseError } from '../track-error';
import { systemMonitor } from '../system-monitor';

// Mock the system monitor
jest.mock('../system-monitor', () => ({
  systemMonitor: {
    recordError: jest.fn(),
  },
}));

describe('Error Tracking', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('trackError', () => {
    it('should track a generic error', () => {
      const error = new Error('Test error');
      trackError(error);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          errorType: 'Error',
          errorMessage: 'Test error',
        })
      );
    });

    it('should track Prisma errors', () => {
      const error = {
        code: 'P1001',
        message: 'Connection error',
      };
      
      trackError(error);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          errorType: 'Prisma.P1001',
          errorCode: 'P1001',
          errorMessage: 'Connection error',
        })
      );
    });

    it('should track HTTP errors', () => {
      const error = {
        status: 404,
        message: 'Not found',
      };
      
      trackError(error);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          errorType: 'HTTP.404',
          errorCode: '404',
          errorMessage: 'Not found',
        })
      );
    });

    it('should track Axios errors', () => {
      const error = {
        isAxiosError: true,
        response: {
          status: 500,
        },
        message: 'Axios error',
      };
      
      trackError(error);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          errorType: 'Axios.500',
          errorCode: '500',
        })
      );
    });

    it('should include context in error tracking', () => {
      const error = new Error('Test error');
      const context = {
        endpoint: '/api/test',
        userId: 'user123',
        customField: 'value',
      };
      
      trackError(error, context);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          endpoint: '/api/test',
          userId: 'user123',
          context: expect.objectContaining({
            endpoint: '/api/test',
            userId: 'user123',
            customField: 'value',
          }),
        })
      );
    });

    it('should handle non-Error objects', () => {
      trackError('String error');

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          errorMessage: 'String error',
        })
      );
    });
  });

  describe('trackDatabaseError', () => {
    it('should track database errors with query', () => {
      const error = {
        code: 'P1001',
        message: 'Connection error',
      };
      const query = 'SELECT * FROM "User"';
      
      trackDatabaseError(error, query);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          errorType: 'Prisma.P1001',
          errorCode: 'P1001',
          context: expect.objectContaining({
            query: 'SELECT * FROM "User"',
          }),
        })
      );
    });

    it('should limit query length in context', () => {
      const error = new Error('Database error');
      const longQuery = 'a'.repeat(500);
      
      trackDatabaseError(error, longQuery);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          context: expect.objectContaining({
            query: expect.stringMatching(/^a{200}$/),
          }),
        })
      );
    });

    it('should include context in database error tracking', () => {
      const error = new Error('Database error');
      const context = {
        endpoint: '/api/users',
        userId: 'user123',
      };
      
      trackDatabaseError(error, undefined, context);

      expect(systemMonitor.recordError).toHaveBeenCalledWith(
        expect.objectContaining({
          endpoint: '/api/users',
          userId: 'user123',
        })
      );
    });
  });
});









