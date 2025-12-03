/**
 * Tests for Circuit Breaker Pattern
 */

import {
  CircuitBreaker,
  CircuitState,
  CircuitBreakerConfig,
} from '../circuit-breaker';

describe('CircuitBreaker', () => {
  let breaker: CircuitBreaker;
  const config: Partial<CircuitBreakerConfig> = {
    failureThreshold: 3,
    successThreshold: 2,
    timeout: 1000,
    windowSize: 5000,
  };

  beforeEach(() => {
    breaker = new CircuitBreaker('test', config);
    jest.useFakeTimers();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    breaker.reset();
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe('Normal operation (CLOSED state)', () => {
    it('should execute function when circuit is closed', async () => {
      const fn = jest.fn().mockResolvedValue('success');
      const result = await breaker.execute(fn);

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should track failures and open circuit after threshold', async () => {
      const fn = jest.fn().mockRejectedValue(new Error('Failure'));

      // Execute failures up to threshold
      for (let i = 0; i < config.failureThreshold!; i++) {
        try {
          await breaker.execute(fn);
        } catch {
          // Expected
        }
      }

      expect(breaker.getState()).toBe(CircuitState.OPEN);
    });
  });

  describe('Open circuit (OPEN state)', () => {
    beforeEach(async () => {
      // Open the circuit
      const fn = jest.fn().mockRejectedValue(new Error('Failure'));
      for (let i = 0; i < config.failureThreshold!; i++) {
        try {
          await breaker.execute(fn);
        } catch {
          // Expected
        }
      }
    });

    it('should reject requests immediately when circuit is open', async () => {
      const fn = jest.fn().mockResolvedValue('success');

      await expect(breaker.execute(fn)).rejects.toThrow('Circuit breaker is OPEN');
      expect(fn).not.toHaveBeenCalled();
    });

    it('should transition to half-open after timeout', async () => {
      jest.advanceTimersByTime(config.timeout! + 100);

      const fn = jest.fn().mockResolvedValue('success');
      const result = await breaker.execute(fn);

      expect(breaker.getState()).toBe(CircuitState.HALF_OPEN);
      expect(result).toBe('success');
    });
  });

  describe('Half-open circuit (HALF_OPEN state)', () => {
    beforeEach(async () => {
      // Open circuit
      const failFn = jest.fn().mockRejectedValue(new Error('Failure'));
      for (let i = 0; i < config.failureThreshold!; i++) {
        try {
          await breaker.execute(failFn);
        } catch {
          // Expected
        }
      }

      // Wait for timeout to enter half-open
      jest.advanceTimersByTime(config.timeout! + 100);
    });

    it('should close circuit after success threshold', async () => {
      const successFn = jest.fn().mockResolvedValue('success');

      // Execute successes up to threshold
      for (let i = 0; i < config.successThreshold!; i++) {
        await breaker.execute(successFn);
      }

      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should open circuit immediately on any failure', async () => {
      const failFn = jest.fn().mockRejectedValue(new Error('Failure'));

      try {
        await breaker.execute(failFn);
      } catch {
        // Expected
      }

      expect(breaker.getState()).toBe(CircuitState.OPEN);
    });
  });

  describe('Statistics', () => {
    it('should track request statistics', async () => {
      const successFn = jest.fn().mockResolvedValue('success');
      const failFn = jest.fn().mockRejectedValue(new Error('Failure'));

      await breaker.execute(successFn);
      try {
        await breaker.execute(failFn);
      } catch {
        // Expected
      }

      const stats = breaker.getStats();
      expect(stats.totalRequests).toBe(2);
      expect(stats.totalFailures).toBe(1);
    });
  });

  describe('Reset', () => {
    it('should reset circuit breaker to closed state', async () => {
      // Open the circuit
      const fn = jest.fn().mockRejectedValue(new Error('Failure'));
      for (let i = 0; i < config.failureThreshold!; i++) {
        try {
          await breaker.execute(fn);
        } catch {
          // Expected
        }
      }

      expect(breaker.getState()).toBe(CircuitState.OPEN);

      breaker.reset();
      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });
  });
});









