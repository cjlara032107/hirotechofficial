/**
 * Circuit Breaker Pattern Implementation
 * 
 * Prevents cascading failures by temporarily stopping requests
 * when failure rate exceeds threshold.
 */

export enum CircuitState {
  CLOSED = 'CLOSED', // Normal operation
  OPEN = 'OPEN', // Failing, reject requests immediately
  HALF_OPEN = 'HALF_OPEN', // Testing if service recovered
}

export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  successThreshold: number; // Number of successes in half-open to close
  timeout: number; // Time in ms before attempting half-open
  windowSize: number; // Time window in ms for tracking failures
}

export interface CircuitBreakerStats {
  state: CircuitState;
  failures: number;
  successes: number;
  lastFailureTime: number | null;
  lastSuccessTime: number | null;
  totalRequests: number;
  totalFailures: number;
}

export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failures: number = 0;
  private successes: number = 0;
  private lastFailureTime: number | null = null;
  private lastSuccessTime: number | null = null;
  private totalRequests: number = 0;
  private totalFailures: number = 0;
  private readonly config: CircuitBreakerConfig;
  private readonly name: string;
  private halfOpenTimeout: NodeJS.Timeout | null = null;

  constructor(
    name: string,
    config: Partial<CircuitBreakerConfig> = {}
  ) {
    this.name = name;
    this.config = {
      failureThreshold: config.failureThreshold || 5,
      successThreshold: config.successThreshold || 2,
      timeout: config.timeout || 60000, // 60 seconds default
      windowSize: config.windowSize || 60000, // 60 seconds default
    };
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.totalRequests++;

    // Check if circuit is open
    if (this.state === CircuitState.OPEN) {
      // Check if timeout has passed to try half-open
      if (
        this.lastFailureTime &&
        Date.now() - this.lastFailureTime >= this.config.timeout
      ) {
        console.log(
          `[CircuitBreaker:${this.name}] 🔄 Transitioning to HALF_OPEN state`
        );
        this.state = CircuitState.HALF_OPEN;
        this.successes = 0;
      } else {
        // Still in open state, reject immediately
        const error = new Error(
          `Circuit breaker is OPEN for ${this.name}. Too many failures.`
        );
        console.error(
          `[CircuitBreaker:${this.name}] 🚫 Request rejected - circuit is OPEN`
        );
        throw error;
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Record a successful call
   */
  private onSuccess(): void {
    this.lastSuccessTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.successes++;
      if (this.successes >= this.config.successThreshold) {
        console.log(
          `[CircuitBreaker:${this.name}] ✅ Circuit CLOSED - service recovered`
        );
        this.state = CircuitState.CLOSED;
        this.failures = 0;
        this.successes = 0;
      }
    } else if (this.state === CircuitState.CLOSED) {
      // Reset failure count on success in closed state
      // Only reset if we're not in a failure window
      if (
        !this.lastFailureTime ||
        Date.now() - this.lastFailureTime > this.config.windowSize
      ) {
        this.failures = 0;
      }
    }
  }

  /**
   * Record a failed call
   */
  private onFailure(): void {
    this.totalFailures++;
    this.lastFailureTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      // Any failure in half-open immediately opens the circuit
      console.error(
        `[CircuitBreaker:${this.name}] ❌ Circuit OPENED - service still failing`
      );
      this.state = CircuitState.OPEN;
      this.successes = 0;
      this.failures = this.config.failureThreshold;
    } else if (this.state === CircuitState.CLOSED) {
      this.failures++;

      // Check if we should open the circuit
      // Only consider failures within the window
      const recentFailures = this.getRecentFailures();
      if (recentFailures >= this.config.failureThreshold) {
        console.error(
          `[CircuitBreaker:${this.name}] 🚫 Circuit OPENED - ${recentFailures} failures in window`
        );
        this.state = CircuitState.OPEN;
      }
    }
  }

  /**
   * Get number of failures in the current window
   */
  private getRecentFailures(): number {
    if (!this.lastFailureTime) {
      return this.failures;
    }

    const windowStart = Date.now() - this.config.windowSize;
    if (this.lastFailureTime < windowStart) {
      // Last failure is outside window, reset count
      this.failures = 1;
      return 1;
    }

    return this.failures;
  }

  /**
   * Get current circuit breaker statistics
   */
  getStats(): CircuitBreakerStats {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailureTime: this.lastFailureTime,
      lastSuccessTime: this.lastSuccessTime,
      totalRequests: this.totalRequests,
      totalFailures: this.totalFailures,
    };
  }

  /**
   * Manually reset the circuit breaker
   */
  reset(): void {
    console.log(`[CircuitBreaker:${this.name}] 🔄 Manually reset`);
    this.state = CircuitState.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = null;
    this.lastSuccessTime = null;
    if (this.halfOpenTimeout) {
      clearTimeout(this.halfOpenTimeout);
      this.halfOpenTimeout = null;
    }
  }

  /**
   * Get the current state
   */
  getState(): CircuitState {
    return this.state;
  }
}

// Circuit breakers for different AI operations
export const aiCircuitBreakers = {
  conversationAnalysis: new CircuitBreaker('conversation-analysis', {
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 60000, // 60 seconds
    windowSize: 60000, // 60 seconds
  }),
  assistantMessage: new CircuitBreaker('assistant-message', {
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 60000,
    windowSize: 60000,
  }),
  personalization: new CircuitBreaker('personalization', {
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 60000,
    windowSize: 60000,
  }),
  followUp: new CircuitBreaker('follow-up', {
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 60000,
    windowSize: 60000,
  }),
};









