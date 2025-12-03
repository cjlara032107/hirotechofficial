/**
 * Request Queue Manager with Priority Support
 * 
 * Manages AI API request queuing to prevent overwhelming the API
 * and allows prioritizing critical requests over background tasks.
 */

export enum RequestPriority {
  LOW = 0,
  NORMAL = 1,
  HIGH = 2,
  CRITICAL = 3,
}

export interface QueuedRequest<T> {
  id: string;
  priority: RequestPriority;
  execute: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  createdAt: number;
  timeout?: number; // Timeout in ms
}

export class RequestQueue {
  private queue: QueuedRequest<unknown>[] = [];
  private processing = false;
  private _maxConcurrent: number;
  private currentConcurrent = 0;
  private processingInterval: NodeJS.Timeout | null = null;

  constructor(maxConcurrent: number = 5) {
    this._maxConcurrent = maxConcurrent;
  }
  
  /**
   * Get max concurrent (read-only access)
   */
  get maxConcurrent(): number {
    return this._maxConcurrent;
  }
  
  /**
   * Update max concurrent (useful for dynamic scaling)
   */
  updateMaxConcurrent(newMax: number): void {
    if (newMax > 0) {
      this._maxConcurrent = newMax;
      console.log(`[RequestQueue] Updated max concurrency to ${newMax}`);
      // Trigger processing if we have capacity and queued items
      if (this.queue.length > 0 && this.currentConcurrent < this._maxConcurrent) {
        this.processQueue();
      }
    }
  }

  /**
   * Add a request to the queue with priority
   */
  async enqueue<T>(
    execute: () => Promise<T>,
    priority: RequestPriority = RequestPriority.NORMAL,
    timeout?: number
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const request: QueuedRequest<T> = {
        id: `req-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        priority,
        execute,
        resolve,
        reject,
        createdAt: Date.now(),
        timeout,
      };

      // Insert based on priority (higher priority first, then FIFO)
      const insertIndex = this.queue.findIndex(
        (r) => r.priority < priority
      );
      if (insertIndex === -1) {
        this.queue.push(request as QueuedRequest<unknown>);
      } else {
        this.queue.splice(insertIndex, 0, request as QueuedRequest<unknown>);
      }

      console.log(
        `[RequestQueue] Enqueued request ${request.id} with priority ${RequestPriority[priority]} (queue size: ${this.queue.length})`
      );

      this.startProcessing();
    });
  }

  /**
   * Start processing the queue
   */
  private startProcessing(): void {
    if (this.processingInterval) {
      return; // Already processing
    }

    this.processingInterval = setInterval(() => {
      this.processQueue();
    }, 100); // Check every 100ms

    // Process immediately
    this.processQueue();
  }

  /**
   * Process queued requests up to maxConcurrent limit
   */
  private async processQueue(): Promise<void> {
    // Remove timed-out requests
    this.removeTimedOutRequests();

    // Process available slots
    while (
      this.currentConcurrent < this.maxConcurrent &&
      this.queue.length > 0
    ) {
      const request = this.queue.shift();
      if (!request) break;

      this.currentConcurrent++;
      this.executeRequest(request).finally(() => {
        this.currentConcurrent--;
        // Continue processing
        setImmediate(() => this.processQueue());
      });
    }

    // Stop interval if queue is empty and nothing is processing
    if (this.queue.length === 0 && this.currentConcurrent === 0) {
      if (this.processingInterval) {
        clearInterval(this.processingInterval);
        this.processingInterval = null;
      }
    }
  }

  /**
   * Execute a single request
   */
  private async executeRequest<T>(request: QueuedRequest<T>): Promise<void> {
    const startTime = Date.now();
    console.log(
      `[RequestQueue] Processing request ${request.id} (priority: ${RequestPriority[request.priority]})`
    );

    try {
      let result: T;
      let timeoutId: NodeJS.Timeout | null = null;
      
      if (request.timeout) {
        // Execute with timeout
        const timeoutPromise = new Promise<T>((_, reject) => {
          timeoutId = setTimeout(
            () => reject(new Error(`Request ${request.id} timed out after ${request.timeout}ms`)),
            request.timeout!
          );
        });
        
        result = await Promise.race([
          request.execute().finally(() => {
            // Clean up timeout if request completes first
            if (timeoutId) {
              clearTimeout(timeoutId);
              timeoutId = null;
            }
          }),
          timeoutPromise,
        ]);
      } else {
        result = await request.execute();
      }

      const duration = Date.now() - startTime;
      console.log(
        `[RequestQueue] ✅ Request ${request.id} completed in ${duration}ms`
      );
      request.resolve(result);
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      console.error(
        `[RequestQueue] ❌ Request ${request.id} failed after ${duration}ms: ${errorMessage}`
      );
      request.reject(
        error instanceof Error ? error : new Error(errorMessage)
      );
    }
  }

  /**
   * Remove requests that have exceeded their timeout
   */
  private removeTimedOutRequests(): void {
    const now = Date.now();
    const initialLength = this.queue.length;

    this.queue = this.queue.filter((request) => {
      if (request.timeout) {
        const age = now - request.createdAt;
        if (age > request.timeout) {
          console.warn(
            `[RequestQueue] ⏰ Request ${request.id} timed out in queue (age: ${age}ms, timeout: ${request.timeout}ms)`
          );
          request.reject(
            new Error(
              `Request timed out in queue after ${request.timeout}ms`
            )
          );
          return false;
        }
      }
      return true;
    });

    if (this.queue.length < initialLength) {
      console.log(
        `[RequestQueue] Removed ${initialLength - this.queue.length} timed-out requests`
      );
    }
  }

  /**
   * Get current queue statistics
   */
  getStats(): {
    queueSize: number;
    currentConcurrent: number;
    maxConcurrent: number;
    priorityBreakdown: Record<string, number>;
  } {
    const priorityBreakdown: Record<string, number> = {};
    this.queue.forEach((req) => {
      const priorityName = RequestPriority[req.priority];
      priorityBreakdown[priorityName] = (priorityBreakdown[priorityName] || 0) + 1;
    });

    return {
      queueSize: this.queue.length,
      currentConcurrent: this.currentConcurrent,
      maxConcurrent: this.maxConcurrent,
      priorityBreakdown,
    };
  }

  /**
   * Clear the queue (reject all pending requests)
   */
  clear(): void {
    const count = this.queue.length;
    this.queue.forEach((request) => {
      request.reject(new Error('Queue cleared'));
    });
    this.queue = [];
    console.log(`[RequestQueue] Cleared ${count} pending requests`);
  }
}

/**
 * Initialize RequestQueue with dynamic concurrency based on available API keys
 * This scales automatically as more keys are added
 */
function getInitialConcurrency(): number {
  // Check if we should use dynamic concurrency
  const useDynamic = process.env.AI_USE_DYNAMIC_CONCURRENCY === 'true';
  
  if (useDynamic) {
    // Try to get dynamic concurrency synchronously (will be updated async if needed)
    // For now, use environment variable with a good default
    const envConcurrency = parseInt(
      process.env.AI_REQUEST_QUEUE_MAX_CONCURRENT || '50',
      10
    );
    return envConcurrency;
  }
  
  // Fallback to environment variable or default
  return parseInt(
    process.env.AI_REQUEST_QUEUE_MAX_CONCURRENT || '5',
    10
  );
}

// Singleton instance
export const requestQueue = new RequestQueue(getInitialConcurrency());

// Update concurrency dynamically if enabled (runs in background)
if (process.env.AI_USE_DYNAMIC_CONCURRENCY === 'true') {
  // Update concurrency asynchronously based on available keys
  import('./dynamic-concurrency')
    .then(({ getDynamicConcurrencyLimits }) => getDynamicConcurrencyLimits())
    .then((limits) => {
      const dynamicConcurrency = limits.analysisConcurrency || 50;
      if (dynamicConcurrency > requestQueue.maxConcurrent) {
        requestQueue.updateMaxConcurrent(dynamicConcurrency);
        console.log(`[RequestQueue] ✅ Updated to dynamic concurrency: ${dynamicConcurrency} (based on ${limits.keyCount} API keys)`);
      }
    })
    .catch((error) => {
      console.warn('[RequestQueue] ⚠️ Could not update to dynamic concurrency, using default:', error instanceof Error ? error.message : String(error));
    });
}

