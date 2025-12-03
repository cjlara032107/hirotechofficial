/**
 * AI Analysis Request Queue
 * 
 * Queues AI analysis requests to prevent connection pool exhaustion.
 * Processes requests in controlled batches with configurable concurrency.
 * 
 * Benefits:
 * - Prevents overwhelming database connection pool
 * - Provides priority support for urgent requests
 * - Monitors queue health and statistics
 * - Graceful shutdown handling
 */

interface QueuedAnalysisRequest {
  id: string;
  messages: Array<{ from: string; text: string; timestamp?: Date }>;
  pipelineStages?: Array<{
    name: string;
    type: string;
    description?: string | null;
    leadScoreMin?: number;
    leadScoreMax?: number;
  }>;
  lastInteraction?: Date;
  jobId?: string;
  priority: 'low' | 'normal' | 'high';
  resolve: (result: any) => void;
  reject: (error: Error) => void;
  createdAt: number;
  retryCount: number;
  timeoutId?: NodeJS.Timeout; // Track timeout so we can clear it when processing starts
}

interface QueueStats {
  totalQueued: number;
  totalProcessed: number;
  totalFailed: number;
  currentQueueSize: number;
  currentProcessing: number;
  averageWaitTime: number;
  averageProcessTime: number;
}

class AnalysisQueue {
  private queue: QueuedAnalysisRequest[] = [];
  private processing: Set<string> = new Set();
  private stats: {
    totalQueued: number;
    totalProcessed: number;
    totalFailed: number;
    waitTimes: number[];
    processTimes: number[];
  } = {
    totalQueued: 0,
    totalProcessed: 0,
    totalFailed: 0,
    waitTimes: [],
    processTimes: [],
  };
  
  private processorInterval: NodeJS.Timeout | null = null;
  private isShuttingDown = false;
  private idleCheckCount = 0; // Track consecutive empty checks
  
  // Configuration
  private readonly MAX_CONCURRENT = parseInt(
    process.env.AI_ANALYSIS_QUEUE_CONCURRENCY || '10',
    10
  );
  private readonly PROCESS_INTERVAL_MS = parseInt(
    process.env.AI_ANALYSIS_QUEUE_INTERVAL || '100',
    10
  );
  private readonly MAX_QUEUE_SIZE = parseInt(
    process.env.AI_ANALYSIS_QUEUE_MAX_SIZE || '1000',
    10
  );
  private readonly MAX_RETRIES = 3;
  private readonly MAX_WAIT_TIME = 300000; // 5 minutes

  /**
   * Add analysis request to queue
   */
  async enqueue(
    messages: Array<{ from: string; text: string; timestamp?: Date }>,
    options: {
      pipelineStages?: Array<{
        name: string;
        type: string;
        description?: string | null;
        leadScoreMin?: number;
        leadScoreMax?: number;
      }>;
      lastInteraction?: Date;
      jobId?: string;
      priority?: 'low' | 'normal' | 'high';
    } = {}
  ): Promise<any> {
    // Check queue size limit
    if (this.queue.length >= this.MAX_QUEUE_SIZE) {
      throw new Error(`Queue is full (${this.MAX_QUEUE_SIZE} requests). Please try again later.`);
    }

    // Check if shutting down
    if (this.isShuttingDown) {
      throw new Error('Queue is shutting down. Cannot accept new requests.');
    }

    const requestId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const createdAt = Date.now();

    return new Promise((resolve, reject) => {
      const request: QueuedAnalysisRequest = {
        id: requestId,
        messages,
        pipelineStages: options.pipelineStages,
        lastInteraction: options.lastInteraction,
        jobId: options.jobId,
        priority: options.priority || 'normal',
        resolve,
        reject,
        createdAt,
        retryCount: 0,
      };

      // Insert based on priority (high first, then normal, then low)
      const priorityOrder = { high: 0, normal: 1, low: 2 };
      const insertIndex = this.queue.findIndex(
        req => priorityOrder[req.priority] > priorityOrder[request.priority]
      );

      if (insertIndex === -1) {
        this.queue.push(request);
      } else {
        this.queue.splice(insertIndex, 0, request);
      }

      this.stats.totalQueued++;

      if (request.jobId) {
        console.log(`[AnalysisQueue ${request.jobId}] ✅ Request ${request.id} enqueued (priority: ${request.priority}, queue size: ${this.queue.length})`);
      }

      // Start processor if not running
      if (!this.processorInterval && !this.isShuttingDown) {
        this.startProcessor();
        if (request.jobId) {
          console.log(`[AnalysisQueue ${request.jobId}] 🚀 Queue processor started`);
        }
      }

      // Store timeout ID in request so we can clear it when processing starts
      request.timeoutId = setTimeout(() => {
        // Check if request is still waiting in queue (not processing)
        const queueIndex = this.queue.findIndex(r => r.id === requestId);
        if (queueIndex !== -1) {
          // Still in queue after max wait time - remove and reject
          this.queue.splice(queueIndex, 1);
          reject(new Error('Request timed out in queue (waited too long)'));
          this.stats.totalFailed++;
        }
        // Note: If request is already processing, let it complete
        // We don't cancel in-flight requests to avoid partial state
      }, this.MAX_WAIT_TIME);
    });
  }

  /**
   * Start queue processor
   */
  private startProcessor(): void {
    if (this.processorInterval) {
      return; // Already running
    }

    this.processorInterval = setInterval(() => {
      this.processQueue().catch(error => {
        console.error('[AnalysisQueue] Error processing queue:', error);
      });
    }, this.PROCESS_INTERVAL_MS);
  }

  /**
   * Stop queue processor
   */
  private stopProcessor(): void {
    if (this.processorInterval) {
      clearInterval(this.processorInterval);
      this.processorInterval = null;
    }
  }

  /**
   * Process queued requests
   */
  private async processQueue(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    // Process multiple requests up to concurrency limit
    while (this.processing.size < this.MAX_CONCURRENT && this.queue.length > 0) {
      // Get next request from queue
      const request = this.queue.shift();
      if (!request) {
        break;
      }

      // Mark as processing
      this.processing.add(request.id);

      if (request.jobId) {
        console.log(`[AnalysisQueue ${request.jobId}] 🔄 Processing request ${request.id} (processing: ${this.processing.size}/${this.MAX_CONCURRENT}, queue: ${this.queue.length})`);
      }

      // Clear timeout since request is now being processed
      // (Request is no longer waiting in queue, so timeout is no longer needed)
      if (request.timeoutId) {
        clearTimeout(request.timeoutId);
        request.timeoutId = undefined;
      }

      const processStartTime = Date.now();
      const waitTime = processStartTime - request.createdAt;

      // Track wait time
      this.stats.waitTimes.push(waitTime);
      if (this.stats.waitTimes.length > 1000) {
        this.stats.waitTimes.shift(); // Keep last 1000
      }

      // Process request (don't await - let it run concurrently)
      this.processRequest(request)
        .then(result => {
          const processTime = Date.now() - processStartTime;
          this.stats.processTimes.push(processTime);
          if (this.stats.processTimes.length > 1000) {
            this.stats.processTimes.shift(); // Keep last 1000
          }

          this.stats.totalProcessed++;
          if (request.jobId) {
            console.log(`[AnalysisQueue ${request.jobId}] ✅ Request ${request.id} completed successfully`);
          }
          request.resolve(result);
        })
        .catch(error => {
          // Retry logic
          if (request.retryCount < this.MAX_RETRIES) {
            request.retryCount++;
            // Re-queue with lower priority
            request.priority = 'low';
            const priorityOrder = { high: 0, normal: 1, low: 2 };
            const insertIndex = this.queue.findIndex(
              req => priorityOrder[req.priority] > priorityOrder[request.priority]
            );
            if (insertIndex === -1) {
              this.queue.push(request);
            } else {
              this.queue.splice(insertIndex, 0, request);
            }
            
            if (request.jobId) {
              console.warn(`[AnalysisQueue ${request.jobId}] Retrying request ${request.id} (attempt ${request.retryCount}/${this.MAX_RETRIES})`);
            }
          } else {
            this.stats.totalFailed++;
            if (request.jobId) {
              console.error(`[AnalysisQueue ${request.jobId}] ❌ Request ${request.id} failed after ${request.retryCount} retries:`, 
                error instanceof Error ? error.message : String(error));
            }
            request.reject(error instanceof Error ? error : new Error(String(error)));
          }
        })
        .finally(() => {
          this.processing.delete(request.id);
          
          // Restart processor if queue has items and we're below concurrency
          // This handles the case where processor stopped while requests were processing
          if (this.queue.length > 0 && this.processing.size < this.MAX_CONCURRENT) {
            if (!this.processorInterval) {
              this.startProcessor();
              if (request.jobId) {
                console.log(`[AnalysisQueue ${request.jobId}] 🔄 Processor restarted (queue has ${this.queue.length} items)`);
              }
            }
            // Note: Processor interval will pick up remaining items on next tick
            // No need for recursive call - interval handles it
          }
        });
    }

    // Stop processor if queue is empty and nothing processing
    // Use idle check count to prevent premature stopping
    if (this.queue.length === 0 && this.processing.size === 0) {
      this.idleCheckCount++;
      // Stop after 5 consecutive empty checks (0.5 seconds at 100ms interval)
      if (this.idleCheckCount >= 5 && this.processorInterval) {
        this.stopProcessor();
        this.idleCheckCount = 0;
        console.log('[AnalysisQueue] ⏸️ Queue processor stopped (idle)');
      }
    } else {
      // Reset idle count if there's work to do
      this.idleCheckCount = 0;
    }
  }

  /**
   * Process a single request
   */
  private async processRequest(request: QueuedAnalysisRequest): Promise<any> {
    try {
      // Import analysis function dynamically
      const { analyzeContact } = await import('@/lib/facebook/pipeline-analyzer/analyze-contact');
      
      const result = await analyzeContact(
        request.messages,
        request.pipelineStages,
        request.lastInteraction,
        request.jobId
      );

      if (!result) {
        throw new Error('Analysis returned null');
      }

      return result;
    } catch (error) {
      // Log error for debugging
      if (request.jobId) {
        console.error(`[AnalysisQueue ${request.jobId}] Error processing request ${request.id}:`, 
          error instanceof Error ? error.message : String(error));
      }
      throw error;
    }
  }

  /**
   * Get queue statistics
   */
  getStats(): QueueStats {
    const avgWaitTime = this.stats.waitTimes.length > 0
      ? this.stats.waitTimes.reduce((a, b) => a + b, 0) / this.stats.waitTimes.length
      : 0;

    const avgProcessTime = this.stats.processTimes.length > 0
      ? this.stats.processTimes.reduce((a, b) => a + b, 0) / this.stats.processTimes.length
      : 0;

    return {
      totalQueued: this.stats.totalQueued,
      totalProcessed: this.stats.totalProcessed,
      totalFailed: this.stats.totalFailed,
      currentQueueSize: this.queue.length,
      currentProcessing: this.processing.size,
      averageWaitTime: Math.round(avgWaitTime),
      averageProcessTime: Math.round(avgProcessTime),
    };
  }

  /**
   * Get current queue size
   */
  getQueueSize(): number {
    return this.queue.length;
  }

  /**
   * Clear queue (for testing/emergency)
   */
  clear(): void {
    // Reject all pending requests
    for (const request of this.queue) {
      request.reject(new Error('Queue cleared'));
      this.stats.totalFailed++;
    }
    this.queue = [];
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true;
    this.stopProcessor();

    // Wait for current processing to complete (max 30 seconds)
    const maxWait = 30000;
    const startTime = Date.now();
    
    while (this.processing.size > 0 && (Date.now() - startTime) < maxWait) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    // Reject remaining queued requests
    for (const request of this.queue) {
      request.reject(new Error('Queue shutdown'));
      this.stats.totalFailed++;
    }
    this.queue = [];

    console.log('[AnalysisQueue] ✅ Shutdown complete');
  }
}

// Export singleton instance
export const analysisQueue = new AnalysisQueue();

// Graceful shutdown on process exit
if (typeof process !== 'undefined') {
  const shutdown = async () => {
    await analysisQueue.shutdown();
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('beforeExit', shutdown);
}

