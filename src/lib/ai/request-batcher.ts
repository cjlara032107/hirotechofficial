import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';

interface BatchedRequest {
  id: string;
  messages: Array<{ role: 'user' | 'assistant' | 'system'; content: string }>;
  resolve: (value: string) => void;
  reject: (error: Error) => void;
  model: string;
  temperature?: number;
  maxTokens?: number;
}

/**
 * Request Batcher for AI API calls
 * Groups multiple requests together to reduce API calls and improve throughput
 */
class RequestBatcher {
  private queue: BatchedRequest[] = [];
  private batchSize: number;
  private batchTimeout: number;
  private timer: NodeJS.Timeout | null = null;
  private processing = false;

  constructor(batchSize: number = 10, batchTimeoutMs: number = 100) {
    this.batchSize = batchSize;
    this.batchTimeout = batchTimeoutMs;
  }

  /**
   * Add a request to the batch queue
   */
  async addRequest(
    messages: Array<{ role: 'user' | 'assistant' | 'system'; content: string }>,
    model: string,
    temperature: number = 0.7,
    maxTokens?: number
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const request: BatchedRequest = {
        id: `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        messages,
        resolve,
        reject,
        model,
        temperature,
        maxTokens,
      };

      this.queue.push(request);

      // Process batch if it reaches the size limit
      if (this.queue.length >= this.batchSize) {
        this.processBatch();
      } else {
        // Start timer for timeout-based batching
        this.startTimer();
      }
    });
  }

  /**
   * Start timer for batch processing
   */
  private startTimer(): void {
    if (this.timer) {
      clearTimeout(this.timer);
    }

    this.timer = setTimeout(() => {
      if (this.queue.length > 0 && !this.processing) {
        this.processBatch();
      }
    }, this.batchTimeout);
  }

  /**
   * Process a batch of requests
   */
  private async processBatch(): Promise<void> {
    if (this.processing || this.queue.length === 0) {
      return;
    }

    this.processing = true;

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    // Group requests by model and parameters for efficient batching
    const batches = this.groupRequestsByModel();
    const batchPromises = batches.map(batch => this.executeBatch(batch));

    try {
      await Promise.all(batchPromises);
    } catch (error) {
      console.error('[RequestBatcher] Error processing batches:', error);
    } finally {
      this.processing = false;

      // Process remaining requests if any
      if (this.queue.length > 0) {
        this.startTimer();
      }
    }
  }

  /**
   * Group requests by model and parameters
   */
  private groupRequestsByModel(): BatchedRequest[][] {
    const groups = new Map<string, BatchedRequest[]>();

    for (const request of this.queue) {
      const key = `${request.model}-${request.temperature || 0.7}-${request.maxTokens || 'default'}`;
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key)!.push(request);
    }

    // Clear queue
    this.queue = [];

    // Split large groups into batches
    const batches: BatchedRequest[][] = [];
    const groupArray = Array.from(groups.values());
    for (const group of groupArray) {
      for (let i = 0; i < group.length; i += this.batchSize) {
        batches.push(group.slice(i, i + this.batchSize));
      }
    }

    return batches;
  }

  /**
   * Execute a batch of requests
   * Note: Most AI APIs don't support true batching, so we process in parallel
   * This still provides benefits through connection pooling and reduced overhead
   */
  private async executeBatch(batch: BatchedRequest[]): Promise<void> {
    if (batch.length === 0) return;

    const apiKey = await apiKeyManager.getNextKey({ operation: 'batchedRequest' });
    if (!apiKey) {
      const error = new Error('No API key available for batch processing');
      batch.forEach(req => req.reject(error));
      return;
    }

    const client = new OpenAI({
      baseURL: 'https://integrate.api.nvidia.com/v1',
      apiKey: apiKey,
    });

    // Process requests in parallel (simulating batching through concurrency)
    const promises = batch.map(async (request) => {
      try {
        const completion = await client.chat.completions.create({
          model: request.model,
          messages: request.messages,
          temperature: request.temperature,
          max_tokens: request.maxTokens,
        });

        const content = completion.choices[0]?.message?.content;
        if (!content) {
          throw new Error('No response content from AI model');
        }

        request.resolve(content);
      } catch (error) {
        request.reject(error instanceof Error ? error : new Error(String(error)));
      }
    });

    await Promise.allSettled(promises);
  }

  /**
   * Get current queue size
   */
  getQueueSize(): number {
    return this.queue.length;
  }

  /**
   * Clear the queue (for cleanup)
   */
  clear(): void {
    this.queue.forEach(req => {
      req.reject(new Error('Batch queue cleared'));
    });
    this.queue = [];
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}

// Singleton instance
const requestBatcher = new RequestBatcher(10, 100);

export default requestBatcher;

