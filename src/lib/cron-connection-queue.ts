/**
 * Connection queue for cron jobs to prevent simultaneous database access
 * This ensures cron jobs don't compete for the single connection in serverless
 */

let connectionQueue: Array<{
  resolve: () => void;
  timestamp: number;
}> = [];
let isProcessing = false;

/**
 * Acquire a connection lock for cron jobs
 * This ensures only one cron job accesses the database at a time
 */
export async function acquireCronConnection(timeout = 30000): Promise<() => void> {
  return new Promise((resolve, reject) => {
    const timestamp = Date.now();
    
    // If no one is processing, acquire immediately
    if (!isProcessing && connectionQueue.length === 0) {
      isProcessing = true;
      resolve(() => {
        isProcessing = false;
        // Process next in queue
        if (connectionQueue.length > 0) {
          const next = connectionQueue.shift();
          if (next) {
            isProcessing = true;
            next.resolve();
          }
        }
      });
      return;
    }
    
    // Otherwise, queue up
    connectionQueue.push({
      resolve: () => {
        isProcessing = true;
        resolve(() => {
          isProcessing = false;
          // Process next in queue
          if (connectionQueue.length > 0) {
            const next = connectionQueue.shift();
            if (next) {
              isProcessing = true;
              next.resolve();
            }
          }
        });
      },
      timestamp,
    });
    
    // Timeout after 30 seconds
    setTimeout(() => {
      const index = connectionQueue.findIndex(item => item.timestamp === timestamp);
      if (index !== -1) {
        connectionQueue.splice(index, 1);
        reject(new Error('Connection queue timeout - another cron job is taking too long'));
      }
    }, timeout);
  });
}

