/**
 * Structured logging utility with log levels
 * Supports: debug, info, warn, error
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogContext {
  [key: string]: unknown;
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: LogContext;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

/**
 * Logger class for structured logging with log levels and context
 * 
 * Supports different log levels (debug, info, warn, error) and provides
 * structured logging with context information. In development, logs are
 * formatted for readability. In production, logs are formatted as JSON
 * for log aggregation systems.
 */
class Logger {
  private minLevel: LogLevel;
  private isDevelopment: boolean;

  /**
   * Creates a new Logger instance
   * 
   * Determines minimum log level from LOG_LEVEL environment variable or
   * defaults to 'info' in production and 'debug' in development.
   */
  constructor() {
    // Determine minimum log level from environment
    // Safe for both server and client (Next.js exposes process.env to client)
    const envLevel = (typeof process !== 'undefined' && process.env?.LOG_LEVEL?.toLowerCase()) as LogLevel | undefined;
    const nodeEnv = typeof process !== 'undefined' ? process.env?.NODE_ENV : 'development';
    
    this.minLevel = envLevel && ['debug', 'info', 'warn', 'error'].includes(envLevel) 
      ? envLevel 
      : nodeEnv === 'production' 
        ? 'info' 
        : 'debug';
    
    this.isDevelopment = nodeEnv !== 'production';
  }

  /**
   * Determines if a log level should be output based on the minimum configured level
   * 
   * @param level - The log level to check
   * @returns True if the level should be logged, false otherwise
   */
  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    const currentIndex = levels.indexOf(this.minLevel);
    const messageIndex = levels.indexOf(level);
    return messageIndex >= currentIndex;
  }

  /**
   * Formats a log entry for output
   * 
   * In development: Returns a human-readable format with emojis and context
   * In production: Returns JSON string for log aggregation systems
   * 
   * @param entry - The log entry to format
   * @returns Formatted log string
   */
  private formatLog(entry: LogEntry): string {
    if (this.isDevelopment) {
      // In development, use readable format
      const timestamp = entry.timestamp;
      const levelEmoji = {
        debug: '🔍',
        info: 'ℹ️',
        warn: '⚠️',
        error: '❌',
      }[entry.level];
      
      const contextStr = entry.context 
        ? ` | ${Object.entries(entry.context)
            .map(([key, value]) => `${key}: ${this.formatValue(value)}`)
            .join(' | ')}`
        : '';
      
      const errorStr = entry.error
        ? ` | Error: ${entry.error.name} - ${entry.error.message}`
        : '';
      
      return `[${timestamp}] ${levelEmoji} [${entry.level.toUpperCase()}] ${entry.message}${contextStr}${errorStr}`;
    }
    
    // In production, use JSON format for log aggregation
    return JSON.stringify(entry);
  }

  /**
   * Formats a value for display in log context strings
   * 
   * Handles null, undefined, objects (as JSON), and primitives
   * 
   * @param value - The value to format
   * @returns String representation of the value
   */
  private formatValue(value: unknown): string {
    if (value === null || value === undefined) {
      return String(value);
    }
    if (typeof value === 'object') {
      try {
        return JSON.stringify(value);
      } catch {
        return '[Object]';
      }
    }
    return String(value);
  }

  /**
   * Creates a structured log entry with timestamp and optional context/error
   * 
   * @param level - The log level (debug, info, warn, error)
   * @param message - The log message
   * @param context - Optional context object with additional data
   * @param error - Optional error object to include in the log
   * @returns A complete log entry object
   */
  private createLogEntry(
    level: LogLevel,
    message: string,
    context?: LogContext,
    error?: Error
  ): LogEntry {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
    };

    if (context) {
      entry.context = context;
    }

    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        stack: this.isDevelopment ? error.stack : undefined,
      };
    }

    return entry;
  }

  /**
   * Outputs a log entry to the appropriate console method
   * 
   * Routes to console.debug, console.log, console.warn, or console.error
   * based on the log level. Only outputs if the level meets the minimum threshold.
   * 
   * @param entry - The log entry to output
   */
  private output(entry: LogEntry): void {
    if (!this.shouldLog(entry.level)) {
      return;
    }

    const formatted = this.formatLog(entry);

    switch (entry.level) {
      case 'debug':
        console.debug(formatted);
        break;
      case 'info':
        console.log(formatted);
        break;
      case 'warn':
        console.warn(formatted);
        break;
      case 'error':
        console.error(formatted);
        if (entry.error?.stack && this.isDevelopment) {
          console.error(entry.error.stack);
        }
        break;
    }
  }

  /**
   * Logs a debug-level message
   * 
   * @param message - The debug message to log
   * @param context - Optional context object with additional debugging information
   */
  debug(message: string, context?: LogContext): void {
    const entry = this.createLogEntry('debug', message, context);
    this.output(entry);
  }

  /**
   * Logs an info-level message
   * 
   * @param message - The informational message to log
   * @param context - Optional context object with additional information
   */
  info(message: string, context?: LogContext): void {
    const entry = this.createLogEntry('info', message, context);
    this.output(entry);
  }

  /**
   * Logs a warning-level message
   * 
   * @param message - The warning message to log
   * @param context - Optional context object with additional warning details
   */
  warn(message: string, context?: LogContext): void {
    const entry = this.createLogEntry('warn', message, context);
    this.output(entry);
  }

  /**
   * Logs an error-level message with optional error object
   * 
   * @param message - The error message to log
   * @param error - Optional error object or unknown value to log
   * @param context - Optional context object with additional error details
   */
  error(message: string, error?: Error | unknown, context?: LogContext): void {
    const err = error instanceof Error 
      ? error 
      : error 
        ? new Error(String(error))
        : undefined;
    
    const entry = this.createLogEntry('error', message, context, err);
    this.output(entry);
  }

  /**
   * Creates a child logger that automatically includes additional context in all logs
   * 
   * Useful for scoping logs to a specific module, request, or operation.
   * The child logger inherits all settings from the parent but adds the provided
   * context to every log entry.
   * 
   * @param context - Context object to include in all logs from this child logger
   * @returns A new Logger instance with the additional context
   */
  child(context: LogContext): Logger {
    const childLogger = new Logger();
    const originalOutput = childLogger.output.bind(childLogger);
    
    childLogger.output = (entry: LogEntry) => {
      entry.context = { ...context, ...entry.context };
      originalOutput(entry);
    };
    
    return childLogger;
  }
}

// Export singleton instance
export const logger = new Logger();

// Export class for testing
export { Logger };

