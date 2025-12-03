// Jest setup file
// This file runs before each test file

// Import testing library matchers
import '@testing-library/jest-dom'

// Mock Next.js modules
jest.mock('next/server', () => ({
  NextRequest: jest.fn(),
  NextResponse: {
    json: jest.fn((data, init) => ({
      json: async () => data,
      status: init?.status || 200,
      headers: new Headers(init?.headers),
    })),
  },
}))

// Mock Next.js navigation
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    refresh: jest.fn(),
    back: jest.fn(),
    forward: jest.fn(),
    prefetch: jest.fn(),
  }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}))

// Mock sonner toast
jest.mock('sonner', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
  },
}))

// Suppress console.error in tests (we test error scenarios explicitly)
const originalError = console.error;
beforeAll(() => {
  console.error = (...args) => {
    // Suppress React act warnings and expected error logs in tests
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('act(...)') || args[0].includes('Analysis error:'))
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  console.error = originalError;
});

// Mock Prisma client to avoid import errors in tests
jest.mock('@prisma/client', () => ({
  Prisma: {
    PrismaClientKnownRequestError: class PrismaClientKnownRequestError extends Error {
      constructor(message, meta) {
        super(message);
        this.code = meta.code;
        this.clientVersion = meta.clientVersion;
        this.name = 'PrismaClientKnownRequestError';
      }
    },
  },
  AlertType: {
    JOB_FAILURE: 'JOB_FAILURE',
    HIGH_ERROR_RATE: 'HIGH_ERROR_RATE',
    PERFORMANCE_DEGRADATION: 'PERFORMANCE_DEGRADATION',
    API_RATE_LIMIT_EXHAUSTION: 'API_RATE_LIMIT_EXHAUSTION',
    DATABASE_CONNECTION_ISSUE: 'DATABASE_CONNECTION_ISSUE',
    DATABASE_POOL_EXHAUSTION: 'DATABASE_POOL_EXHAUSTION',
  },
  AlertSeverity: {
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    CRITICAL: 'CRITICAL',
  },
  AlertStatus: {
    ACTIVE: 'ACTIVE',
    RESOLVED: 'RESOLVED',
    ACKNOWLEDGED: 'ACKNOWLEDGED',
  },
}), { virtual: true });

// Mock environment variables
process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co'
process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key'
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test'

// Polyfill setImmediate for Jest environment (Node.js has it, but Jest may not)
if (typeof setImmediate === 'undefined') {
  global.setImmediate = (fn) => setTimeout(fn, 0);
}

