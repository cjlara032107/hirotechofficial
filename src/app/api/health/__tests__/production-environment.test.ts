/**
 * Production Environment Tests
 * 
 * Tests to verify the application works correctly in production environment:
 * - Environment variable validation
 * - Production-specific configurations
 * - Health check endpoint functionality
 * - Service connectivity in production mode
 */

import { NextRequest } from 'next/server';
import { GET } from '../route';
import { prisma } from '@/lib/db';
import { checkConnectionPoolHealth } from '@/lib/db-health';

// Note: Next.js server modules are mocked in jest.setup.js
// The NextResponse.json mock should work from there

// Mock dependencies
jest.mock('@/lib/db', () => ({
  prisma: {
    user: {
      count: jest.fn(),
    },
  },
}));

jest.mock('@/lib/db-health', () => ({
  checkConnectionPoolHealth: jest.fn(),
}));

jest.mock('@/lib/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

jest.mock('@/lib/utils/request-logger', () => ({
  logRequest: jest.fn(),
  logResponse: jest.fn(),
}));

describe('Production Environment Tests', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetAllMocks();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('Environment Variable Validation', () => {
    it('should pass health check when all required environment variables are set', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.status).toBe('healthy');
      expect(data.services.environment.status).toBe('healthy');
      expect(data.requiredEnvVars.DATABASE_URL).toBe(true);
      expect(data.requiredEnvVars.NEXTAUTH_SECRET).toBe(true);
      expect(data.requiredEnvVars.NEXT_PUBLIC_SUPABASE_URL).toBe(true);
      expect(data.requiredEnvVars.NEXT_PUBLIC_SUPABASE_ANON_KEY).toBe(true);
      expect(data.requiredEnvVars.FACEBOOK_APP_ID).toBe(true);
      expect(data.requiredEnvVars.FACEBOOK_APP_SECRET).toBe(true);
    });

    it('should fail health check when required environment variables are missing', async () => {
      process.env.NODE_ENV = 'production';
      delete process.env.DATABASE_URL;
      delete process.env.NEXTAUTH_SECRET;

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(response.status).toBe(503);
      expect(data.status).toBe('unhealthy');
      expect(data.services.environment.status).toBe('unhealthy');
      expect(data.requiredEnvVars.DATABASE_URL).toBe(false);
      expect(data.requiredEnvVars.NEXTAUTH_SECRET).toBe(false);
    });

    it('should include warnings for missing optional environment variables', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';
      delete process.env.REDIS_URL;
      delete process.env.NEXT_PUBLIC_APP_URL;

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.warnings).toContain('REDIS_URL not set - Campaign sending will not work');
      expect(data.warnings).toContain('NEXT_PUBLIC_APP_URL not set - OAuth redirects may fail');
    });
  });

  describe('Production Mode Configuration', () => {
    it('should correctly identify production environment', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(data.environment.nodeEnv).toBe('production');
    });

    it('should handle development environment correctly', async () => {
      process.env.NODE_ENV = 'development';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(data.environment.nodeEnv).toBe('development');
    });
  });

  describe('Service Health Checks', () => {
    it('should report healthy database connection', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(data.services.database.status).toBe('healthy');
      expect(data.services.database.details).toContain('Database connection successful');
      expect(data.services.database.details).toContain('50ms');
    });

    it('should report unhealthy database connection', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: false,
        error: 'Connection timeout',
        errorCode: 'P1001',
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(response.status).toBe(503);
      expect(data.status).toBe('unhealthy');
      expect(data.services.database.status).toBe('unhealthy');
      expect(data.services.database.details).toContain('Connection timeout');
    });

    it('should report healthy Prisma client', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(data.services.prisma.status).toBe('healthy');
      expect(data.services.prisma.details).toContain('Prisma client operational');
      expect(data.services.prisma.details).toContain('10 users');
    });

    it('should report unhealthy Prisma client on error', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockRejectedValue(new Error('Prisma client error'));

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(response.status).toBe(503);
      expect(data.status).toBe('unhealthy');
      expect(data.services.prisma.status).toBe('unhealthy');
      expect(data.services.prisma.details).toContain('Prisma client error');
    });
  });

  describe('Production Readiness', () => {
    it('should return all required information for production monitoring', async () => {
      process.env.NODE_ENV = 'production';
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.NEXTAUTH_SECRET = 'test-secret-minimum-32-characters-long';
      process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
      process.env.FACEBOOK_APP_ID = 'test-app-id';
      process.env.FACEBOOK_APP_SECRET = 'test-app-secret';
      process.env.REDIS_URL = 'redis://localhost:6379';
      process.env.NEXT_PUBLIC_APP_URL = 'https://example.com';

      (checkConnectionPoolHealth as jest.Mock).mockResolvedValue({
        healthy: true,
        responseTime: 50,
      });
      (prisma.user.count as jest.Mock).mockResolvedValue(10);

      // Create a proper mock request matching the route handler's expectations
      const url = new URL('http://localhost:3000/api/health');
      const request = {
        url: url.toString(),
        method: 'GET',
        headers: new Headers(),
        nextUrl: {
          pathname: url.pathname,
          searchParams: url.searchParams,
        },
      } as any;
      
      let response;
      try {
        response = await GET(request);
      } catch (error) {
        console.error('GET function threw error:', error);
        throw error;
      }
      
      // Check if response exists
      expect(response).toBeDefined();
      expect(response).not.toBeNull();
      
      // NextResponse.json() returns a Response-like object with json() method
      const data = await response.json();

      expect(data).toHaveProperty('timestamp');
      expect(data).toHaveProperty('status');
      expect(data).toHaveProperty('services');
      expect(data).toHaveProperty('environment');
      expect(data).toHaveProperty('requiredEnvVars');
      expect(data).toHaveProperty('optionalEnvVars');
      expect(data).toHaveProperty('warnings');
      expect(Array.isArray(data.warnings)).toBe(true);
    });
  });
});

