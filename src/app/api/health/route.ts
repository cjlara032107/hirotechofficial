import { NextRequest, NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const startTime = Date.now();
  const requestId = `health-${Date.now()}`;
  
  try {
    console.log(`[Health Check ${requestId}] Starting health check`);

    const checks = {
      timestamp: new Date().toISOString(),
      status: 'healthy',
      services: {
        database: { status: 'unknown' as 'unknown' | 'healthy' | 'degraded' | 'unhealthy', details: '' },
        prisma: { status: 'unknown' as 'unknown' | 'healthy' | 'degraded' | 'unhealthy', details: '' },
        environment: { status: 'unknown' as 'unknown' | 'healthy' | 'degraded' | 'unhealthy', details: '' },
      },
      environment: {
        nodeEnv: process.env.NODE_ENV || 'development',
        nextVersion: process.env.npm_package_version || 'unknown',
      },
      requiredEnvVars: {} as Record<string, boolean>,
    };

    // Check Database Connection (safe with error handling)
    try {
      const { performHealthCheck } = await import('@/lib/health/comprehensive-health-check');
      const healthResult = await performHealthCheck();
      
      checks.services.database.status = healthResult.services.database.status as 'unknown' | 'healthy' | 'degraded' | 'unhealthy';
      checks.services.database.details = healthResult.services.database.message;
      
      checks.services.prisma.status = healthResult.services.database.status as 'unknown' | 'healthy' | 'degraded' | 'unhealthy';
      checks.services.prisma.details = `Database ${healthResult.services.database.status}`;
    } catch (healthError) {
      console.warn(`[Health Check ${requestId}] Comprehensive check failed, using fallback`, healthError);
      checks.services.database.status = 'unknown';
      checks.services.database.details = 'Health check module unavailable';
      checks.services.prisma.status = 'unknown';
      checks.services.prisma.details = 'Health check module unavailable';
    }

  // Check Required Environment Variables
  const requiredVars = [
    'DATABASE_URL',
    'NEXTAUTH_SECRET',
    'NEXT_PUBLIC_SUPABASE_URL',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'FACEBOOK_APP_ID',
    'FACEBOOK_APP_SECRET',
  ];

  const optionalVars = [
    'REDIS_URL',
    'NEXT_PUBLIC_APP_URL',
    'FACEBOOK_WEBHOOK_VERIFY_TOKEN',
  ];

  requiredVars.forEach(varName => {
    checks.requiredEnvVars[varName] = !!process.env[varName];
    if (!process.env[varName]) {
      checks.status = 'unhealthy';
      checks.services.environment.status = 'unhealthy';
      checks.services.environment.details = 'Missing required environment variables';
    }
  });

  const optionalEnvVars: Record<string, boolean> = {};
  optionalVars.forEach(varName => {
    optionalEnvVars[varName] = !!process.env[varName];
  });

  if (checks.services.environment.status === 'unknown') {
    checks.services.environment.status = 'healthy';
    checks.services.environment.details = 'All required environment variables present';
  }

  const response = {
    ...checks,
    optionalEnvVars,
    warnings: [] as string[],
  };

  // Add warnings for missing optional variables
  if (!process.env.REDIS_URL) {
    response.warnings.push('REDIS_URL not set - Campaign sending will not work');
  }
  if (!process.env.NEXT_PUBLIC_APP_URL) {
    response.warnings.push('NEXT_PUBLIC_APP_URL not set - OAuth redirects may fail');
  }

  const httpResponse = NextResponse.json(response, {
    status: checks.status === 'healthy' ? 200 : 503,
  });

    try {
      logResponse(request, httpResponse, startTime);
    } catch (logError) {
      // Non-critical - continue even if logging fails
      console.warn('[Health] Log response failed:', logError);
    }
    
    return httpResponse;
  } catch (error) {
    // Ultimate fallback - return error response if everything fails
    console.error('[Health] Critical error in health check:', error);
    return NextResponse.json(
      {
        timestamp: new Date().toISOString(),
        status: 'unhealthy',
        error: 'Health check failed',
        message: error instanceof Error ? error.message : 'Unknown error',
        services: {
          database: { status: 'unknown', details: 'Health check error' },
          prisma: { status: 'unknown', details: 'Health check error' },
          environment: { status: 'unknown', details: 'Health check error' },
        },
      },
      { status: 500 }
    );
  }
}

