import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { logger } from '@/lib/utils/logger';

/**
 * GET /api/developer/databases
 * Get all configured databases (developer only)
 */
export async function GET() {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check developer role
    if (session.user.role !== 'DEVELOPER') {
      return NextResponse.json(
        { error: 'Forbidden - Developer access required' },
        { status: 403 }
      );
    }

    const dbCount = parseInt(process.env.DB_COUNT || '1', 10);
    const databases = [];

    for (let i = 0; i < dbCount; i++) {
      const dbUrl = process.env[`DATABASE_URL_${i}`];
      const directUrl = process.env[`DIRECT_URL_${i}`];

      if (dbUrl) {
        // Extract project reference from URL
        const projectRefMatch = dbUrl.match(/postgres\.([^.]+)\./);
        const projectRef = projectRefMatch ? projectRefMatch[1] : 'unknown';

        databases.push({
          index: i,
          projectRef,
          hasPooledUrl: !!dbUrl,
          hasDirectUrl: !!directUrl,
          // Don't expose full URLs for security
          urlPreview: dbUrl.replace(/:[^:@]+@/, ':****@').substring(0, 80) + '...',
        });
      }
    }

    // Calculate total connection capacity
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    const connectionsPerDatabase = isVercel ? 20 : 30;
    const totalConnectionCapacity = dbCount * connectionsPerDatabase;
    const supabasePoolCapacity = dbCount * 200; // Each Supabase free tier = 200 pooled connections

    return NextResponse.json({
      success: true,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      dbCount,
      routingStrategy: process.env.DB_ROUTING_STRATEGY || 'hash',
      databases,
      capacity: {
        connectionsPerDatabase,
        totalConnectionCapacity,
        supabasePoolCapacity,
        environment: isVercel ? 'vercel' : 'traditional',
      },
    });
  } catch (error) {
    logger.error('Get databases error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json(
      { error: 'Failed to fetch databases' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/developer/databases
 * Add a new database (developer only)
 * Note: This updates environment variables, which requires server restart
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check developer role
    if (session.user.role !== 'DEVELOPER') {
      return NextResponse.json(
        { error: 'Forbidden - Developer access required' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { databaseUrl, directUrl, name } = body;

    if (!databaseUrl || typeof databaseUrl !== 'string') {
      return NextResponse.json(
        { error: 'databaseUrl is required' },
        { status: 400 }
      );
    }

    // Validate URL format
    if (!databaseUrl.startsWith('postgresql://')) {
      return NextResponse.json(
        { error: 'Invalid database URL format. Must start with postgresql://' },
        { status: 400 }
      );
    }

    // Get current database count
    const currentCount = parseInt(process.env.DB_COUNT || '1', 10);
    const nextIndex = currentCount;

    // Test the connection
    try {
      const testClient = new (await import('@prisma/client')).PrismaClient({
        datasources: {
          db: {
            url: databaseUrl,
          },
        },
      });

      await testClient.$queryRaw`SELECT 1`;
      await testClient.$disconnect();
    } catch (testError) {
      return NextResponse.json(
        { 
          error: 'Database connection test failed',
          details: testError instanceof Error ? testError.message : String(testError)
        },
        { status: 400 }
      );
    }

    // Calculate new capacity after adding this database
    const isVercel = process.env.VERCEL === '1' || process.env.NEXT_PUBLIC_VERCEL_ENV;
    const connectionsPerDatabase = isVercel ? 20 : 30;
    const currentCapacity = parseInt(process.env.DB_COUNT || '1', 10) * connectionsPerDatabase;
    const newCapacity = (nextIndex + 1) * connectionsPerDatabase;
    const capacityIncrease = newCapacity - currentCapacity;
    const newSupabaseCapacity = (nextIndex + 1) * 200;

    // Return instructions for adding to .env.local
    // (We can't modify .env.local at runtime, so we provide instructions)
    return NextResponse.json({
      success: true,
      message: 'Database connection test passed. Add to .env.local:',
      instructions: {
        step1: `Add to .env.local:`,
        step2: `DATABASE_URL_${nextIndex}="${databaseUrl}"`,
        step3: directUrl ? `DIRECT_URL_${nextIndex}="${directUrl}"` : null,
        step4: `Update DB_COUNT=${nextIndex + 1}`,
        step5: `Restart server: npm run dev`,
      },
      nextIndex,
      connectionTest: 'passed',
      capacity: {
        current: currentCapacity,
        new: newCapacity,
        increase: capacityIncrease,
        supabasePoolCapacity: newSupabaseCapacity,
        message: `After restart, total capacity will increase from ${currentCapacity} to ${newCapacity} connections (+${capacityIncrease})`,
      },
    }, { status: 200 });
  } catch (error) {
    logger.error('Add database error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json(
      { error: 'Failed to add database' },
      { status: 500 }
    );
  }
}

