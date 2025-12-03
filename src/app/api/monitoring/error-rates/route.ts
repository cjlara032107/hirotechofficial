import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * GET /api/monitoring/error-rates
 * 
 * Returns error rate metrics with time-based aggregations
 * 
 * Query parameters:
 * - timeWindow: '1h' | '24h' | '7d' | '30d' (default: '24h')
 * - groupBy: 'hour' | 'day' (default: 'hour' for <7d, 'day' for >=7d)
 * - errorType: Filter by specific error type
 * - errorCode: Filter by specific error code
 * - level: 'error' | 'warn' | 'info' (default: 'error')
 */
export async function GET(request: NextRequest) {
  try {
    // Check authentication
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const timeWindow = searchParams.get('timeWindow') || '24h';
    const groupBy = searchParams.get('groupBy');
    const errorType = searchParams.get('errorType');
    const errorCode = searchParams.get('errorCode');
    const level = searchParams.get('level') || 'error';

    // Calculate time window
    const now = new Date();
    let startDate: Date;
    let defaultGroupBy: 'hour' | 'day';

    switch (timeWindow) {
      case '1h':
        startDate = new Date(now.getTime() - 60 * 60 * 1000);
        defaultGroupBy = 'hour';
        break;
      case '24h':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        defaultGroupBy = 'hour';
        break;
      case '7d':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        defaultGroupBy = 'day';
        break;
      case '30d':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        defaultGroupBy = 'day';
        break;
      default:
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        defaultGroupBy = 'hour';
    }

    const finalGroupBy = (groupBy as 'hour' | 'day') || defaultGroupBy;

    // Build where clause
    const where: any = {
      createdAt: {
        gte: startDate,
      },
      level,
    };

    if (errorType) {
      where.errorType = errorType;
    }

    if (errorCode) {
      where.errorCode = errorCode;
    }

    // Get total error count
    const totalErrors = await prisma.errorLog.count({ where });

    // Get errors by type
    const errorsByType = await prisma.errorLog.groupBy({
      by: ['errorType'],
      where,
      _count: {
        id: true,
      },
      orderBy: {
        _count: {
          id: 'desc',
        },
      },
    });

    // Get errors by code
    const errorsByCode = await prisma.errorLog.groupBy({
      by: ['errorCode'],
      where: {
        ...where,
        errorCode: { not: null },
      },
      _count: {
        id: true,
      },
      orderBy: {
        _count: {
          id: 'desc',
        },
      },
    });

    // Get time-series data
    const allErrors = await prisma.errorLog.findMany({
      where,
      select: {
        createdAt: true,
        errorType: true,
        errorCode: true,
        level: true,
      },
      orderBy: {
        createdAt: 'asc',
      },
    });

    // Group by time window
    const timeSeries: Record<string, number> = {};
    const timeSeriesByType: Record<string, Record<string, number>> = {};

    allErrors.forEach((error) => {
      const date = new Date(error.createdAt);
      let timeKey: string;

      if (finalGroupBy === 'hour') {
        // Group by hour
        timeKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}T${String(date.getHours()).padStart(2, '0')}:00:00`;
      } else {
        // Group by day
        timeKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
      }

      timeSeries[timeKey] = (timeSeries[timeKey] || 0) + 1;

      if (error.errorType) {
        if (!timeSeriesByType[timeKey]) {
          timeSeriesByType[timeKey] = {};
        }
        timeSeriesByType[timeKey][error.errorType] = (timeSeriesByType[timeKey][error.errorType] || 0) + 1;
      }
    });

    // Calculate error rate (errors per hour)
    const hoursInWindow = (now.getTime() - startDate.getTime()) / (1000 * 60 * 60);
    const errorRate = hoursInWindow > 0 ? totalErrors / hoursInWindow : 0;

    // Get recent errors (last 50)
    const recentErrors = await prisma.errorLog.findMany({
      where,
      take: 50,
      orderBy: {
        createdAt: 'desc',
      },
      select: {
        id: true,
        level: true,
        message: true,
        errorType: true,
        errorCode: true,
        createdAt: true,
        context: true,
      },
    });

    // Calculate trends (compare first half vs second half of time window)
    const midpoint = new Date(startDate.getTime() + (now.getTime() - startDate.getTime()) / 2);
    const firstHalfCount = await prisma.errorLog.count({
      where: {
        ...where,
        createdAt: {
          gte: startDate,
          lt: midpoint,
        },
      },
    });
    const secondHalfCount = await prisma.errorLog.count({
      where: {
        ...where,
        createdAt: {
          gte: midpoint,
          lte: now,
        },
      },
    });

    const trend = firstHalfCount > 0
      ? ((secondHalfCount - firstHalfCount) / firstHalfCount) * 100
      : secondHalfCount > 0 ? 100 : 0;

    return NextResponse.json(
      {
        success: true,
        data: {
          timeWindow,
          groupBy: finalGroupBy,
          totalErrors,
          errorRate: Math.round(errorRate * 100) / 100,
          trend: Math.round(trend * 100) / 100,
          errorsByType: errorsByType.map((e) => ({
            errorType: e.errorType || 'unknown',
            count: e._count.id,
          })),
          errorsByCode: errorsByCode.map((e) => ({
            errorCode: e.errorCode || 'unknown',
            count: e._count.id,
          })),
          timeSeries: Object.entries(timeSeries)
            .map(([time, count]) => ({ time, count }))
            .sort((a, b) => a.time.localeCompare(b.time)),
          timeSeriesByType: Object.entries(timeSeriesByType).map(([time, types]) => ({
            time,
            types: Object.entries(types).map(([type, count]) => ({ type, count })),
          })).sort((a, b) => a.time.localeCompare(b.time)),
          recentErrors: recentErrors.map((e) => ({
            id: e.id,
            level: e.level,
            message: e.message.substring(0, 200),
            errorType: e.errorType,
            errorCode: e.errorCode,
            createdAt: e.createdAt.toISOString(),
            context: e.context,
          })),
        },
      },
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    console.error('[Error Rates API] Error fetching error rates:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch error rates',
        details: process.env.NODE_ENV === 'development' 
          ? error instanceof Error ? error.message : String(error)
          : undefined,
      },
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  }
}









