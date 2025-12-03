import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { systemMonitor } from '@/lib/monitoring/system-monitor';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * GET /api/monitoring/metrics
 * 
 * Returns system monitoring metrics including:
 * - Database query performance
 * - Memory usage
 * - Error rates by type
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

    // Get system metrics
    const metrics = systemMonitor.getSystemMetrics();

    return NextResponse.json(
      {
        success: true,
        data: metrics,
      },
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    console.error('[Monitoring API] Error fetching metrics:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch monitoring metrics',
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









