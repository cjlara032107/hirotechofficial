import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { systemMonitor } from '@/lib/monitoring/system-monitor';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * GET /api/monitoring/resource-usage
 * 
 * Returns resource usage metrics including:
 * - CPU usage
 * - Memory usage
 * - Network I/O
 * - Disk usage (if available)
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

    // Get resource usage stats
    const resources = systemMonitor.getResourceUsageStats();
    const memory = systemMonitor.getMemoryStats();

    // Get current system metrics
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    // Calculate disk usage (approximate - Node.js doesn't provide direct disk stats)
    // This would need to be implemented via system calls or external monitoring tools
    const diskUsage = {
      available: null as number | null,
      used: null as number | null,
      total: null as number | null,
      usagePercent: null as number | null,
      note: 'Disk usage monitoring requires system-level access. Consider using external monitoring tools.',
    };

    return NextResponse.json(
      {
        success: true,
        data: {
          cpu: {
            ...resources.cpu,
            currentProcess: {
              user: cpuUsage.user / 1000000, // Convert to seconds
              system: cpuUsage.system / 1000000, // Convert to seconds
            },
          },
          memory: {
            ...memory,
            currentProcess: {
              heapUsed: memoryUsage.heapUsed,
              heapTotal: memoryUsage.heapTotal,
              rss: memoryUsage.rss,
              external: memoryUsage.external,
              heapUsedMB: memoryUsage.heapUsed / 1024 / 1024,
              heapTotalMB: memoryUsage.heapTotal / 1024 / 1024,
              rssMB: memoryUsage.rss / 1024 / 1024,
              externalMB: memoryUsage.external / 1024 / 1024,
            },
          },
          network: resources.network,
          disk: diskUsage,
          timestamp: Date.now(),
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
    console.error('[Resource Usage API] Error fetching resource usage:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch resource usage',
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









