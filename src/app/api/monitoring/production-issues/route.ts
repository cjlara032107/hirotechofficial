import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { z } from 'zod';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const createIssueSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().min(1),
  severity: z.enum(['INFO', 'WARNING', 'ERROR', 'CRITICAL']),
  type: z.enum([
    'API_RATE_LIMIT_EXHAUSTION',
    'DATABASE_CONNECTION_ISSUE',
    'DATABASE_POOL_EXHAUSTION',
    'MEMORY_LEAK_DETECTED',
    'SYSTEM_ERROR',
    'JOB_FAILURE',
    'HIGH_ERROR_RATE',
    'PERFORMANCE_DEGRADATION',
  ]).optional(),
  affectedServices: z.array(z.string()).optional(),
  rootCause: z.string().optional(),
  resolution: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

/**
 * GET /api/monitoring/production-issues
 * 
 * Returns production issues/incidents
 * 
 * Query parameters:
 * - status: 'ACTIVE' | 'RESOLVED' | 'ACKNOWLEDGED' (optional)
 * - severity: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL' (optional)
 * - type: AlertType (optional)
 * - limit: number (default: 50)
 * - offset: number (default: 0)
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
    const status = searchParams.get('status') as 'ACTIVE' | 'RESOLVED' | 'ACKNOWLEDGED' | null;
    const severity = searchParams.get('severity') as 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL' | null;
    const type = searchParams.get('type');
    const limit = parseInt(searchParams.get('limit') || '50', 10);
    const offset = parseInt(searchParams.get('offset') || '0', 10);

    // Build where clause
    const where: any = {};

    if (status) {
      where.status = status;
    }

    if (severity) {
      where.severity = severity;
    }

    if (type) {
      where.type = type;
    }

    // Get issues
    const [issues, total] = await Promise.all([
      prisma.systemAlert.findMany({
        where,
        take: limit,
        skip: offset,
        orderBy: {
          createdAt: 'desc',
        },
      }),
      prisma.systemAlert.count({ where }),
    ]);

    // Get user details for acknowledged issues
    const acknowledgedUserIds = issues
      .filter((issue) => issue.acknowledgedBy)
      .map((issue) => issue.acknowledgedBy)
      .filter((id): id is string => id !== null);

    const acknowledgedUsers = acknowledgedUserIds.length > 0
      ? await prisma.user.findMany({
          where: {
            id: { in: acknowledgedUserIds },
          },
          select: {
            id: true,
            name: true,
            email: true,
          },
        })
      : [];

    const userMap = new Map(acknowledgedUsers.map((user) => [user.id, user]));

    // Get statistics
    const stats = {
      total: await prisma.systemAlert.count(),
      active: await prisma.systemAlert.count({ where: { status: 'ACTIVE' } }),
      resolved: await prisma.systemAlert.count({ where: { status: 'RESOLVED' } }),
      acknowledged: await prisma.systemAlert.count({ where: { status: 'ACKNOWLEDGED' } }),
      bySeverity: {
        INFO: await prisma.systemAlert.count({ where: { severity: 'INFO' } }),
        WARNING: await prisma.systemAlert.count({ where: { severity: 'WARNING' } }),
        ERROR: await prisma.systemAlert.count({ where: { severity: 'ERROR' } }),
        CRITICAL: await prisma.systemAlert.count({ where: { severity: 'CRITICAL' } }),
      },
    };

    return NextResponse.json(
      {
        success: true,
        data: {
          issues: issues.map((issue) => {
            const acknowledgedByUser = issue.acknowledgedBy
              ? userMap.get(issue.acknowledgedBy)
              : null;

            return {
              id: issue.id,
              type: issue.type,
              severity: issue.severity,
              title: issue.title,
              message: issue.message,
              status: issue.status,
              metadata: issue.metadata,
              resolvedAt: issue.resolvedAt?.toISOString() || null,
              acknowledgedAt: issue.acknowledgedAt?.toISOString() || null,
              acknowledgedBy: acknowledgedByUser
                ? {
                    id: acknowledgedByUser.id,
                    name: acknowledgedByUser.name,
                    email: acknowledgedByUser.email,
                  }
                : null,
              createdAt: issue.createdAt.toISOString(),
              updatedAt: issue.updatedAt.toISOString(),
            };
          }),
          pagination: {
            total,
            limit,
            offset,
            hasMore: offset + limit < total,
          },
          stats,
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
    console.error('[Production Issues API] Error fetching issues:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch production issues',
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

/**
 * POST /api/monitoring/production-issues
 * 
 * Create a new production issue/incident
 */
export async function POST(request: NextRequest) {
  try {
    // Check authentication
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const body = await request.json();
    const validated = createIssueSchema.parse(body);

    // Create issue using SystemAlert model
    const issue = await prisma.systemAlert.create({
      data: {
        type: validated.type || 'SYSTEM_ERROR',
        severity: validated.severity,
        title: validated.title,
        message: validated.description,
        status: 'ACTIVE',
        metadata: {
          ...validated.metadata,
          affectedServices: validated.affectedServices || [],
          rootCause: validated.rootCause || null,
          resolution: validated.resolution || null,
          createdBy: session.user.id,
        },
      },
    });

    return NextResponse.json(
      {
        success: true,
        data: {
          id: issue.id,
          type: issue.type,
          severity: issue.severity,
          title: issue.title,
          message: issue.message,
          status: issue.status,
          createdAt: issue.createdAt.toISOString(),
        },
      },
      {
        status: 201,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          error: 'Validation error',
          details: error.errors,
        },
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
    }

    console.error('[Production Issues API] Error creating issue:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to create production issue',
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

