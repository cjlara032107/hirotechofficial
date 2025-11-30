import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { z } from 'zod';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const updateIssueSchema = z.object({
  status: z.enum(['ACTIVE', 'RESOLVED', 'ACKNOWLEDGED']).optional(),
  resolution: z.string().optional(),
  rootCause: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

/**
 * GET /api/monitoring/production-issues/[id]
 * 
 * Get a specific production issue
 */
export async function GET(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    // Check authentication
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { id } = await props.params;

    const issue = await prisma.systemAlert.findUnique({
      where: { id },
    });

    if (!issue) {
      return NextResponse.json(
        { error: 'Issue not found' },
        { status: 404 }
      );
    }

    // Get acknowledged by user if exists
    const acknowledgedByUser = issue.acknowledgedBy
      ? await prisma.user.findUnique({
          where: { id: issue.acknowledgedBy },
          select: {
            id: true,
            name: true,
            email: true,
          },
        })
      : null;

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
    console.error('[Production Issues API] Error fetching issue:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch production issue',
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
 * PATCH /api/monitoring/production-issues/[id]
 * 
 * Update a production issue (resolve, acknowledge, or update details)
 */
export async function PATCH(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    // Check authentication
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { id } = await props.params;
    const body = await request.json();
    const validated = updateIssueSchema.parse(body);

    // Get existing issue
    const existingIssue = await prisma.systemAlert.findUnique({
      where: { id },
    });

    if (!existingIssue) {
      return NextResponse.json(
        { error: 'Issue not found' },
        { status: 404 }
      );
    }

    // Build update data
    const updateData: any = {
      metadata: {
        ...(existingIssue.metadata as Record<string, unknown> || {}),
        ...(validated.metadata || {}),
      },
    };

    if (validated.status) {
      updateData.status = validated.status;

      if (validated.status === 'RESOLVED') {
        updateData.resolvedAt = new Date();
      } else if (validated.status === 'ACKNOWLEDGED') {
        updateData.acknowledgedAt = new Date();
        updateData.acknowledgedBy = session.user.id;
      }
    }

    // Update metadata with resolution and root cause if provided
    if (validated.resolution) {
      updateData.metadata.resolution = validated.resolution;
    }

    if (validated.rootCause) {
      updateData.metadata.rootCause = validated.rootCause;
    }

    // Update issue
    const issue = await prisma.systemAlert.update({
      where: { id },
      data: updateData,
    });

    // Get acknowledged by user if exists
    const acknowledgedByUser = issue.acknowledgedBy
      ? await prisma.user.findUnique({
          where: { id: issue.acknowledgedBy },
          select: {
            id: true,
            name: true,
            email: true,
          },
        })
      : null;

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
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          error: 'Validation error',
          details: error.issues,
        },
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
    }

    console.error('[Production Issues API] Error updating issue:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to update production issue',
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

