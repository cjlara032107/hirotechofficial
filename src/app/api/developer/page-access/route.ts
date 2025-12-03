import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

/**
 * GET /api/developer/page-access
 * Get all page access settings for the current developer
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

    // Get all page access settings for the current developer
    // Using findFirst with filter since userId might not be in generated types yet
    const allPageAccesses = await prisma.pageAccess.findMany({
      orderBy: {
        pagePath: 'asc',
      },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const pageAccesses = allPageAccesses.filter((pa: any) => pa.userId === session.user.id);

    return NextResponse.json(pageAccesses);
  } catch (error) {
    // Handle schema mismatch errors gracefully
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2022' || error.code === 'P2021') {
        // Table or column doesn't exist - database schema is out of sync
        console.warn(
          '[Page Access API] Database schema is out of sync. Page access feature requires migration. Returning empty array.'
        );
        // Return empty array when schema is missing
        return NextResponse.json([]);
      }
    }
    console.error('Get page access error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch page access' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/developer/page-access
 * Create or update page access setting
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
    const { pagePath, isEnabled } = body;

    if (!pagePath || typeof pagePath !== 'string') {
      return NextResponse.json(
        { error: 'pagePath is required' },
        { status: 400 }
      );
    }

    if (typeof isEnabled !== 'boolean') {
      return NextResponse.json(
        { error: 'isEnabled must be a boolean' },
        { status: 400 }
      );
    }

    // Upsert page access for the current developer
    // Using findFirst since compound unique constraint might not be in generated types
    const existing = await prisma.pageAccess.findFirst({
      where: {
        pagePath: pagePath,
      },
    });

    // Check if this existing record belongs to the current user
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const userOwnsRecord = existing && (existing as any).userId === session.user.id;
    
    const pageAccess = userOwnsRecord
      ? await prisma.pageAccess.update({
          where: { id: existing.id },
          data: { isEnabled },
        })
      : await prisma.pageAccess.create({
          data: {
            userId: session.user.id,
            pagePath: pagePath,
            isEnabled,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          } as any, // Type assertion needed until Prisma types are regenerated
        });

    return NextResponse.json(pageAccess, { status: 201 });
  } catch (error) {
    // Handle schema mismatch errors gracefully
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2022' || error.code === 'P2021') {
        // Table or column doesn't exist - database schema is out of sync
        console.warn(
          '[Page Access API] Database schema is out of sync. Page access feature requires migration.'
        );
        return NextResponse.json(
          { error: 'Database schema is out of sync. Please run database migration.' },
          { status: 503 }
        );
      }
    }
    console.error('Create/update page access error:', error);
    return NextResponse.json(
      { error: 'Failed to update page access' },
      { status: 500 }
    );
  }
}

