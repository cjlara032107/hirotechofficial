import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ pageId: string }> }
) {
  try {
    const { pageId } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Fetch page with auto-pipeline settings
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: pageId,
        organizationId: session.user.organizationId,
      },
      include: {
        autoPipeline: true,
      },
    });

    if (!page) {
      return NextResponse.json({ error: 'Page not found' }, { status: 404 });
    }

    return NextResponse.json(page);
  } catch (error) {
    console.error('Get page error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch page' },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  props: { params: Promise<{ pageId: string }> }
) {
  try {
    const { pageId } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { autoPipelineId, autoPipelineMode, autoSync } = body;

    // Verify page belongs to user's organization
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: pageId,
        organizationId: session.user.organizationId
      }
    });

    if (!page) {
      return NextResponse.json({ error: 'Page not found' }, { status: 404 });
    }

    // Build update data object conditionally
    const updateData: {
      autoPipelineId?: string | null;
      autoPipelineMode?: 'SKIP_EXISTING' | 'UPDATE_EXISTING';
      autoSync?: boolean;
    } = {};

    if (autoPipelineId !== undefined) {
      updateData.autoPipelineId = autoPipelineId === null || autoPipelineId === 'none' ? null : autoPipelineId;
    }
    if (autoPipelineMode !== undefined) {
      updateData.autoPipelineMode = (autoPipelineMode || 'SKIP_EXISTING') as 'SKIP_EXISTING' | 'UPDATE_EXISTING';
    }
    if (autoSync !== undefined) {
      updateData.autoSync = Boolean(autoSync);
    }

    // Update settings - only update if we have data to update
    if (Object.keys(updateData).length === 0) {
      return NextResponse.json(page);
    }

    const updated = await prisma.facebookPage.update({
      where: { id: pageId },
      data: updateData
    });

    return NextResponse.json(updated);
  } catch (error) {
    console.error('Update page settings error:', error);
    return NextResponse.json(
      { error: 'Failed to update settings' },
      { status: 500 }
    );
  }
}

