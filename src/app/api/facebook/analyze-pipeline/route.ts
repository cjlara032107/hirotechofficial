import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { startPipelineAnalysis } from '@/lib/facebook/pipeline-analyzer';
import { validateUUID } from '@/lib/api/validate-uuid';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { facebookPageId, forceUpdateExisting } = body;

    if (!facebookPageId) {
      return NextResponse.json(
        { error: 'facebookPageId is required' },
        { status: 400 }
      );
    }

    // Validate facebookPageId is valid UUID format
    if (typeof facebookPageId !== 'string') {
      return NextResponse.json(
        { error: 'facebookPageId must be a string' },
        { status: 400 }
      );
    }

    const trimmedFacebookPageId = facebookPageId.trim();
    if (trimmedFacebookPageId.length === 0) {
      return NextResponse.json(
        { error: 'facebookPageId cannot be empty' },
        { status: 400 }
      );
    }
    const uuidValidation = validateUUID(trimmedFacebookPageId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: uuidValidation.error.message },
        { status: uuidValidation.error.status }
      );
    }

    // Validate forceUpdateExisting is boolean if provided
    if (forceUpdateExisting !== undefined && typeof forceUpdateExisting !== 'boolean') {
      return NextResponse.json(
        { error: 'forceUpdateExisting must be a boolean' },
        { status: 400 }
      );
    }

    // Verify the page belongs to the user's organization
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: trimmedFacebookPageId,
        organizationId: session.user.organizationId,
      },
      include: {
        autoPipeline: true,
      },
    });

    if (!page) {
      return NextResponse.json(
        { error: 'Facebook page not found or access denied' },
        { status: 404 }
      );
    }

    // Allow analysis even without a pipeline - it will auto-create one after analysis
    if (!page.autoPipelineId) {
      console.log(`[Analyze Pipeline API] No pipeline configured for page ${trimmedFacebookPageId} - will auto-create after analysis`);
    }

    // Start pipeline analysis (force re-analysis if requested)
    // If no pipeline exists, analysis will auto-create one based on analyzed contacts
    const result = await startPipelineAnalysis(trimmedFacebookPageId);

    return NextResponse.json(result);
  } catch (error) {
    console.error('Error starting pipeline analysis:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    return NextResponse.json(
      { error: 'Failed to start pipeline analysis. Please try again.' },
      { status: 500 }
    );
  }
}

