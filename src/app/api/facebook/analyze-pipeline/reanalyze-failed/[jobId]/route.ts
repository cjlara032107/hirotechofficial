/**
 * API Route: Reanalyze Failed Contacts
 * 
 * This endpoint extracts failed and timed-out contact IDs from a pipeline analysis job
 * and reanalyzes them using the analyzeSelectedContacts function.
 * 
 * POST /api/facebook/analyze-pipeline/reanalyze-failed/[jobId]
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireAuth } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';
import { analyzeSelectedContacts } from '@/lib/facebook/analyze-selected-contacts';

interface RouteParams {
  params: Promise<{ jobId: string }>;
}

export async function POST(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    // Validate session
    const authResult = await requireAuth();
    if ('error' in authResult) {
      return authResult.error;
    }
    const { session } = authResult;

    const { jobId } = await params;

    // Validate jobId
    if (!jobId || typeof jobId !== 'string') {
      return NextResponse.json(
        { error: 'Job ID required' },
        { status: 400 }
      );
    }

    const trimmedJobId = jobId.trim();
    if (trimmedJobId.length === 0) {
      return NextResponse.json(
        { error: 'Job ID cannot be empty' },
        { status: 400 }
      );
    }

    const uuidValidation = validateUUID(trimmedJobId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: 'Job ID must be a valid UUID format' },
        { status: uuidValidation.error.status }
      );
    }

    // Get the job and verify ownership
    const job = await prisma.syncJob.findFirst({
      where: {
        id: trimmedJobId,
        facebookPage: {
          organizationId: session.user.organizationId,
        },
      },
      include: {
        facebookPage: {
          select: {
            id: true,
            pageId: true,
            pageName: true,
            organizationId: true,
          },
        },
      },
    });

    if (!job) {
      return NextResponse.json(
        { error: 'Analysis job not found or unauthorized' },
        { status: 404 }
      );
    }

    // Extract failed contact IDs from errors
    const failedContactIds: string[] = [];
    const timeoutContactIds: string[] = [];

    if (job.errors && Array.isArray(job.errors)) {
      for (const error of job.errors) {
        // Handle different error formats
        if (typeof error === 'object' && error !== null) {
          const errorObj = error as { id?: string; error?: string; platform?: string };
          
          if (errorObj.id && errorObj.id !== 'unknown' && errorObj.id !== 'truncated') {
            const errorMessage = errorObj.error || '';
            
            // Check if it's a timeout error
            if (
              errorMessage.toLowerCase().includes('timeout') ||
              errorMessage.toLowerCase().includes('timed out') ||
              errorMessage.toLowerCase().includes('analysis timeout')
            ) {
              timeoutContactIds.push(errorObj.id);
            } else {
              // Regular failure
              failedContactIds.push(errorObj.id);
            }
          }
        }
      }
    }

    // Combine all failed contacts (timeouts are also failures)
    const allFailedContactIds = Array.from(new Set([...failedContactIds, ...timeoutContactIds]));

    if (allFailedContactIds.length === 0) {
      return NextResponse.json(
        { 
          success: false,
          error: 'No failed contacts found in this job',
          failedContacts: 0,
        },
        { status: 400 }
      );
    }

    console.log(`[Reanalyze Failed] Found ${allFailedContactIds.length} failed contacts (${timeoutContactIds.length} timeouts, ${failedContactIds.length} other failures)`);

    // Verify contacts exist and belong to the same organization
    const contacts = await prisma.contact.findMany({
      where: {
        id: { in: allFailedContactIds },
        facebookPage: {
          organizationId: session.user.organizationId,
        },
      },
      select: {
        id: true,
      },
    });

    const validContactIds = contacts.map(c => c.id);
    const invalidCount = allFailedContactIds.length - validContactIds.length;

    if (validContactIds.length === 0) {
      return NextResponse.json(
        { 
          success: false,
          error: 'No valid contacts found to reanalyze',
          failedContacts: allFailedContactIds.length,
        },
        { status: 400 }
      );
    }

    if (invalidCount > 0) {
      console.warn(`[Reanalyze Failed] ${invalidCount} contact IDs were invalid or not found`);
    }

    // Reanalyze the failed contacts
    // Use analyzeSelectedContacts which handles individual contact analysis
    const result = await analyzeSelectedContacts(
      validContactIds,
      session.user.organizationId
    );

    return NextResponse.json({
      success: true,
      message: `Reanalyzed ${result.successCount} of ${validContactIds.length} failed contacts`,
      reanalyzed: result.successCount,
      failed: result.failedCount,
      totalAttempted: validContactIds.length,
      errors: result.errors,
    });

  } catch (error) {
    console.error('Error reanalyzing failed contacts:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { 
        success: false,
        error: `Failed to reanalyze contacts: ${errorMessage}` 
      },
      { status: 500 }
    );
  }
}









