import { NextRequest, NextResponse } from 'next/server';
import { prisma as defaultPrisma, connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { requireAuth } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

interface RouteParams {
  params: Promise<{ jobId: string }>;
}

export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  const startTime = Date.now();
  let jobIdForLog = 'unknown';
  
  try {
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();

    // Validate session with token expiration handling
    const authResult = await requireAuth();
    if ('error' in authResult) {
      return authResult.error;
    }
    const { session: validatedSession } = authResult;

    let { jobId } = await params;
    jobIdForLog = jobId || 'unknown';

    if (!jobId) {
      return NextResponse.json(
        { error: 'Job ID required' },
        { status: 400 }
      );
    }

    // Validate jobId is valid UUID format
    if (typeof jobId !== 'string') {
      return NextResponse.json(
        { error: 'Job ID must be a string' },
        { status: 400 }
      );
    }

    jobId = jobId.trim();
    if (jobId.length === 0) {
      return NextResponse.json(
        { error: 'Job ID cannot be empty' },
        { status: 400 }
      );
    }
    const uuidValidation = validateUUID(jobId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: 'Job ID must be a valid UUID format' },
        { status: uuidValidation.error.status }
      );
    }

    console.log('[Analysis Status API] Looking for analysis job:', {
      jobId,
      organizationId: validatedSession.user.organizationId,
    });

    const queryStartTime = Date.now();
    let job = null;
    let queryTime = 0;

    // Strategy: First try to find the job in the default database to get its organizationId
    let jobOrganizationId: string | null = null;
    try {
      const jobInDefault = await defaultPrisma.analysisJob.findUnique({
        where: { id: jobId },
        select: {
          id: true,
          status: true,
          totalContacts: true,
          analyzedContacts: true,
          failedContacts: true,
          errors: true,
          createdAt: true,
          startedAt: true,
          completedAt: true,
          organizationId: true,
        },
      });
      
      if (jobInDefault) {
        queryTime = Date.now() - queryStartTime;
        jobOrganizationId = jobInDefault.organizationId;
        
        // If multi-DB is enabled, get the full job data from the routed database
        if (process.env.ENABLE_MULTI_DB === 'true' && jobOrganizationId) {
          const prismaClient = getPrismaForOrg(jobOrganizationId);
          const fullJob = await prismaClient.analysisJob.findUnique({
            where: { id: jobId },
            select: {
              id: true,
              status: true,
              totalContacts: true,
              analyzedContacts: true,
              failedContacts: true,
              errors: true,
              createdAt: true,
              startedAt: true,
              completedAt: true,
              organizationId: true,
            },
          });
          
          if (fullJob) {
            job = fullJob;
            console.log('[Analysis Status API] Job found in routed database:', {
              jobId,
              organizationId: fullJob.organizationId,
            });
          } else {
            // Job exists in default but not in routed - use default
            job = jobInDefault;
            console.warn('[Analysis Status API] Job found in default database but not in routed, using default:', {
              jobId,
              organizationId: jobInDefault.organizationId,
            });
          }
        } else {
          // Multi-DB not enabled or no organizationId - use default
          job = jobInDefault;
        }
      }
    } catch (defaultDbError) {
      console.error('[Analysis Status API] Error checking default database:', defaultDbError);
    }

    // If not found in default database, try the routed database based on session organizationId
    if (!job) {
      const prismaClient = getPrismaForOrg(validatedSession.user.organizationId);
      try {
        job = await prismaClient.analysisJob.findFirst({
          where: {
            id: jobId,
            organizationId: validatedSession.user.organizationId,
          },
          select: {
            id: true,
            status: true,
            totalContacts: true,
            analyzedContacts: true,
            failedContacts: true,
            errors: true,
            createdAt: true,
            startedAt: true,
            completedAt: true,
            organizationId: true,
          },
        });
        queryTime = Date.now() - queryStartTime;
        
        if (job) {
          jobOrganizationId = job.organizationId;
          console.log('[Analysis Status API] Job found in routed database:', {
            jobId,
            organizationId: job.organizationId,
          });
        }
      } catch (routedDbError) {
        console.error('[Analysis Status API] Error checking routed database:', routedDbError);
      }
    }
    
    // If still not found and we have a jobOrganizationId from default DB, try that organization's database
    if (!job && jobOrganizationId && process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const prismaClient = getPrismaForOrg(jobOrganizationId);
        job = await prismaClient.analysisJob.findUnique({
          where: { id: jobId },
          select: {
            id: true,
            status: true,
            totalContacts: true,
            analyzedContacts: true,
            failedContacts: true,
            errors: true,
            createdAt: true,
            startedAt: true,
            completedAt: true,
            organizationId: true,
          },
        });
        
        if (job) {
          console.log('[Analysis Status API] Job found in job organization database:', {
            jobId,
            organizationId: job.organizationId,
          });
        }
      } catch (orgDbError) {
        console.error('[Analysis Status API] Error checking job organization database:', orgDbError);
      }
    }
    
    // Last resort: If still not found and multi-DB is enabled, search all databases
    if (!job && process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allDatabases = router.getAllDatabaseConfigs();
        
        console.log('[Analysis Status API] Job not found in initial searches, searching all databases:', {
          jobId,
          dbCount: allDatabases.length,
          sessionOrganizationId: validatedSession.user.organizationId,
        });
        
        // Search each database sequentially
        for (const dbConfig of allDatabases) {
          try {
            const foundJob = await dbConfig.client.analysisJob.findUnique({
              where: { id: jobId },
              select: {
                id: true,
                status: true,
                totalContacts: true,
                analyzedContacts: true,
                failedContacts: true,
                errors: true,
                createdAt: true,
                startedAt: true,
                completedAt: true,
                organizationId: true,
              },
            });
            
            if (foundJob) {
              job = foundJob;
              jobOrganizationId = foundJob.organizationId;
              console.log('[Analysis Status API] Job found in database', dbConfig.index, ':', {
                jobId,
                organizationId: foundJob.organizationId,
              });
              break;
            }
          } catch (dbSearchError) {
            console.error(`[Analysis Status API] Error searching database ${dbConfig.index}:`, dbSearchError);
            // Continue to next database
          }
        }
      } catch (allDbError) {
        console.error('[Analysis Status API] Error in all-database search:', allDbError);
      }
    }

    if (queryTime > 1000) {
      console.warn('[Analysis Status API] Slow database query:', {
        jobId,
        queryTime: `${queryTime}ms`,
      });
    }

    if (!job) {
      console.warn('[Analysis Status API] Analysis job not found:', {
        jobId,
        organizationId: validatedSession.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      return NextResponse.json(
        { error: 'Analysis job not found or unauthorized' },
        { status: 404 }
      );
    }

    // Verify the job belongs to the user's organization (or allow cross-org access like contact detail page)
    if (job.organizationId !== validatedSession.user.organizationId) {
      console.warn('[Analysis Status API] Organization mismatch detected, allowing cross-organization access (like contact detail page):', {
        jobId,
        jobOrganizationId: job.organizationId,
        userOrganizationId: validatedSession.user.organizationId,
      });
      
      // Allow cross-organization access (same behavior as contact detail page)
      // The user can view analysis jobs for contacts they have access to, even if in different org
      // This is consistent with how contacts can be accessed across organizations
      console.log('[Analysis Status API] Allowing cross-organization access to job:', {
        jobId,
        jobOrganizationId: job.organizationId,
        userOrganizationId: validatedSession.user.organizationId,
      });
    }
    
    // Cross-organization access is now allowed (same as contact detail page)

    const totalTime = Date.now() - startTime;
    if (totalTime > 500) {
      console.log('[Analysis Status API] Request completed:', {
        jobId,
        status: job.status,
        totalTime: `${totalTime}ms`,
        queryTime: `${queryTime}ms`,
      });
    }

    return NextResponse.json({
      id: job.id,
      status: job.status,
      totalContacts: job.totalContacts,
      analyzedContacts: job.analyzedContacts,
      failedContacts: job.failedContacts,
      errors: job.errors,
      createdAt: job.createdAt,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch analysis status';
    const errorStack = error instanceof Error ? error.stack : undefined;
    const totalTime = Date.now() - startTime;
    
    // Try to get jobId for logging, but don't fail if params access fails
    try {
      const resolvedParams = await params;
      jobIdForLog = resolvedParams.jobId || 'unknown';
    } catch {
      // Ignore error accessing params
    }
    
    console.error('[Analysis Status API] Error fetching analysis status:', {
      error: errorMessage,
      stack: errorStack,
      jobId: jobIdForLog,
      totalTime: `${totalTime}ms`,
      errorName: error instanceof Error ? error.name : 'Unknown',
    });
    
    // Don't expose internal errors to client
    return NextResponse.json(
      { error: 'Failed to fetch analysis status' },
      { status: 500 }
    );
  }
}

