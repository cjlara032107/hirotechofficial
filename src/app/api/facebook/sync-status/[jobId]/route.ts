import { NextRequest, NextResponse } from 'next/server';
import { prisma as defaultPrisma, connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { requireAuth } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ jobId: string }> }
) {
  const startTime = Date.now();
  let jobIdForLog = 'unknown';
  
  try {
    // Validate and extract jobId first
    let jobId: string;
    try {
      const params = await props.params;
      jobId = params.jobId;
      jobIdForLog = jobId;
      
      // Validate jobId format
      if (!jobId || typeof jobId !== 'string' || jobId.trim().length === 0) {
        return NextResponse.json(
          { error: 'Invalid job ID' },
          { status: 400 }
        );
      }
      
      // Trim whitespace
      jobId = jobId.trim();
      
      // Validate UUID format
      const uuidValidation = validateUUID(jobId);
      if (uuidValidation?.error) {
        return NextResponse.json(
          { error: uuidValidation.error.message },
          { status: uuidValidation.error.status }
        );
      }
    } catch (paramsError) {
      console.error('[Sync Status API] Error extracting params:', paramsError);
      return NextResponse.json(
        { error: 'Invalid request parameters' },
        { status: 400 }
      );
    }

    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();

    // Validate session with token expiration handling
    const authResult = await requireAuth();
    if ('error' in authResult) {
      return authResult.error;
    }
    const { session: validatedSession } = authResult;

    // ============================================
    // MULTI-DB JOB LOOKUP TRACE
    // ============================================
    const multiDbEnabled = process.env.ENABLE_MULTI_DB === 'true';
    const routingStrategy = process.env.DB_ROUTING_STRATEGY || 'hash';
    
    console.log('[Sync Status API] ============================================');
    console.log('[Sync Status API] JOB LOOKUP START');
    console.log('[Sync Status API] - Job ID:', jobId);
    console.log('[Sync Status API] - Session Org ID:', validatedSession.user.organizationId);
    console.log('[Sync Status API] - Multi-DB Enabled:', multiDbEnabled);
    console.log('[Sync Status API] - Routing Strategy:', routingStrategy);
    console.log('[Sync Status API] - Lookup Strategy: Default DB first, then routed, then all DBs');
    console.log('[Sync Status API] ============================================');

    const queryStartTime = Date.now();
    let job = null;
    let queryTime = 0;

    // Strategy: First try to find the job in the default database to get its organizationId
    // This works because job IDs are unique and we need to know which database it's in
    let jobOrganizationId: string | null = null;
    
    console.log('[Sync Status API] ============================================');
    console.log('[Sync Status API] STEP 1: CHECKING DEFAULT DATABASE (DB 0)');
    console.log('[Sync Status API] ============================================');
    
    try {
      const jobInDefault = await defaultPrisma.syncJob.findUnique({
        where: { id: jobId },
        include: {
          facebookPage: {
            select: {
              organizationId: true,
            },
          },
        },
      });
      
      if (jobInDefault) {
        queryTime = Date.now() - queryStartTime;
        jobOrganizationId = jobInDefault.facebookPage?.organizationId || null;
        
        console.log('[Sync Status API] ✅ Job found in default DB:', {
          jobId,
          jobOrgId: jobOrganizationId,
          queryTime: `${queryTime}ms`,
        });
        
        // If multi-DB is enabled, get the full job data from the routed database
        if (process.env.ENABLE_MULTI_DB === 'true' && jobOrganizationId) {
          const prismaClient = getPrismaForOrg(jobOrganizationId);
          
          // Log which DB we're routing to
          let routedDbIndex = 0;
          let routedDbHost = 'unknown';
          try {
            const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
            const router = getDatabaseRouter();
            const allConfigs = router.getAllDatabaseConfigs();
            const chosenClient = router.getClient(jobOrganizationId);
            const matchedConfig = allConfigs.find(cfg => cfg.client === chosenClient);
            if (matchedConfig) {
              routedDbIndex = matchedConfig.index;
              const urlMatch = matchedConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
              routedDbHost = urlMatch ? urlMatch[1] : 'unknown';
            }
            
            console.log('[Sync Status API] Checking job org routed DB:', {
              jobOrgId: jobOrganizationId,
              routedToDbIndex: routedDbIndex,
              routedToDbHost: routedDbHost,
            });
          } catch (routerError) {
            console.error('[Sync Status API] Error getting router info:', routerError);
          }
          
          const fullJob = await prismaClient.syncJob.findUnique({
            where: { id: jobId },
            include: {
              facebookPage: {
                select: {
                  organizationId: true,
                },
              },
            },
          });
          
          if (fullJob) {
            job = fullJob;
            console.log('[Sync Status API] ✅ Job verified in routed DB', routedDbIndex);
          } else {
            // Job exists in default but not in routed - use default
            job = jobInDefault;
            console.warn('[Sync Status API] ⚠️  Job in default DB but NOT in routed DB', routedDbIndex);
            console.warn('[Sync Status API] Using job from default DB');
          }
        } else {
          // Multi-DB not enabled or no organizationId - use default
          job = jobInDefault;
          console.log('[Sync Status API] Using job from default DB (multi-DB not enabled)');
        }
      } else {
        console.log('[Sync Status API] ⚠️  Job NOT found in default DB');
      }
    } catch (defaultDbError) {
      console.error('[Sync Status API] ❌ Error checking default database:', defaultDbError);
    }

    // If not found in default database, try the routed database based on session organizationId
    if (!job) {
      console.log('[Sync Status API] ============================================');
      console.log('[Sync Status API] STEP 2: CHECKING SESSION ORG ROUTED DB');
      console.log('[Sync Status API] - Session Org ID:', validatedSession.user.organizationId);
      console.log('[Sync Status API] ============================================');
      
      const prismaClient = getPrismaForOrg(validatedSession.user.organizationId);
      
      // Log which DB we're routing to
      let routedDbIndex = 0;
      let routedDbHost = 'unknown';
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allConfigs = router.getAllDatabaseConfigs();
        const chosenClient = router.getClient(validatedSession.user.organizationId);
        const matchedConfig = allConfigs.find(cfg => cfg.client === chosenClient);
        if (matchedConfig) {
          routedDbIndex = matchedConfig.index;
          const urlMatch = matchedConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
          routedDbHost = urlMatch ? urlMatch[1] : 'unknown';
        }
        
        console.log('[Sync Status API] Routed to DB:', {
          dbIndex: routedDbIndex,
          dbHost: routedDbHost,
        });
      } catch (routerError) {
        console.error('[Sync Status API] Error getting router info:', routerError);
      }
      
      try {
        job = await prismaClient.syncJob.findUnique({
          where: { id: jobId },
          include: {
            facebookPage: {
              select: {
                organizationId: true,
              },
            },
          },
        });
        queryTime = Date.now() - queryStartTime;
        
        if (job) {
          jobOrganizationId = job.facebookPage?.organizationId || null;
          console.log('[Sync Status API] ✅ Job found in session org routed DB', routedDbIndex);
        } else {
          console.log('[Sync Status API] ⚠️  Job NOT found in session org routed DB', routedDbIndex);
        }
      } catch (routedDbError) {
        console.error('[Sync Status API] ❌ Error checking routed database', routedDbIndex, ':', routedDbError);
      }
    }
    
    // If still not found and we have a jobOrganizationId from default DB, try that organization's database
    if (!job && jobOrganizationId && process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const prismaClient = getPrismaForOrg(jobOrganizationId);
        job = await prismaClient.syncJob.findUnique({
          where: { id: jobId },
          include: {
            facebookPage: {
              select: {
                organizationId: true,
              },
            },
          },
        });
        
        if (job) {
          console.log('[Sync Status API] Job found in job organization database:', {
            jobId,
            organizationId: job.facebookPage?.organizationId,
          });
        }
      } catch (orgDbError) {
        console.error('[Sync Status API] Error checking job organization database:', orgDbError);
      }
    }
    
    // Last resort: If still not found and multi-DB is enabled, search all databases
    // This handles cases where the job is in a routed database but not in default or session's database
    if (!job && process.env.ENABLE_MULTI_DB === 'true') {
      console.log('[Sync Status API] ============================================');
      console.log('[Sync Status API] STEP 3: SEARCHING ALL DATABASES');
      console.log('[Sync Status API] ============================================');
      
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allDatabases = router.getAllDatabaseConfigs();
        
        console.log('[Sync Status API] Scanning all databases:', {
          jobId,
          totalDatabases: allDatabases.length,
          sessionOrgId: validatedSession.user.organizationId,
        });
        
        // Search each database sequentially using existing clients
        for (const dbConfig of allDatabases) {
          // Extract host from URL (mask credentials)
          let dbHost = 'unknown';
          try {
            const urlMatch = dbConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
            dbHost = urlMatch ? urlMatch[1] : 'unknown';
          } catch {
            // Ignore
          }
          
          console.log('[Sync Status API] - Searching DB', dbConfig.index, `(${dbHost})...`);
          
          try {
            const foundJob = await dbConfig.client.syncJob.findUnique({
              where: { id: jobId },
              include: {
                facebookPage: {
                  select: {
                    organizationId: true,
                  },
                },
              },
            });
            
            if (foundJob) {
              job = foundJob;
              jobOrganizationId = foundJob.facebookPage?.organizationId || null;
              console.log('[Sync Status API] ============================================');
              console.log('[Sync Status API] ✅ JOB FOUND IN DB', dbConfig.index);
              console.log('[Sync Status API] - Job ID:', jobId);
              console.log('[Sync Status API] - Job Org ID:', foundJob.facebookPage?.organizationId);
              console.log('[Sync Status API] - DB Index:', dbConfig.index);
              console.log('[Sync Status API] - DB Host:', dbHost);
              console.log('[Sync Status API] ============================================');
              break;
            } else {
              console.log('[Sync Status API]   ⚠️  Not in DB', dbConfig.index);
            }
          } catch (dbSearchError) {
            console.error('[Sync Status API]   ❌ Error searching DB', dbConfig.index, ':', dbSearchError);
            // Continue to next database
          }
        }
      } catch (allDbError) {
        console.error('[Sync Status API] ❌ Error in all-database search:', allDbError);
      }
    }

    if (queryTime > 1000) {
      console.warn('[Sync Status API] Slow database query:', {
        jobId,
        queryTime: `${queryTime}ms`,
      });
    }

    if (!job) {
      console.error('[Sync Status API] ============================================');
      console.error('[Sync Status API] ❌ JOB NOT FOUND AFTER ALL LOOKUPS');
      console.error('[Sync Status API] - Job ID:', jobId);
      console.error('[Sync Status API] - Session Org ID:', validatedSession.user.organizationId);
      console.error('[Sync Status API] - Multi-DB Enabled:', process.env.ENABLE_MULTI_DB === 'true');
      console.error('[Sync Status API] - Routing Strategy:', routingStrategy);
      console.error('[Sync Status API] - Lookups performed:');
      console.error('[Sync Status API]   1. Default DB (DB 0)');
      console.error('[Sync Status API]   2. Session org routed DB');
      if (jobOrganizationId) {
        console.error('[Sync Status API]   3. Job org routed DB');
      }
      if (process.env.ENABLE_MULTI_DB === 'true') {
        console.error('[Sync Status API]   4. All databases scanned');
      }
      console.error('[Sync Status API] - Result: Job does not exist in any database');
      console.error('[Sync Status API] - Possible causes:');
      console.error('[Sync Status API]   • Job ID is invalid or expired');
      console.error('[Sync Status API]   • Job was deleted');
      console.error('[Sync Status API]   • Database connection issues');
      console.error('[Sync Status API] ============================================');
      
      return NextResponse.json(
        { error: 'Sync job not found' },
        { status: 404 }
      );
    }

    if (!job.facebookPage) {
      console.error('[Sync Status API] Facebook page not found for sync job:', {
        jobId,
        organizationId: validatedSession.user.organizationId,
      });
      return NextResponse.json(
        { error: 'Facebook page not found for this sync job' },
        { status: 404 }
      );
    }

    // Verify the job belongs to a page in the user's organization
    // If there's a mismatch, verify the user actually has access to the job's organization
    if (job.facebookPage.organizationId !== validatedSession.user.organizationId) {
      console.warn('[Sync Status API] Organization mismatch detected, verifying user access:', {
        jobId,
        jobOrganizationId: job.facebookPage.organizationId,
        userOrganizationId: validatedSession.user.organizationId,
      });
      
      // Check if the user belongs to the job's organization
      try {
        const userInJobOrg = await defaultPrisma.user.findFirst({
          where: {
            id: validatedSession.user.id,
            organizationId: job.facebookPage.organizationId,
          },
          select: {
            id: true,
            organizationId: true,
          },
        });
        
        if (!userInJobOrg) {
          console.error('[Sync Status API] User does not belong to job organization:', {
            jobId,
            jobOrganizationId: job.facebookPage.organizationId,
            userOrganizationId: validatedSession.user.organizationId,
            userId: validatedSession.user.id,
          });
          return NextResponse.json(
            { error: 'Unauthorized access to sync job' },
            { status: 403 }
          );
        }
        
        console.log('[Sync Status API] User verified to have access to job organization:', {
          jobId,
          jobOrganizationId: job.facebookPage.organizationId,
          userOrganizationId: validatedSession.user.organizationId,
          note: 'User belongs to job organization, allowing access despite session organizationId mismatch',
        });
      } catch (verifyError) {
        console.error('[Sync Status API] Error verifying user access to job organization:', verifyError);
        // If verification fails, deny access for security
        return NextResponse.json(
          { error: 'Unauthorized access to sync job' },
          { status: 403 }
        );
      }
    }

    const totalTime = Date.now() - startTime;
    if (totalTime > 500) {
      console.log('[Sync Status API] Request completed:', {
        jobId,
        status: job.status,
        totalTime: `${totalTime}ms`,
        queryTime: `${queryTime}ms`,
      });
    }

    return NextResponse.json({
      id: job.id,
      status: job.status,
      syncedContacts: job.syncedContacts,
      failedContacts: job.failedContacts,
      totalContacts: job.totalContacts,
      tokenExpired: job.tokenExpired,
      errors: job.errors,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch sync status';
    const errorStack = error instanceof Error ? error.stack : undefined;
    const totalTime = Date.now() - startTime;
    
    // Try to get jobId for logging, but don't fail if params access fails
    try {
      const params = await props.params;
      jobIdForLog = params.jobId || 'unknown';
    } catch {
      // Ignore error accessing params
    }
    
    console.error('[Sync Status API] Error fetching sync status:', {
      error: errorMessage,
      stack: errorStack,
      jobId: jobIdForLog,
      totalTime: `${totalTime}ms`,
      errorName: error instanceof Error ? error.name : 'Unknown',
    });
    
    // Don't expose internal errors to client
    return NextResponse.json(
      { error: 'Failed to fetch sync status' },
      { status: 500 }
    );
  }
}

