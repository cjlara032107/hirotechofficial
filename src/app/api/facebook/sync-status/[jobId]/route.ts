import { NextRequest, NextResponse } from 'next/server';
import { prisma as defaultPrisma, connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { requireAuth } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

// ============================================
// IN-MEMORY JOB LOCATION CACHE
// ============================================
// Cache job locations (jobId → dbIndex) to avoid scanning all databases
// This is per-instance and survives hot reloads in development
interface JobLocationCache {
  [jobId: string]: {
    dbIndex: number;
    dbHost: string;
    timestamp: number;
  };
}

declare global {
  // eslint-disable-next-line no-var
  var jobLocationCache: JobLocationCache | undefined;
}

if (!globalThis.jobLocationCache) {
  globalThis.jobLocationCache = {};
}

const jobLocationCache = globalThis.jobLocationCache;

// Cache configuration
const JOB_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const JOB_CACHE_MAX_SIZE = 1000; // Prevent memory bloat

/**
 * Get cached job location
 */
function getCachedJobLocation(jobId: string): { dbIndex: number; dbHost: string } | null {
  const cached = jobLocationCache[jobId];
  if (!cached) return null;
  
  const age = Date.now() - cached.timestamp;
  if (age > JOB_CACHE_TTL_MS) {
    // Expired
    delete jobLocationCache[jobId];
    return null;
  }
  
  console.log(`[Sync Status API] [Cache] ✅ Cache HIT for job ${jobId} (age: ${age}ms, dbIndex: ${cached.dbIndex})`);
  return { dbIndex: cached.dbIndex, dbHost: cached.dbHost };
}

/**
 * Store job location in cache
 */
function setCachedJobLocation(jobId: string, dbIndex: number, dbHost: string) {
  // Simple eviction: if cache is full, clear oldest entries
  const keys = Object.keys(jobLocationCache);
  if (keys.length >= JOB_CACHE_MAX_SIZE) {
    const sortedKeys = keys.sort((a, b) => {
      return (jobLocationCache[a]?.timestamp || 0) - (jobLocationCache[b]?.timestamp || 0);
    });
    
    // Remove oldest 20%
    const toRemove = sortedKeys.slice(0, Math.floor(JOB_CACHE_MAX_SIZE * 0.2));
    toRemove.forEach(key => delete jobLocationCache[key]);
    
    console.log(`[Sync Status API] [Cache] Evicted ${toRemove.length} old entries (cache size: ${keys.length})`);
  }
  
  jobLocationCache[jobId] = {
    dbIndex,
    dbHost,
    timestamp: Date.now(),
  };
  
  console.log(`[Sync Status API] [Cache] Stored job ${jobId} → DB ${dbIndex} (${dbHost})`);
}

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ jobId: string }> }
) {
  const requestStartTime = Date.now();
  const timings: { [key: string]: number } = {};
  let jobIdForLog = 'unknown';
  let strategyUsed = 'unknown';
  
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
    console.log('[Sync Status API] - Lookup Strategy: Cache → Metadata → Default → Routed → Parallel Scan');
    console.log('[Sync Status API] - Cache size:', Object.keys(jobLocationCache).length, 'entries');
    console.log('[Sync Status API] ============================================');

    let job = null;
    let queryTime = 0;
    let foundDbIndex = 0;
    let foundDbHost = 'unknown';

    // ============================================
    // STEP -1: CHECK CACHE FIRST (FASTEST)
    // ============================================
    const cachedLocation = getCachedJobLocation(jobId);
    if (cachedLocation && multiDbEnabled) {
      timings['cache_check'] = Date.now() - requestStartTime;
      
      console.log('[Sync Status API] ============================================');
      console.log('[Sync Status API] STEP -1: USING CACHED JOB LOCATION');
      console.log(`[Sync Status API]   - Job ID: ${jobId}`);
      console.log(`[Sync Status API]   - Cached dbIndex: ${cachedLocation.dbIndex}`);
      console.log(`[Sync Status API]   - Cached dbHost: ${cachedLocation.dbHost}`);
      console.log('[Sync Status API] ============================================');
      
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allConfigs = router.getAllDatabaseConfigs();
        const targetConfig = allConfigs.find(cfg => cfg.index === cachedLocation.dbIndex);
        
        if (targetConfig) {
          const cacheQueryStart = Date.now();
          job = await targetConfig.client.syncJob.findUnique({
            where: { id: jobId },
            include: {
              facebookPage: {
                select: {
                  organizationId: true,
                },
              },
            },
          });
          const cacheQueryDuration = Date.now() - cacheQueryStart;
          queryTime = cacheQueryDuration;
          timings['cache_lookup'] = Date.now() - requestStartTime;
          
          if (job) {
            foundDbIndex = cachedLocation.dbIndex;
            foundDbHost = cachedLocation.dbHost;
            strategyUsed = 'cache_hit';
            
            console.log(`[Sync Status API] ✅ Cache lookup succeeded - ${cacheQueryDuration}ms`);
            console.log(`[Sync Status API]   - Strategy: CACHE HIT (fastest path)`);
            console.log(`[Sync Status API]   - DB Index: ${foundDbIndex}`);
          } else {
            console.warn(`[Sync Status API] ⚠️  Cache pointed to DB ${cachedLocation.dbIndex} but job not found (may be deleted)`);
            delete jobLocationCache[jobId]; // Invalidate cache
          }
        }
      } catch (cacheError) {
        console.error('[Sync Status API] Cache lookup error:', cacheError);
        delete jobLocationCache[jobId]; // Invalidate cache on error
      }
    }

    // ============================================
    // STEP 0: CHECK METADATA ROUTING (FAST)
    // ============================================
    let jobDbIndexFromMetadata: number | null = null;
    
    if (!job) {
      timings['metadata_check_start'] = Date.now() - requestStartTime;
      
      try {
        // Quick check in default DB for metadata only
        const jobMetadata = await defaultPrisma.syncJob.findUnique({
          where: { id: jobId },
          select: { 
            // @ts-expect-error - dbIndex field added in schema but types not yet regenerated
            dbIndex: true, 
            facebookPage: { select: { organizationId: true } } 
          },
        });
        
        // @ts-expect-error - dbIndex field added in schema but types not yet regenerated
        if (jobMetadata?.dbIndex !== null && jobMetadata?.dbIndex !== undefined && multiDbEnabled) {
          // @ts-expect-error - dbIndex field added in schema but types not yet regenerated
          jobDbIndexFromMetadata = jobMetadata.dbIndex as number;
          
          console.log('[Sync Status API] ============================================');
          console.log('[Sync Status API] STEP 0: USING JOB ROUTING METADATA');
          console.log(`[Sync Status API]   - Job ID: ${jobId}`);
          console.log(`[Sync Status API]   - Metadata dbIndex: ${jobDbIndexFromMetadata}`);
          console.log('[Sync Status API] ============================================');
          
          // Direct lookup in the metadata-specified database
          const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
          const router = getDatabaseRouter();
          const allConfigs = router.getAllDatabaseConfigs();
          const targetConfig = allConfigs.find(cfg => cfg.index === jobDbIndexFromMetadata);
          
          if (targetConfig) {
            // Extract host for logging
            try {
              const urlMatch = targetConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
              foundDbHost = urlMatch ? urlMatch[1] : 'unknown';
            } catch {}
            
            const metadataLookupStart = Date.now();
            job = await targetConfig.client.syncJob.findUnique({
              where: { id: jobId },
              include: {
                facebookPage: {
                  select: {
                    organizationId: true,
                  },
                },
              },
            });
            const metadataLookupDuration = Date.now() - metadataLookupStart;
            queryTime = metadataLookupDuration;
            timings['metadata_lookup'] = Date.now() - requestStartTime;
            
            if (job) {
              foundDbIndex = jobDbIndexFromMetadata as number;
              strategyUsed = 'metadata_routing';
              
              console.log(`[Sync Status API] ✅ Job found using metadata routing - ${metadataLookupDuration}ms`);
              console.log(`[Sync Status API]   - Strategy: METADATA ROUTING (direct lookup)`);
              console.log(`[Sync Status API]   - DB Index: ${foundDbIndex}`);
              console.log(`[Sync Status API]   - DB Host: ${foundDbHost}`);
              
              // Store in cache for future requests
              setCachedJobLocation(jobId, foundDbIndex, foundDbHost);
            } else {
              console.warn(`[Sync Status API] ⚠️  Metadata pointed to DB ${jobDbIndexFromMetadata} but job not found there`);
            }
          }
        }
      } catch (metadataError) {
        console.error('[Sync Status API] Error checking job metadata:', metadataError);
        // Continue with normal lookup flow
      }
    }

    // Strategy: Try to find the job in the default database to get its organizationId
    // This works because job IDs are unique and we need to know which database it's in
    let jobOrganizationId: string | null = null;
    
    if (!job) {
      timings['default_db_start'] = Date.now() - requestStartTime;
      console.log('[Sync Status API] ============================================');
      console.log('[Sync Status API] STEP 1: CHECKING DEFAULT DATABASE (DB 0)');
      console.log('[Sync Status API] ============================================');
    }
    
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
        const queryStartTime = timings['default_db_start'] || requestStartTime;
        queryTime = Date.now() - queryStartTime;
        jobOrganizationId = jobInDefault.facebookPage?.organizationId || null;
        timings['default_db_lookup'] = Date.now() - requestStartTime;
        foundDbIndex = 0;
        foundDbHost = 'default';
        strategyUsed = 'default_db';
        
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
            foundDbIndex = routedDbIndex;
            foundDbHost = routedDbHost;
            strategyUsed = 'job_org_routed';
            console.log('[Sync Status API] ✅ Job verified in routed DB', routedDbIndex);
            
            // Store in cache
            setCachedJobLocation(jobId, foundDbIndex, foundDbHost);
          } else {
            // Job exists in default but not in routed - use default
            job = jobInDefault;
            foundDbIndex = 0;
            foundDbHost = 'default';
            strategyUsed = 'default_db';
            console.warn('[Sync Status API] ⚠️  Job in default DB but NOT in routed DB', routedDbIndex);
            console.warn('[Sync Status API] Using job from default DB');
            
            // Store in cache
            setCachedJobLocation(jobId, 0, 'default');
          }
        } else {
          // Multi-DB not enabled or no organizationId - use default
          job = jobInDefault;
          foundDbIndex = 0;
          foundDbHost = 'default';
          strategyUsed = 'default_db';
          console.log('[Sync Status API] Using job from default DB (multi-DB not enabled)');
          
          // Store in cache if multi-DB is enabled
          if (multiDbEnabled) {
            setCachedJobLocation(jobId, 0, 'default');
          }
        }
      } else {
        console.log('[Sync Status API] ⚠️  Job NOT found in default DB');
      }
    } catch (defaultDbError) {
      console.error('[Sync Status API] ❌ Error checking default database:', defaultDbError);
    }

    // If not found in default database, try the routed database based on session organizationId
    if (!job) {
      timings['session_routed_start'] = Date.now() - requestStartTime;
      
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
        const sessionRoutedStart = Date.now();
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
        queryTime = Date.now() - sessionRoutedStart;
        timings['session_routed_lookup'] = Date.now() - requestStartTime;
        
        if (job) {
          jobOrganizationId = job.facebookPage?.organizationId || null;
          foundDbIndex = routedDbIndex;
          foundDbHost = routedDbHost;
          strategyUsed = 'session_routed';
          
          console.log('[Sync Status API] ✅ Job found in session org routed DB', routedDbIndex);
          
          // Store in cache
          setCachedJobLocation(jobId, foundDbIndex, foundDbHost);
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
    
    // Last resort: If still not found and multi-DB is enabled, search all databases IN PARALLEL
    // This handles cases where the job is in a routed database but not in default or session's database
    if (!job && process.env.ENABLE_MULTI_DB === 'true') {
      timings['parallel_scan_start'] = Date.now() - requestStartTime;
      
      console.log('[Sync Status API] ============================================');
      console.log('[Sync Status API] STEP 3: SEARCHING ALL DATABASES (PARALLEL)');
      console.log('[Sync Status API] ============================================');
      
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allDatabases = router.getAllDatabaseConfigs();
        
        console.log('[Sync Status API] Scanning all databases in parallel:', {
          jobId,
          totalDatabases: allDatabases.length,
          sessionOrgId: validatedSession.user.organizationId,
        });
        
        const searchStartTime = Date.now();
        
        // Search all databases IN PARALLEL using Promise.all
        const results = await Promise.all(
          allDatabases.map(async (dbConfig) => {
            const dbSearchStart = Date.now();
            try {
              // Extract host for logging
              let dbHost = 'unknown';
              try {
                const urlMatch = dbConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
                dbHost = urlMatch ? urlMatch[1] : 'unknown';
              } catch {}
              
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
              
              const dbSearchDuration = Date.now() - dbSearchStart;
              
              if (foundJob) {
                console.log(`[Sync Status API] [DB Search] ✅ Found in DB ${dbConfig.index} (${dbHost}) - ${dbSearchDuration}ms`);
              } else {
                console.log(`[Sync Status API] [DB Search]   ⚠️  Not in DB ${dbConfig.index} (${dbHost}) - ${dbSearchDuration}ms`);
              }
              
              return { dbIndex: dbConfig.index, job: foundJob, host: dbHost, duration: dbSearchDuration, error: null };
            } catch (error) {
              const dbSearchDuration = Date.now() - dbSearchStart;
              console.error(`[Sync Status API] [DB Search]   ❌ Error in DB ${dbConfig.index} - ${dbSearchDuration}ms:`, error);
              return { dbIndex: dbConfig.index, job: null, host: 'error', duration: dbSearchDuration, error };
            }
          })
        );
        
        const searchTotalDuration = Date.now() - searchStartTime;
        timings['parallel_scan_complete'] = Date.now() - requestStartTime;
        queryTime = searchTotalDuration;
        
        // Find the first hit
        const hit = results.find(r => r.job);
        
        if (hit) {
          job = hit.job;
          jobOrganizationId = hit.job?.facebookPage?.organizationId || null;
          foundDbIndex = hit.dbIndex;
          foundDbHost = hit.host;
          strategyUsed = 'parallel_scan';
          
          const totalSequentialTime = results.reduce((sum, r) => sum + r.duration, 0);
          
          console.log('[Sync Status API] ============================================');
          console.log('[Sync Status API] ✅ JOB FOUND IN PARALLEL SEARCH');
          console.log(`[Sync Status API]   - Job ID: ${jobId}`);
          console.log(`[Sync Status API]   - Job Org ID: ${jobOrganizationId}`);
          console.log(`[Sync Status API]   - Found in DB: ${hit.dbIndex} (${hit.host})`);
          console.log(`[Sync Status API]   - DB query time: ${hit.duration}ms`);
          console.log(`[Sync Status API]   - Total parallel search time: ${searchTotalDuration}ms`);
          console.log(`[Sync Status API]   - Databases searched: ${allDatabases.length}`);
          console.log(`[Sync Status API]   - Performance gain: ${totalSequentialTime}ms sequential → ${searchTotalDuration}ms parallel (${((totalSequentialTime / searchTotalDuration) * 100).toFixed(0)}% faster)`);
          console.log('[Sync Status API] ============================================');
          
          // Store in cache for future requests
          setCachedJobLocation(jobId, foundDbIndex, foundDbHost);
        } else {
          // Log all search results for debugging
          const successfulSearches = results.filter(r => !r.error).length;
          const failedSearches = results.filter(r => r.error).length;
          const totalSequentialTime = results.reduce((sum, r) => sum + r.duration, 0);
          
          console.log('[Sync Status API] ============================================');
          console.log('[Sync Status API] ⚠️  JOB NOT FOUND IN ANY DATABASE');
          console.log(`[Sync Status API]   - Job ID: ${jobId}`);
          console.log(`[Sync Status API]   - Databases searched: ${allDatabases.length}`);
          console.log(`[Sync Status API]   - Successful searches: ${successfulSearches}`);
          console.log(`[Sync Status API]   - Failed searches: ${failedSearches}`);
          console.log(`[Sync Status API]   - Total parallel search time: ${searchTotalDuration}ms`);
          console.log(`[Sync Status API]   - Performance: ${totalSequentialTime}ms sequential → ${searchTotalDuration}ms parallel`);
          console.log(`[Sync Status API]   - Per-DB results:`);
          results.forEach(r => {
            const status = r.error ? '❌ ERROR' : r.job ? '✅ FOUND' : '⚠️  NOT FOUND';
            console.log(`[Sync Status API]     • DB ${r.dbIndex} (${r.host}): ${status} - ${r.duration}ms`);
          });
          console.log('[Sync Status API] ============================================');
        }
      } catch (allDbError) {
        console.error('[Sync Status API] ❌ Error in all-database parallel search:', allDbError);
      }
    }

    if (queryTime > 1000) {
      console.warn('[Sync Status API] Slow database query:', {
        jobId,
        queryTime: `${queryTime}ms`,
      });
    }

    if (!job) {
      const totalDuration = Date.now() - requestStartTime;
      timings['not_found_total'] = totalDuration;
      
      console.error('[Sync Status API] ============================================');
      console.error('[Sync Status API] ❌ JOB NOT FOUND AFTER ALL LOOKUPS');
      console.error('[Sync Status API] - Job ID:', jobId);
      console.error('[Sync Status API] - Session Org ID:', validatedSession.user.organizationId);
      console.error('[Sync Status API] - Multi-DB Enabled:', multiDbEnabled);
      console.error('[Sync Status API] - Routing Strategy:', routingStrategy);
      console.error('[Sync Status API] - Total search time:', `${totalDuration}ms`);
      console.error('[Sync Status API] - Lookups performed:');
      if (timings['cache_check']) {
        console.error('[Sync Status API]   -1. Cache check (no hit)');
      }
      if (timings['metadata_check_start']) {
        console.error('[Sync Status API]   0. Metadata check (no metadata or not found)');
      }
      console.error('[Sync Status API]   1. Default DB (DB 0)');
      console.error('[Sync Status API]   2. Session org routed DB');
      if (jobOrganizationId) {
        console.error('[Sync Status API]   3. Job org routed DB');
      }
      if (multiDbEnabled && timings['parallel_scan_start']) {
        console.error('[Sync Status API]   4. All databases scanned in parallel');
      }
      console.error('[Sync Status API] - Result: Job does not exist in any database');
      console.error('[Sync Status API] - Timing breakdown:');
      Object.entries(timings).forEach(([step, duration]) => {
        console.error(`[Sync Status API]     • ${step}: ${duration}ms`);
      });
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

    const totalDuration = Date.now() - requestStartTime;
    timings['total'] = totalDuration;
    
    // Log comprehensive timing information
    console.log('[Sync Status API] ============================================');
    console.log('[Sync Status API] REQUEST COMPLETE');
    console.log(`[Sync Status API]   - Job ID: ${jobId}`);
    console.log(`[Sync Status API]   - Job Status: ${job.status}`);
    console.log(`[Sync Status API]   - Total time: ${totalDuration}ms`);
    console.log(`[Sync Status API]   - Strategy used: ${strategyUsed}`);
    console.log(`[Sync Status API]   - Found in DB: ${foundDbIndex} (${foundDbHost})`);
    console.log(`[Sync Status API]   - Query time: ${queryTime}ms`);
    console.log(`[Sync Status API]   - Timing breakdown:`);
    
    // Calculate relative timings
    const timingKeys = Object.keys(timings).filter(k => k !== 'total').sort((a, b) => timings[a] - timings[b]);
    let lastTime = 0;
    timingKeys.forEach(step => {
      const absoluteTime = timings[step];
      const relativeTime = absoluteTime - lastTime;
      console.log(`[Sync Status API]     • ${step}: +${relativeTime}ms (${absoluteTime}ms total)`);
      lastTime = absoluteTime;
    });
    
    console.log('[Sync Status API] ============================================');
    
    // Warn if slow (only log if > 500ms for normal requests or > 1000ms for any request)
    if (totalDuration > 1000) {
      console.warn(`[Sync Status API] ⚠️  SLOW REQUEST: ${totalDuration}ms`);
      console.warn(`[Sync Status API]   - Strategy: ${strategyUsed}`);
      console.warn(`[Sync Status API]   - Consider investigating if this is consistent`);
    } else if (totalDuration > 500 && strategyUsed === 'parallel_scan') {
      console.log(`[Sync Status API] ℹ️  Parallel scan took ${totalDuration}ms (acceptable for full DB scan)`);
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
    const totalTime = Date.now() - requestStartTime;
    
    // Try to get jobId for logging, but don't fail if params access fails
    try {
      const params = await props.params;
      jobIdForLog = params.jobId || 'unknown';
    } catch {
      // Ignore error accessing params
    }
    
    console.error('[Sync Status API] ============================================');
    console.error('[Sync Status API] ❌ ERROR FETCHING SYNC STATUS');
    console.error('[Sync Status API]   - Job ID:', jobIdForLog);
    console.error('[Sync Status API]   - Error:', errorMessage);
    console.error('[Sync Status API]   - Error Type:', error instanceof Error ? error.name : 'Unknown');
    console.error('[Sync Status API]   - Total Time:', `${totalTime}ms`);
    console.error('[Sync Status API]   - Stack:', errorStack);
    console.error('[Sync Status API] ============================================');
    
    // Don't expose internal errors to client
    return NextResponse.json(
      { error: 'Failed to fetch sync status' },
      { status: 500 }
    );
  }
}

