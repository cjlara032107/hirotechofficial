import { prisma, connectPrisma } from '@/lib/db';
import { analyzeSelectedContacts } from './analyze-selected-contacts';
import { AnalysisJobStatus } from '@prisma/client';

interface BackgroundAnalysisResult {
  success: boolean;
  jobId: string;
  message: string;
  cancelledJobs?: string[]; // IDs of jobs that were cancelled due to overlap
}

/**
 * Starts a background analysis job that tracks progress in the database
 * This allows analysis to continue even if the user navigates away
 */
export async function startBackgroundAnalysis(
  contactIds: string[],
  organizationId: string,
  userId: string
): Promise<BackgroundAnalysisResult> {
  try {
    // CRITICAL: Log exactly what we received
    console.log(`[Background Analysis] 🔍 DEBUG: startBackgroundAnalysis called`);
    console.log(`[Background Analysis] Received ${contactIds.length} contact ID(s):`, contactIds);
    console.log(`[Background Analysis] Organization ID: ${organizationId}`);
    console.log(`[Background Analysis] User ID: ${userId}`);
    
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();
    
    // CRITICAL: Sort contactIds for consistent comparison
    const contactIdsSorted = [...contactIds].sort();
    
    // STEP 1: Find jobs with overlapping contacts (for cancellation)
    // We'll cancel PENDING jobs with overlapping contacts to prevent conflicts
    const overlappingJobs = await prisma.analysisJob.findMany({
      where: {
        organizationId,
        userId,
        status: {
          in: ['PENDING', 'IN_PROGRESS'],
        },
        contactIds: {
          hasSome: contactIds,
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
    
    // STEP 2: Check for exact match first (reuse if exact match)
    let exactMatchJob = null;
    let cancelledJobs: string[] = [];
    
    for (const job of overlappingJobs) {
      const jobIdsSorted = [...job.contactIds].sort();
      const isExactMatch = 
        job.contactIds.length === contactIds.length &&
        jobIdsSorted.every((id, idx) => id === contactIdsSorted[idx]);
      
      if (isExactMatch) {
        exactMatchJob = job;
        console.log(`[Background Analysis] ✅ Found existing job with exact contact match: ${job.id}`);
        console.log(`[Background Analysis] Reusing job with ${job.totalContacts} contact(s)`);
        break; // Found exact match, no need to check others
      }
    }
    
     // STEP 3: If exact match found, check status and handle accordingly
     if (exactMatchJob) {
       // Cancel other overlapping jobs (but not the exact match)
       const jobsToCancel = overlappingJobs.filter(j => j.id !== exactMatchJob!.id);
       if (jobsToCancel.length > 0) {
         const cancelled = await prisma.analysisJob.updateMany({
           where: {
             id: { in: jobsToCancel.map(j => j.id) },
             status: { in: ['PENDING', 'IN_PROGRESS'] },
           },
           data: {
             status: 'CANCELLED',
             completedAt: new Date(),
           },
         });
         cancelledJobs = jobsToCancel.map(j => j.id);
         console.log(`[Background Analysis] 🗑️ Cancelled ${cancelled.count} overlapping job(s) to prevent conflicts`);
       }
       
       // If job is COMPLETED, just return it
       if (exactMatchJob.status === 'COMPLETED') {
         console.log(`[Background Analysis] ✅ Found existing COMPLETED job - returning existing job ID`);
         return {
           success: true,
           jobId: exactMatchJob.id,
           message: 'Analysis already completed',
           cancelledJobs: cancelledJobs.length > 0 ? cancelledJobs : undefined,
         };
       }
       
       // If job is IN_PROGRESS, check if it's stuck
       if (exactMatchJob.status === 'IN_PROGRESS') {
         const now = new Date();
         const startedAt = exactMatchJob.startedAt || exactMatchJob.createdAt;
         const timeSinceStart = now.getTime() - startedAt.getTime();
         const STUCK_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes
         
         // Check if job is stuck (started >5 minutes ago with no progress)
         const isStuck = timeSinceStart > STUCK_THRESHOLD_MS && 
                         exactMatchJob.analyzedContacts === 0 && 
                         exactMatchJob.failedContacts === 0;
         
         if (!isStuck) {
           // Job appears to be running - return it
           console.log(`[Background Analysis] ✅ Found existing IN_PROGRESS job that appears to be running`);
           console.log(`[Background Analysis] Job ID: ${exactMatchJob.id}`);
           console.log(`[Background Analysis] Progress: ${exactMatchJob.analyzedContacts}/${exactMatchJob.totalContacts} analyzed`);
           return {
             success: true,
             jobId: exactMatchJob.id,
             message: 'Analysis already in progress',
             cancelledJobs: cancelledJobs.length > 0 ? cancelledJobs : undefined,
           };
         } else {
           // Job is stuck - restart it
           console.log(`[Background Analysis] ⚠️ Found existing IN_PROGRESS job that appears STUCK`);
           console.log(`[Background Analysis] Job ID: ${exactMatchJob.id}`);
           console.log(`[Background Analysis] Started: ${startedAt.toISOString()}, Time since start: ${Math.round(timeSinceStart / 1000)}s`);
           console.log(`[Background Analysis] 🔄 Restarting stuck job...`);
         }
       }
       
       // Job is PENDING, FAILED, or STUCK - restart it!
       console.log(`[Background Analysis] ⚠️ Found existing ${exactMatchJob.status} job - restarting execution`);
       console.log(`[Background Analysis] Job ID: ${exactMatchJob.id}`);
       
       // Update job status to IN_PROGRESS and restart execution
       await prisma.analysisJob.update({
         where: { id: exactMatchJob.id },
         data: { 
           status: 'IN_PROGRESS', 
           startedAt: new Date(),
           analyzedContacts: 0,
           failedContacts: 0,
           errors: undefined,
         },
       });
       
       // Start background execution for the existing job
       const restartPromise = (async () => {
         try {
           console.log(`[Background Analysis ${exactMatchJob.id}] 📍 Restarting background execution`);
           await connectPrisma();
           console.log(`[Background Analysis ${exactMatchJob.id}] ✅ Database connection established`);
           
           // Verify job is still active
           const jobCheck = await prisma.analysisJob.findUnique({
             where: { id: exactMatchJob.id },
             select: { status: true },
           });
           
           if (jobCheck?.status === 'CANCELLED') {
             console.log(`[Background Analysis ${exactMatchJob.id}] ⚠️ Job was cancelled, aborting`);
             return;
           }
           
           await executeBackgroundAnalysis(exactMatchJob.id, contactIds, organizationId);
           console.log(`[Background Analysis ${exactMatchJob.id}] ✅ Background execution completed`);
         } catch (error) {
           console.error(`[Background Analysis ${exactMatchJob.id}] ❌ CRITICAL ERROR:`, error);
           try {
             await connectPrisma();
             await prisma.analysisJob.update({
               where: { id: exactMatchJob.id },
               data: {
                 status: 'FAILED',
                 errors: [
                   {
                     error: error instanceof Error ? error.message : String(error),
                     stack: error instanceof Error ? error.stack : undefined,
                     timestamp: new Date().toISOString(),
                   },
                 ],
                 completedAt: new Date(),
               },
             });
           } catch (dbError) {
             console.error(`[Background Analysis ${exactMatchJob.id}] ❌ Failed to update job status:`, dbError);
           }
         }
       })();
       
       // Keep promise alive
       if (typeof globalThis !== 'undefined') {
         (globalThis as any).__backgroundAnalysisPromises = (globalThis as any).__backgroundAnalysisPromises || new Set();
         (globalThis as any).__backgroundAnalysisPromises.add(restartPromise);
         restartPromise.finally(() => {
           (globalThis as any).__backgroundAnalysisPromises?.delete(restartPromise);
         });
       }
       
       // Wait a tick to ensure promise starts
       await new Promise<void>((resolve) => {
         if (typeof process !== 'undefined' && process.nextTick) {
           process.nextTick(() => resolve());
         } else if (typeof setImmediate !== 'undefined') {
           setImmediate(() => resolve());
         } else {
           setTimeout(() => resolve(), 0);
         }
       });
       
       return {
         success: true,
         jobId: exactMatchJob.id,
         message: 'Analysis restarted',
         cancelledJobs: cancelledJobs.length > 0 ? cancelledJobs : undefined,
       };
     }
    
    // STEP 4: No exact match - cancel all overlapping PENDING jobs before creating new one
    if (overlappingJobs.length > 0) {
      const jobsToCancel = overlappingJobs.filter(j => j.status === 'PENDING');
      if (jobsToCancel.length > 0) {
        const cancelled = await prisma.analysisJob.updateMany({
          where: {
            id: { in: jobsToCancel.map(j => j.id) },
            status: 'PENDING',
          },
          data: {
            status: 'CANCELLED',
            completedAt: new Date(),
          },
        });
        cancelledJobs = jobsToCancel.map(j => j.id);
        console.log(`[Background Analysis] 🗑️ Cancelled ${cancelled.count} PENDING job(s) with overlapping contacts`);
        console.log(`[Background Analysis]   Cancelled job IDs:`, cancelledJobs);
        console.log(`[Background Analysis]   Reason: Creating new job with different contact set`);
      }
      
      // Note: We don't cancel IN_PROGRESS jobs as they're actively running
      const inProgressJobs = overlappingJobs.filter(j => j.status === 'IN_PROGRESS');
      if (inProgressJobs.length > 0) {
        console.log(`[Background Analysis] ⚠️ Found ${inProgressJobs.length} IN_PROGRESS job(s) with overlapping contacts`);
        console.log(`[Background Analysis]   These jobs will continue running (not cancelled)`);
        console.log(`[Background Analysis]   New job will be created in parallel`);
      }
    }

    // CRITICAL VALIDATION: Log exactly what we're creating the job with
    console.log(`[Background Analysis] Creating job with ${contactIds.length} contact(s)`);
    console.log(`[Background Analysis] Contact IDs:`, contactIds);
    
    // Create a new analysis job
    const analysisJob = await prisma.analysisJob.create({
      data: {
        organizationId,
        userId,
        contactIds,
        status: 'PENDING',
        totalContacts: contactIds.length,
        analyzedContacts: 0,
        failedContacts: 0,
      },
    });
    
    console.log(`[Background Analysis] ✅ Job created: ${analysisJob.id} with ${analysisJob.totalContacts} contact(s)`);

    // CRITICAL: Update status to IN_PROGRESS immediately to confirm execution will start
    // This ensures the UI shows progress even if the background promise is delayed
    await prisma.analysisJob.update({
      where: { id: analysisJob.id },
      data: { status: 'IN_PROGRESS', startedAt: new Date() },
    });
    console.log(`[Background Analysis] ✅ Job status updated to IN_PROGRESS - execution will start immediately`);

    // CRITICAL: Start execution immediately and ensure it actually runs
    // For Vercel serverless, we must ensure the promise is actively executing before returning
    console.log(`[Background Analysis ${analysisJob.id}] 🚀 Starting background execution immediately...`);
    console.log(`[Background Analysis ${analysisJob.id}] Contact IDs to process:`, contactIds);
    console.log(`[Background Analysis ${analysisJob.id}] Total contacts: ${contactIds.length}`);
    
    // CRITICAL: Start the background promise and ensure it begins executing
    // For Vercel serverless, we must ensure the promise is actively executing before returning
    // The IIFE pattern ensures the promise starts immediately
    const backgroundPromise = (async () => {
      try {
        // CRITICAL: Log immediately to confirm promise is executing
        console.log(`[Background Analysis ${analysisJob.id}] 📍 Inside background promise - starting execution`);
        
        // CRITICAL: Start the first async operation immediately
        // This ensures the promise is actively executing, not just created
        await connectPrisma();
        console.log(`[Background Analysis ${analysisJob.id}] ✅ Database connection established`);
        
        // Now call the actual analysis function
        await executeBackgroundAnalysis(analysisJob.id, contactIds, organizationId);
        console.log(`[Background Analysis ${analysisJob.id}] ✅ Background execution completed`);
      } catch (error) {
        console.error(`[Background Analysis ${analysisJob.id}] ❌ CRITICAL ERROR:`, error);
        console.error(`[Background Analysis ${analysisJob.id}] Error stack:`, error instanceof Error ? error.stack : 'No stack trace');
        
        // Mark job as failed in database
        try {
          await connectPrisma(); // Ensure connection before update
          await prisma.analysisJob.update({
            where: { id: analysisJob.id },
            data: {
              status: 'FAILED',
              errors: [
                {
                  error: error instanceof Error ? error.message : String(error),
                  stack: error instanceof Error ? error.stack : undefined,
                  timestamp: new Date().toISOString(),
                },
              ],
              completedAt: new Date(),
            },
          });
          console.log(`[Background Analysis ${analysisJob.id}] ✅ Job marked as FAILED in database`);
        } catch (dbError) {
          console.error(`[Background Analysis ${analysisJob.id}] ❌ CRITICAL: Failed to update job status:`, dbError);
        }
      }
    })(); // Immediately invoked async function - starts executing NOW
    
    // CRITICAL: In Vercel, we need to keep the promise alive
    // Store it globally to prevent garbage collection
    if (typeof globalThis !== 'undefined') {
      (globalThis as any).__backgroundAnalysisPromises = (globalThis as any).__backgroundAnalysisPromises || new Set();
      (globalThis as any).__backgroundAnalysisPromises.add(backgroundPromise);
      backgroundPromise.finally(() => {
        (globalThis as any).__backgroundAnalysisPromises?.delete(backgroundPromise);
      });
    }

    // CRITICAL: Ensure promise starts executing by waiting for the first microtask
    // This guarantees the promise chain begins before we return the response
    // The IIFE above already started the promise, but we wait a tick to ensure it's executing
    await new Promise<void>((resolve) => {
      // Use process.nextTick if available (Node.js), otherwise setImmediate/setTimeout
      // This ensures the promise chain has started executing before we return
      if (typeof process !== 'undefined' && process.nextTick) {
        process.nextTick(() => {
          console.log(`[Background Analysis ${analysisJob.id}] ✅ Promise chain confirmed active (nextTick)`);
          resolve();
        });
      } else if (typeof setImmediate !== 'undefined') {
        setImmediate(() => {
          console.log(`[Background Analysis ${analysisJob.id}] ✅ Promise chain confirmed active (setImmediate)`);
          resolve();
        });
      } else {
        setTimeout(() => {
          console.log(`[Background Analysis ${analysisJob.id}] ✅ Promise chain confirmed active (setTimeout)`);
          resolve();
        }, 0);
      }
    });
    
    console.log(`[Background Analysis] ✅ Background promise execution started - returning response`);

    return {
      success: true,
      jobId: analysisJob.id,
      message: cancelledJobs.length > 0 
        ? `Analysis started. ${cancelledJobs.length} previous job(s) were cancelled.`
        : 'Analysis started',
      cancelledJobs: cancelledJobs.length > 0 ? cancelledJobs : undefined,
    };
  } catch (error) {
    console.error('Failed to start background analysis:', error);
    throw error;
  }
}

/**
 * Executes the actual analysis operation and updates job status
 */
async function executeBackgroundAnalysis(
  jobId: string,
  contactIds: string[],
  organizationId: string
): Promise<void> {
  try {
    // CRITICAL: Log exactly what we're processing
    console.log(`[Background Analysis ${jobId}] 🔍 DEBUG: executeBackgroundAnalysis called`);
    console.log(`[Background Analysis ${jobId}] Processing ${contactIds.length} contact ID(s):`, contactIds);
    
    // CRITICAL VALIDATION: If only 1 contact ID was provided, ensure we only process 1
    if (contactIds.length === 1) {
      console.log(`[Background Analysis ${jobId}] ✅ SINGLE CONTACT MODE: Processing exactly 1 contact`);
      console.log(`[Background Analysis ${jobId}] Contact ID: ${contactIds[0]}`);
    } else if (contactIds.length > 1) {
      console.log(`[Background Analysis ${jobId}] ⚠️ MULTIPLE CONTACTS: Processing ${contactIds.length} contacts`);
      console.log(`[Background Analysis ${jobId}] Contact IDs:`, contactIds);
    }
    
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();
    
    // Status already updated to IN_PROGRESS in startBackgroundAnalysis
    // Just verify it's still active and log confirmation
    const jobStatus = await prisma.analysisJob.findUnique({
      where: { id: jobId },
      select: { status: true, startedAt: true },
    });
    if (jobStatus?.status === 'CANCELLED') {
      console.log(`[Background Analysis ${jobId}] Job was cancelled, aborting execution`);
      return;
    }
    console.log(`[Background Analysis ${jobId}] ✅ Job status verified: ${jobStatus?.status}, started at: ${jobStatus?.startedAt?.toISOString()}`);

    console.log(`[Background Analysis ${jobId}] ✅ Starting analysis for ${contactIds.length} contacts at ${new Date().toISOString()}`);

    // For small jobs (≤20 contacts), process individually for better progress visibility
    // For larger jobs, use batches for efficiency
    const SMALL_JOB_THRESHOLD = 20;
    const useIndividualProcessing = contactIds.length <= SMALL_JOB_THRESHOLD;
    
    let analyzedCount = 0;
    let failedCount = 0;
    const errors: Array<{ contactId: string; error: string }> = [];

    // Helper function to update progress (non-blocking)
    const updateProgress = async (force = false) => {
      // Always update for small jobs, or every 5 contacts for large jobs, or when count is 0 (initial state)
      const shouldUpdate = force || useIndividualProcessing || analyzedCount === 0 || (analyzedCount + failedCount) % 5 === 0;
      
      if (shouldUpdate) {
        // Fire-and-forget progress update (don't block processing)
        prisma.analysisJob.update({
          where: { id: jobId },
          data: {
            analyzedContacts: analyzedCount,
            failedContacts: failedCount,
            errors: errors.length > 0 ? errors : undefined,
          },
        }).catch((error) => {
          console.error(`[Background Analysis ${jobId}] Failed to update progress:`, error);
        });
        
        // CRITICAL: Log progress to help debug stuck jobs
        console.log(
          `[Background Analysis ${jobId}] 📊 Progress: ${analyzedCount}/${contactIds.length} analyzed, ${failedCount} failed`
        );
      }
    };
    
    // CRITICAL: Initial progress update to confirm execution started
    await updateProgress(true);
    console.log(`[Background Analysis ${jobId}] ✅ Initial progress update sent - analysis is running`);

    if (useIndividualProcessing) {
      // Process all contacts in a single batch for maximum efficiency!
      // This is much faster than calling analyzeSelectedContacts 15 times separately
      console.log(`[Background Analysis ${jobId}] Processing ${contactIds.length} contacts in a single optimized batch`);
      
      // Check if job was cancelled before starting
      const job = await prisma.analysisJob.findUnique({
        where: { id: jobId },
        select: { status: true },
      });

      if (job?.status === 'CANCELLED') {
        console.log(`[Background Analysis ${jobId}] Job was cancelled`);
        return;
      }

      try {
        console.log(`[Background Analysis ${jobId}] 🔍 About to call analyzeSelectedContacts with ${contactIds.length} contact(s)`);
        console.log(`[Background Analysis ${jobId}] Contact IDs:`, contactIds);
        
        // Process all contacts at once - analyzeSelectedContacts handles parallel processing internally
        // This is MUCH faster than calling it 15 times with 1 contact each
        // Pass progress callback to get real-time updates
        const result = await analyzeSelectedContacts(
          contactIds, 
          organizationId,
          (analyzed, failed, total) => {
            // Update counts and progress in real-time
            analyzedCount = analyzed;
            failedCount = failed;
            console.log(`[Background Analysis ${jobId}] 📊 Progress callback: ${analyzed}/${total} analyzed, ${failed} failed`);
            // Update progress (non-blocking)
            updateProgress(true).catch((err) => {
              console.error(`[Background Analysis ${jobId}] Failed to update progress:`, err);
            });
          }
        );
        
        console.log(`[Background Analysis ${jobId}] ✅ analyzeSelectedContacts completed:`, {
          successCount: result.successCount,
          failedCount: result.failedCount,
          errors: result.errors.length
        });
        
        analyzedCount = result.successCount;
        failedCount = result.failedCount;
        errors.push(...result.errors);
        
        // Final progress update
        await updateProgress(true);
      } catch (error) {
        console.error(`[Background Analysis ${jobId}] Batch processing failed:`, error);
        failedCount = contactIds.length;
        errors.push(
          ...contactIds.map((id) => ({
            contactId: id,
            error: error instanceof Error ? error.message : 'Unknown error',
          }))
        );
        await updateProgress(true);
      }
    } else {
      // Process in batches for larger jobs
      const BATCH_SIZE = 50;
      const batches: string[][] = [];
      for (let i = 0; i < contactIds.length; i += BATCH_SIZE) {
        batches.push(contactIds.slice(i, i + BATCH_SIZE));
      }

      console.log(`[Background Analysis ${jobId}] Processing ${contactIds.length} contacts in ${batches.length} parallel batches`);

      const MAX_CONCURRENT_BATCHES = 5;
      
      for (let i = 0; i < batches.length; i += MAX_CONCURRENT_BATCHES) {
        const concurrentBatches = batches.slice(i, i + MAX_CONCURRENT_BATCHES);
        
        console.log(`[Background Analysis ${jobId}] Processing batch group ${Math.floor(i / MAX_CONCURRENT_BATCHES) + 1}/${Math.ceil(batches.length / MAX_CONCURRENT_BATCHES)} (${concurrentBatches.length} batches)`);
        
        // Check if job was cancelled
        const job = await prisma.analysisJob.findUnique({
          where: { id: jobId },
          select: { status: true },
        });

        if (job?.status === 'CANCELLED') {
          console.log(`[Background Analysis ${jobId}] Job was cancelled`);
          return;
        }

        // Process batches in parallel, but track progress as they complete
        const batchPromises = concurrentBatches.map(async (batch) => {
          try {
            const result = await analyzeSelectedContacts(batch, organizationId);
            
            // Update counts immediately as batch completes
            analyzedCount += result.successCount;
            failedCount += result.failedCount;
            errors.push(...result.errors);
            
            // Update progress after each batch completes
            await updateProgress();
            
            return { status: 'fulfilled' as const, value: result };
          } catch (error) {
            failedCount += batch.length;
            errors.push(
              ...batch.map((id) => ({
                contactId: id,
                error: error instanceof Error ? error.message : 'Unknown error',
              }))
            );
            
            // Update progress even on failure
            await updateProgress();
            
            return { status: 'rejected' as const, reason: error };
          }
        });

        // Wait for all batches in this group to complete
        await Promise.all(batchPromises);
        
        // Final update after batch group
        await updateProgress(true);
      }
    }

    // Mark job as completed
    await prisma.analysisJob.update({
      where: { id: jobId },
      data: {
        status: 'COMPLETED',
        analyzedContacts: analyzedCount,
        failedContacts: failedCount,
        errors: errors.length > 0 ? errors : undefined,
        completedAt: new Date(),
      },
    });

    console.log(
      `[Background Analysis ${jobId}] ✅ Completed: ${analyzedCount} analyzed, ${failedCount} failed`
    );
    
    // CRITICAL: Log detailed results for debugging
    if (analyzedCount > 0) {
      console.log(`[Background Analysis ${jobId}] ✅ Successfully analyzed ${analyzedCount} contact(s)`);
    }
    if (failedCount > 0) {
      console.error(`[Background Analysis ${jobId}] ❌ Failed to analyze ${failedCount} contact(s)`);
      if (errors.length > 0) {
        console.error(`[Background Analysis ${jobId}] Error details:`, errors);
      }
    }
  } catch (error) {
    console.error(`[Background Analysis ${jobId}] Error:`, error);
    
    // Mark job as failed
    await prisma.analysisJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [
          {
            error: error instanceof Error ? error.message : 'Unknown error',
            timestamp: new Date().toISOString(),
          },
        ],
        completedAt: new Date(),
      },
    });
  }
}

/**
 * Get analysis job status
 */
export async function getAnalysisJobStatus(jobId: string) {
  const job = await prisma.analysisJob.findUnique({
    where: { id: jobId },
    select: {
      id: true,
      status: true,
      totalContacts: true,
      analyzedContacts: true,
      failedContacts: true,
      errors: true,
      startedAt: true,
      completedAt: true,
      createdAt: true,
    },
  });

  return job;
}

/**
 * Get latest analysis job for user
 */
export async function getLatestAnalysisJob(organizationId: string, userId: string) {
  return prisma.analysisJob.findFirst({
    where: {
      organizationId,
      userId,
      status: {
        in: ['PENDING', 'IN_PROGRESS'],
      },
    },
    orderBy: {
      createdAt: 'desc',
    },
  });
}

/**
 * Cancel an analysis job
 */
export async function cancelAnalysisJob(jobId: string, userId: string): Promise<boolean> {
  const job = await prisma.analysisJob.findUnique({
    where: { id: jobId },
    select: { userId: true, status: true },
  });

  if (!job) {
    return false;
  }

  if (job.userId !== userId) {
    throw new Error('Unauthorized');
  }

  if (job.status === 'COMPLETED' || job.status === 'FAILED' || job.status === 'CANCELLED') {
    return false;
  }

  await prisma.analysisJob.update({
    where: { id: jobId },
    data: {
      status: 'CANCELLED',
      completedAt: new Date(),
    },
  });

  return true;
}

