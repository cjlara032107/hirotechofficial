import { prisma, connectPrisma } from '@/lib/db';
import { analyzeSelectedContacts } from './analyze-selected-contacts';
import { AnalysisJobStatus } from '@prisma/client';
import { updateAnalysisJobProgress, normalizeCount } from './progress-update';
import {
  isJobActive,
  markJobFailedDueToTokenExpiration,
} from './job-safety-checks';
import { calculateJobMetrics, getApiMetricsForPeriod } from '@/lib/jobs/job-metrics';

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
    
    // STEP 3: If exact match found, cancel other overlapping jobs and return
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
      
      return {
        success: true,
        jobId: exactMatchJob.id,
        message: 'Analysis already in progress',
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
 * 
 * Handles very long-running jobs (hours) by:
 * - Persisting progress to database periodically
 * - Checking job status for cancellation
 * - Using efficient batching for large contact sets
 * - Updating progress more frequently for very large jobs (1000+ contacts)
 * 
 * Note: On Vercel serverless, jobs are limited by function timeout (60s on Pro plan).
 * For jobs exceeding this limit, consider implementing a queue system (BullMQ/Redis)
 * or a cron job to resume incomplete jobs.
 */
async function executeBackgroundAnalysis(
  jobId: string,
  contactIds: string[],
  organizationId: string
): Promise<void> {
  // Initialize counters outside try block so they're accessible in catch
  let analyzedCount = 0;
  let failedCount = 0;
  const errors: Array<{ contactId: string; error: string }> = [];

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
    
    // Check comprehensive job status
    const statusCheck = await isJobActive(jobId, 'analysis');
    if (!statusCheck.active) {
      console.log(`[Background Analysis ${jobId}] Job ${statusCheck.reason || 'status changed'}, aborting execution`);
      return;
    }
    console.log(`[Background Analysis ${jobId}] ✅ Job status verified: ${statusCheck.status}, job is active`);

    console.log(`[Background Analysis ${jobId}] ✅ Starting analysis for ${contactIds.length} contacts at ${new Date().toISOString()}`);

    // For small jobs (≤20 contacts), process individually for better progress visibility
    // For larger jobs, use batches for efficiency
    // For very large jobs (1000+ contacts), use larger batches and more frequent progress updates
    const SMALL_JOB_THRESHOLD = 20;
    const LARGE_JOB_THRESHOLD = 1000;
    const useIndividualProcessing = contactIds.length <= SMALL_JOB_THRESHOLD;
    const isVeryLargeJob = contactIds.length >= LARGE_JOB_THRESHOLD;
    
    // For very long-running jobs (hours), save progress more frequently
    const progressUpdateInterval = isVeryLargeJob ? 5 : 10; // Update every 5 contacts for very large jobs

    // Helper function to update progress (non-blocking)
    // OPTIMIZATION: Update progress based on job size
    // - Small jobs (≤20): every contact for real-time feedback
    // - Large jobs (21-999): every 25 contacts to reduce DB load
    // - Very large jobs (1000+): every 5 contacts for better progress tracking on long-running jobs
    const updateProgress = async (force = false) => {
      const progressInterval = useIndividualProcessing 
        ? 1 
        : isVeryLargeJob 
          ? progressUpdateInterval 
          : 25;
      const shouldUpdate = force || useIndividualProcessing || analyzedCount === 0 || (analyzedCount + failedCount) % progressInterval === 0;
      
      if (shouldUpdate) {
        // Use safe progress update utility (handles errors gracefully, uses atomic increments)
        await updateAnalysisJobProgress(jobId, {
          analyzedCount: normalizeCount(analyzedCount),
          failedCount: normalizeCount(failedCount),
          errors: errors.length > 0 ? errors : undefined,
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
      
        // Check comprehensive job status before starting
        const statusCheck = await isJobActive(jobId, 'analysis');
        if (!statusCheck.active) {
          console.log(`[Background Analysis ${jobId}] Job ${statusCheck.reason || 'status changed'}, aborting execution`);
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
      // Process in batches for larger jobs - FULLY PARALLEL (no sequential batch groups)
      const BATCH_SIZE = 50;
      const batches: string[][] = [];
      for (let i = 0; i < contactIds.length; i += BATCH_SIZE) {
        batches.push(contactIds.slice(i, i + BATCH_SIZE));
      }

      console.log(`[Background Analysis ${jobId}] Processing ${contactIds.length} contacts in ${batches.length} batches - FULLY PARALLEL`);

      // Get dynamic concurrency limit based on API keys
      const { getCachedConcurrencyLimits } = await import('@/lib/ai/dynamic-concurrency');
      const concurrencyLimits = await getCachedConcurrencyLimits();
      
      // Use batch concurrency limit (scales with API keys)
      const MAX_CONCURRENT_BATCHES = concurrencyLimits.batchConcurrency;
      
      console.log(`[Background Analysis ${jobId}] Using ${MAX_CONCURRENT_BATCHES} concurrent batches (${concurrencyLimits.keyCount} API keys)`);

      // Concurrency limiter for batch processing
      class BatchConcurrencyLimiter {
        private queue: Array<{ fn: () => Promise<unknown>; resolve: (value: unknown) => void; reject: (error: unknown) => void }> = [];
        private running = 0;
        constructor(private limit: number) {}
        async execute<T>(fn: () => Promise<T>): Promise<T> {
          return new Promise<T>((resolve, reject) => {
            this.queue.push({ fn: fn as () => Promise<unknown>, resolve: resolve as (value: unknown) => void, reject: reject as (error: unknown) => void });
            this.process();
          });
        }
        private async process() {
          while (this.running < this.limit && this.queue.length > 0) {
            const task = this.queue.shift();
            if (!task) break;
            this.running++;
            task.fn().then(task.resolve).catch(task.reject).finally(() => {
              this.running--;
              this.process();
            });
          }
        }
      }

      const batchLimiter = new BatchConcurrencyLimiter(MAX_CONCURRENT_BATCHES);

      // Process ALL batches in parallel (continuous processing - no waiting for batch groups)
      const batchPromises = batches.map((batch, batchIndex) =>
        batchLimiter.execute(async () => {
          try {
            // Check cancellation before starting batch analysis
            const jobCheck = await prisma.analysisJob.findUnique({
              where: { id: jobId },
              select: { status: true },
            });

            if (jobCheck?.status === 'CANCELLED') {
              throw new Error('Job cancelled before batch analysis');
            }

            console.log(`[Background Analysis ${jobId}] Starting batch ${batchIndex + 1}/${batches.length} (${batch.length} contacts)`);
            const result = await analyzeSelectedContacts(
              batch, 
              organizationId,
              (analyzed, failed, total) => {
                // Update counts in real-time as contacts complete
                analyzedCount = analyzed;
                failedCount = failed;
                // Update progress (non-blocking)
                updateProgress(true).catch((err) => {
                  console.error(`[Background Analysis ${jobId}] Failed to update progress:`, err);
                });
              }
            );
            
            // Check cancellation after batch analysis
            const jobCheckAfter = await prisma.analysisJob.findUnique({
              where: { id: jobId },
              select: { status: true },
            });

            if (jobCheckAfter?.status === 'CANCELLED') {
              throw new Error('Job cancelled after batch analysis');
            }
            
            // Update counts immediately as batch completes
            analyzedCount += result.successCount;
            failedCount += result.failedCount;
            errors.push(...result.errors);
            
            console.log(`[Background Analysis ${jobId}] Completed batch ${batchIndex + 1}/${batches.length}: ${result.successCount} success, ${result.failedCount} failed`);
            
            // Update progress after each batch completes
            await updateProgress(true);
            
            return { status: 'fulfilled' as const, value: result };
          } catch (error) {
            failedCount += batch.length;
            errors.push(
              ...batch.map((id) => ({
                contactId: id,
                error: error instanceof Error ? error.message : 'Unknown error',
              }))
            );
            
            console.error(`[Background Analysis ${jobId}] Batch ${batchIndex + 1}/${batches.length} failed:`, error instanceof Error ? error.message : String(error));
            
            // Update progress even on failure
            await updateProgress(true);
            
            return { status: 'rejected' as const, reason: error };
          }
        })
      );

      // Wait for ALL batches to complete in parallel (fully continuous processing)
      await Promise.allSettled(batchPromises);
      
      console.log(`[Background Analysis ${jobId}] ✅ All ${batches.length} batches completed in parallel`);
    }

    // Mark job as completed (use safe update for final status)
    try {
      // Get job to retrieve startedAt for metrics calculation
      const job = await prisma.analysisJob.findUnique({
        where: { id: jobId },
        select: { startedAt: true },
      });

      const completedAt = new Date();
      
      // Get API call metrics for the job period
      const apiMetrics = getApiMetricsForPeriod(job?.startedAt || null, completedAt);

      // Calculate performance metrics
      const metrics = calculateJobMetrics({
        startedAt: job?.startedAt || null,
        completedAt,
        totalContacts: contactIds.length,
        processedContacts: analyzedCount,
        failedContacts: failedCount,
        aiSuccessCount: analyzedCount, // AI analysis succeeded for these
        aiFailureCount: failedCount,   // AI analysis failed for these
        apiSuccessCount: apiMetrics.successCount,
        apiFailureCount: apiMetrics.failureCount,
      });

      await prisma.analysisJob.update({
        where: { id: jobId },
        data: {
          status: 'COMPLETED',
          analyzedContacts: normalizeCount(analyzedCount),
          failedContacts: normalizeCount(failedCount),
          errors: errors.length > 0 ? errors : undefined,
          completedAt,
          durationMs: metrics.durationMs,
          contactsPerSecond: metrics.contactsPerSecond,
          aiSuccessRate: metrics.aiSuccessRate,
          apiSuccessRate: metrics.apiSuccessRate,
        },
      });

      // Log metrics
      if (metrics.durationMs) {
        console.log(`[Background Analysis ${jobId}] ⏱️ Duration: ${(metrics.durationMs / 1000).toFixed(1)}s`);
      }
      if (metrics.contactsPerSecond) {
        console.log(`[Background Analysis ${jobId}] 📊 Contacts/sec: ${metrics.contactsPerSecond.toFixed(2)}`);
      }
      if (metrics.aiSuccessRate !== undefined) {
        console.log(`[Background Analysis ${jobId}] 🤖 AI Success Rate: ${metrics.aiSuccessRate.toFixed(1)}%`);
      }
      if (metrics.apiSuccessRate !== undefined) {
        console.log(`[Background Analysis ${jobId}] 🔌 API Success Rate: ${metrics.apiSuccessRate.toFixed(1)}%`);
      }
    } catch (error) {
      // Log but don't throw - job processing is complete
      console.error(`[Background Analysis ${jobId}] Failed to mark job as completed:`, error);
    }

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
        // Categorize errors by type for better debugging
        const errorCategories = new Map<string, number>();
        errors.forEach(err => {
          const category = err.error.split(':')[0] || err.error.split(' ')[0] || 'Unknown';
          errorCategories.set(category, (errorCategories.get(category) || 0) + 1);
        });
        
        console.error(`[Background Analysis ${jobId}] Error summary by category:`);
        errorCategories.forEach((count, category) => {
          console.error(`[Background Analysis ${jobId}]   - ${category}: ${count} contact(s)`);
        });
        
        // Log first 10 errors in detail, then summarize the rest
        const maxDetailErrors = 10;
        const errorsToLog = errors.slice(0, maxDetailErrors);
        const remainingCount = errors.length - maxDetailErrors;
        
        console.error(`[Background Analysis ${jobId}] Detailed error list (showing first ${errorsToLog.length}):`);
        errorsToLog.forEach((err, index) => {
          console.error(`[Background Analysis ${jobId}]   ${index + 1}. Contact ${err.contactId}: ${err.error}`);
        });
        
        if (remainingCount > 0) {
          console.error(`[Background Analysis ${jobId}]   ... and ${remainingCount} more error(s) (see job errors field for full list)`);
        }
        
        // Also log full errors array for programmatic access
        console.error(`[Background Analysis ${jobId}] Full error array (${errors.length} errors):`, JSON.stringify(errors, null, 2));
      }
    }
  } catch (error) {
    console.error(`[Background Analysis ${jobId}] Error:`, error);
    
    // Mark job as failed (use safe update)
    try {
      // Get job to retrieve startedAt for metrics calculation
      const job = await prisma.analysisJob.findUnique({
        where: { id: jobId },
        select: { startedAt: true, totalContacts: true },
      });

      const completedAt = new Date();
      
      // Get API call metrics for the job period
      const apiMetrics = getApiMetricsForPeriod(job?.startedAt || null, completedAt);

      // Calculate metrics even for failed jobs
      const metrics = calculateJobMetrics({
        startedAt: job?.startedAt || null,
        completedAt,
        totalContacts: job?.totalContacts || contactIds.length,
        processedContacts: analyzedCount,
        failedContacts: failedCount,
        aiSuccessCount: analyzedCount,
        aiFailureCount: failedCount,
        apiSuccessCount: apiMetrics.successCount,
        apiFailureCount: apiMetrics.failureCount,
      });

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
          completedAt,
          durationMs: metrics.durationMs,
          contactsPerSecond: metrics.contactsPerSecond,
          aiSuccessRate: metrics.aiSuccessRate,
          apiSuccessRate: metrics.apiSuccessRate,
        },
      });
    } catch (updateError) {
      // Log but don't throw - error already logged above
      console.error(`[Background Analysis ${jobId}] Failed to mark job as failed:`, updateError);
    }
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

