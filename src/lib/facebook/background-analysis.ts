import { prisma, connectPrisma } from '@/lib/db';
import { analyzeSelectedContacts } from './analyze-selected-contacts';
import { AnalysisJobStatus } from '@prisma/client';

interface BackgroundAnalysisResult {
  success: boolean;
  jobId: string;
  message: string;
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
    
    // Check if there's already an active analysis job for these contacts
    const existingJob = await prisma.analysisJob.findFirst({
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

    if (existingJob) {
      return {
        success: true,
        jobId: existingJob.id,
        message: 'Analysis already in progress',
      };
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

    // Start the analysis process asynchronously (don't await)
    // For Vercel serverless, we need to ensure the promise chain starts before response
    // Use immediate execution with proper error handling
    const backgroundPromise = (async () => {
      try {
        console.log(`[Background Analysis ${analysisJob.id}] 🚀 Starting background execution immediately...`);
        console.log(`[Background Analysis ${analysisJob.id}] Contact IDs to process:`, contactIds);
        console.log(`[Background Analysis ${analysisJob.id}] Total contacts: ${contactIds.length}`);
        
        // CRITICAL: Ensure we have a connection before starting
        await connectPrisma();
        
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
    })(); // Immediately invoked async function
    
    // CRITICAL: In Vercel, we need to keep the promise alive
    // Store it globally to prevent garbage collection
    if (typeof globalThis !== 'undefined') {
      (globalThis as any).__backgroundAnalysisPromises = (globalThis as any).__backgroundAnalysisPromises || new Set();
      (globalThis as any).__backgroundAnalysisPromises.add(backgroundPromise);
      backgroundPromise.finally(() => {
        (globalThis as any).__backgroundAnalysisPromises?.delete(backgroundPromise);
      });
    }

    return {
      success: true,
      jobId: analysisJob.id,
      message: 'Analysis started',
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
    
    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();
    
    // Update job status to IN_PROGRESS
    await prisma.analysisJob.update({
      where: { id: jobId },
      data: {
        status: 'IN_PROGRESS',
        startedAt: new Date(),
      },
    });

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
      // Always update for small jobs, or every 5 contacts for large jobs
      const shouldUpdate = force || useIndividualProcessing || (analyzedCount + failedCount) % 5 === 0;
      
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
        
        console.log(
          `[Background Analysis ${jobId}] Progress: ${analyzedCount}/${contactIds.length} analyzed, ${failedCount} failed`
        );
      }
    };

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
      `[Background Analysis ${jobId}] Completed: ${analyzedCount} analyzed, ${failedCount} failed`
    );
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

