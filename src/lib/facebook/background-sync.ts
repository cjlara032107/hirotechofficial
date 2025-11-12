import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeConversation, analyzeConversationWithStageRecommendation } from '@/lib/ai/google-ai-service';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';

interface BackgroundSyncResult {
  success: boolean;
  jobId: string;
  message: string;
}

/**
 * Starts a background sync job that tracks progress in the database
 * This allows syncing to continue even if the user navigates away
 */
export async function startBackgroundSync(facebookPageId: string): Promise<BackgroundSyncResult> {
  try {
    // Check if there's already an active sync job for this page
    const existingJob = await prisma.syncJob.findFirst({
      where: {
        facebookPageId,
        status: {
          in: ['PENDING', 'IN_PROGRESS'],
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
        message: 'Sync already in progress',
      };
    }

    // Create a new sync job
    const syncJob = await prisma.syncJob.create({
      data: {
        facebookPageId,
        status: 'PENDING',
      },
    });

    // Start the sync process asynchronously (don't await)
    executeBackgroundSync(syncJob.id, facebookPageId).catch((error) => {
      console.error(`Background sync failed for job ${syncJob.id}:`, error);
    });

    return {
      success: true,
      jobId: syncJob.id,
      message: 'Sync started',
    };
  } catch (error) {
    console.error('Failed to start background sync:', error);
    throw error;
  }
}

/**
 * Check if sync job has been cancelled
 */
async function isJobCancelled(jobId: string): Promise<boolean> {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
    select: { status: true },
  });
  return job?.status === 'CANCELLED';
}

/**
 * Executes the actual sync operation and updates the job status
 */
async function executeBackgroundSync(jobId: string, facebookPageId: string): Promise<void> {
  try {
    // Update job status to in progress
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'IN_PROGRESS',
        startedAt: new Date(),
      },
    });

    const page = await prisma.facebookPage.findUnique({
      where: { id: facebookPageId },
      include: {
        autoPipeline: {
          include: {
            stages: { orderBy: { order: 'asc' } }
          }
        }
      }
    });

    if (!page) {
      throw new Error('Facebook page not found');
    }

    const client = new FacebookClient(page.pageAccessToken);
    let syncedCount = 0;
    let failedCount = 0;
    
    console.log(`[Background Sync ${jobId}] Auto-Pipeline Enabled:`, !!page.autoPipelineId);
    if (page.autoPipelineId) {
      console.log(`[Background Sync ${jobId}] Target Pipeline:`, page.autoPipeline?.name);
      console.log(`[Background Sync ${jobId}] Mode:`, page.autoPipelineMode);
    }
    let tokenExpired = false;
    const errors: Array<{ platform: string; id: string; error: string; code?: number }> = [];

    console.log(`[Background Sync ${jobId}] Starting contact sync for Facebook Page: ${page.pageId}`);

    // Sync Messenger contacts
    try {
      console.log(`[Background Sync ${jobId}] Fetching Messenger conversations...`);
      const messengerConvos = await client.getMessengerConversations(page.pageId);
      console.log(`[Background Sync ${jobId}] Fetched ${messengerConvos.length} Messenger conversations`);

      for (const convo of messengerConvos) {
        // Check if sync has been cancelled
        if (await isJobCancelled(jobId)) {
          console.log(`[Background Sync ${jobId}] Sync cancelled by user`);
          return; // Exit gracefully
        }

        for (const participant of convo.participants.data) {
          if (participant.id === page.pageId) continue; // Skip page itself

          try {
            // Extract name from conversation messages
            let firstName = `User ${participant.id.slice(-6)}`;
            let lastName: string | null = null;

            if (convo.messages?.data) {
              const userMessage = convo.messages.data.find(
                (msg: { from?: { id?: string } }) => msg.from?.id === participant.id
              );

              if (userMessage?.from?.name) {
                const nameParts = userMessage.from.name.trim().split(' ');
                firstName = nameParts[0] || firstName;

                if (nameParts.length > 1) {
                  lastName = nameParts.slice(1).join(' ');
                }
              }
            }

            // Analyze conversation with AI if messages exist
            let aiContext: string | null = null;
            let aiAnalysis = null;
            
            if (convo.messages?.data && convo.messages.data.length > 0) {
              try {
                const messagesToAnalyze = convo.messages.data
                  .filter((msg: any) => msg.message)
                  .map((msg: any) => ({
                    from: msg.from?.name || msg.from?.id || 'Unknown',
                    text: msg.message,
                  }));

                if (messagesToAnalyze.length > 0) {
                  // If auto-pipeline is enabled, get full analysis
                  if (page.autoPipelineId && page.autoPipeline) {
                    aiAnalysis = await analyzeConversationWithStageRecommendation(
                      messagesToAnalyze,
                      page.autoPipeline.stages
                    );
                    aiContext = aiAnalysis?.summary || null;
                  } else {
                    // Otherwise just get summary
                    aiContext = await analyzeConversation(messagesToAnalyze);
                  }
                  
                  // Always add delay after analysis attempt (success or failure)
                  // This ensures we don't hit rate limits on the next contact
                  await new Promise(resolve => setTimeout(resolve, 1000));
                }
              } catch (error) {
                console.error(`[Background Sync ${jobId}] Failed to analyze conversation for ${participant.id}:`, error);
                // Add delay even on error to prevent rapid-fire failures
                await new Promise(resolve => setTimeout(resolve, 1000));
              }
            }

            const savedContact = await prisma.contact.upsert({
              where: {
                messengerPSID_facebookPageId: {
                  messengerPSID: participant.id,
                  facebookPageId: page.id,
                },
              },
              create: {
                messengerPSID: participant.id,
                firstName: firstName,
                lastName: lastName,
                hasMessenger: true,
                organizationId: page.organizationId,
                facebookPageId: page.id,
                lastInteraction: new Date(convo.updated_time),
                aiContext: aiContext,
                aiContextUpdatedAt: aiContext ? new Date() : null,
              },
              update: {
                firstName: firstName,
                lastName: lastName,
                lastInteraction: new Date(convo.updated_time),
                hasMessenger: true,
                aiContext: aiContext,
                aiContextUpdatedAt: aiContext ? new Date() : null,
              },
            });
            
            // Auto-assign to pipeline if enabled
            if (aiAnalysis && page.autoPipelineId) {
              await autoAssignContactToPipeline({
                contactId: savedContact.id,
                aiAnalysis,
                pipelineId: page.autoPipelineId,
                updateMode: page.autoPipelineMode,
              });
            }
            
            syncedCount++;

            // Update job progress periodically
            if (syncedCount % 10 === 0) {
              await prisma.syncJob.update({
                where: { id: jobId },
                data: {
                  syncedContacts: syncedCount,
                  failedContacts: failedCount,
                },
              });
            }
          } catch (error) {
            failedCount++;
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const errorCode = error instanceof FacebookApiError ? error.code : undefined;

            if (error instanceof FacebookApiError && error.isTokenExpired) {
              tokenExpired = true;
            }

            console.error(`[Background Sync ${jobId}] Failed to sync Messenger contact ${participant.id}:`, errorMessage);
            errors.push({
              platform: 'Messenger',
              id: participant.id,
              error: errorMessage,
              code: errorCode,
            });
          }
        }
      }
    } catch (error) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }

      console.error(`[Background Sync ${jobId}] Failed to fetch Messenger conversations:`, error);
      errors.push({
        platform: 'Messenger',
        id: 'conversations',
        error: errorMessage,
        code: errorCode,
      });
    }

    // Sync Instagram contacts (if connected)
    if (page.instagramAccountId) {
      try {
        console.log(`[Background Sync ${jobId}] Fetching Instagram conversations...`);
        const igConvos = await client.getInstagramConversations(page.instagramAccountId);
        console.log(`[Background Sync ${jobId}] Fetched ${igConvos.length} Instagram conversations`);

      for (const convo of igConvos) {
        // Check if sync has been cancelled
        if (await isJobCancelled(jobId)) {
          console.log(`[Background Sync ${jobId}] Sync cancelled by user`);
          return; // Exit gracefully
        }

        for (const participant of convo.participants.data) {
          if (participant.id === page.instagramAccountId) continue;

          try {
            let firstName = `IG User ${participant.id.slice(-6)}`;
            let lastName: string | null = null;

            if (convo.messages?.data) {
              const userMessage = convo.messages.data.find(
                (msg: { from?: { id?: string } }) => msg.from?.id === participant.id
              );

              if (userMessage?.from?.name) {
                const nameParts = userMessage.from.name.trim().split(' ');
                firstName = nameParts[0] || firstName;

                if (nameParts.length > 1) {
                  lastName = nameParts.slice(1).join(' ');
                }
              } else if (userMessage?.from?.username) {
                firstName = userMessage.from.username;
              }
            }

            // Analyze conversation with AI if messages exist
            let aiContext: string | null = null;
            let aiAnalysis = null;
            
            if (convo.messages?.data && convo.messages.data.length > 0) {
              try {
                const messagesToAnalyze = convo.messages.data
                  .filter((msg: any) => msg.message)
                  .map((msg: any) => ({
                    from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
                    text: msg.message,
                  }));

                if (messagesToAnalyze.length > 0) {
                  // If auto-pipeline is enabled, get full analysis
                  if (page.autoPipelineId && page.autoPipeline) {
                    aiAnalysis = await analyzeConversationWithStageRecommendation(
                      messagesToAnalyze,
                      page.autoPipeline.stages
                    );
                    aiContext = aiAnalysis?.summary || null;
                  } else {
                    // Otherwise just get summary
                    aiContext = await analyzeConversation(messagesToAnalyze);
                  }
                  
                  // Always add delay after analysis attempt (success or failure)
                  // This ensures we don't hit rate limits on the next contact
                  await new Promise(resolve => setTimeout(resolve, 1000));
                }
              } catch (error) {
                console.error(`[Background Sync ${jobId}] Failed to analyze IG conversation for ${participant.id}:`, error);
                // Add delay even on error to prevent rapid-fire failures
                await new Promise(resolve => setTimeout(resolve, 1000));
              }
            }

              const existingContact = await prisma.contact.findFirst({
                where: {
                  OR: [
                    { instagramSID: participant.id, facebookPageId: page.id },
                    { messengerPSID: participant.id, facebookPageId: page.id },
                  ],
                },
              });

              let savedContact;
              if (existingContact) {
                savedContact = await prisma.contact.update({
                  where: { id: existingContact.id },
                  data: {
                    instagramSID: participant.id,
                    firstName: firstName,
                    lastName: lastName,
                    hasInstagram: true,
                    lastInteraction: new Date(convo.updated_time),
                    aiContext: aiContext,
                    aiContextUpdatedAt: aiContext ? new Date() : null,
                  },
                });
              } else {
                savedContact = await prisma.contact.create({
                  data: {
                    instagramSID: participant.id,
                    firstName: firstName,
                    lastName: lastName,
                    hasInstagram: true,
                    organizationId: page.organizationId,
                    facebookPageId: page.id,
                    lastInteraction: new Date(convo.updated_time),
                    aiContext: aiContext,
                    aiContextUpdatedAt: aiContext ? new Date() : null,
                  },
                });
              }
              
              // Auto-assign to pipeline if enabled
              if (aiAnalysis && page.autoPipelineId) {
                await autoAssignContactToPipeline({
                  contactId: savedContact.id,
                  aiAnalysis,
                  pipelineId: page.autoPipelineId,
                  updateMode: page.autoPipelineMode,
                });
              }
              
              syncedCount++;

              // Update job progress periodically
              if (syncedCount % 10 === 0) {
                await prisma.syncJob.update({
                  where: { id: jobId },
                  data: {
                    syncedContacts: syncedCount,
                    failedContacts: failedCount,
                  },
              });
            }
          } catch (error) {
            failedCount++;
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const errorCode = error instanceof FacebookApiError ? error.code : undefined;

            if (error instanceof FacebookApiError && error.isTokenExpired) {
              tokenExpired = true;
            }

            console.error(`[Background Sync ${jobId}] Failed to sync IG contact ${participant.id}:`, errorMessage);
            errors.push({
              platform: 'Instagram',
              id: participant.id,
              error: errorMessage,
              code: errorCode,
            });
          }
        }
      }
    } catch (error) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }

      console.error(`[Background Sync ${jobId}] Failed to fetch Instagram conversations:`, error);
      errors.push({
        platform: 'Instagram',
        id: 'conversations',
        error: errorMessage,
        code: errorCode,
      });
    }
  }

    // Update last synced time if successful
    if (syncedCount > 0 || !tokenExpired) {
      await prisma.facebookPage.update({
        where: { id: page.id },
        data: { lastSyncedAt: new Date() },
      });
    }

    // Update job with final results
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: tokenExpired ? 'FAILED' : 'COMPLETED',
        syncedContacts: syncedCount,
        failedContacts: failedCount,
        totalContacts: syncedCount + failedCount,
        errors: errors.length > 0 ? errors : Prisma.JsonNull,
        tokenExpired,
        completedAt: new Date(),
      },
    });

    console.log(`[Background Sync ${jobId}] Completed: ${syncedCount} synced, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`[Background Sync ${jobId}] Fatal error:`, error);

    // Mark job as failed
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        status: 'FAILED',
        errors: [{ error: errorMessage }],
        completedAt: new Date(),
      },
    });
  }
}

/**
 * Gets the status of a sync job
 */
export async function getSyncJobStatus(jobId: string) {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
  });

  if (!job) {
    throw new Error('Sync job not found');
  }

  return job;
}

/**
 * Gets the latest sync job for a Facebook page
 */
export async function getLatestSyncJob(facebookPageId: string) {
  return prisma.syncJob.findFirst({
    where: {
      facebookPageId,
    },
    orderBy: {
      createdAt: 'desc',
    },
  });
}

