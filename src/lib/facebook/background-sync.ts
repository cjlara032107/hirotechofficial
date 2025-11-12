import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeConversation } from '@/lib/ai/google-ai-service';

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
    });

    if (!page) {
      throw new Error('Facebook page not found');
    }

    const client = new FacebookClient(page.pageAccessToken);
    let syncedCount = 0;
    let failedCount = 0;
    let tokenExpired = false;
    const errors: Array<{ platform: string; id: string; error: string; code?: number }> = [];

    console.log(`[Background Sync ${jobId}] Starting contact sync for Facebook Page: ${page.pageId}`);

    // Sync Messenger contacts
    try {
      console.log(`[Background Sync ${jobId}] Fetching Messenger conversations...`);
      const messengerConvos = await client.getMessengerConversations(page.pageId);
      console.log(`[Background Sync ${jobId}] Fetched ${messengerConvos.length} Messenger conversations`);

      for (const convo of messengerConvos) {
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
            
            if (convo.messages?.data && convo.messages.data.length > 0) {
              try {
                const messagesToAnalyze = convo.messages.data
                  .filter((msg: any) => msg.message)
                  .map((msg: any) => ({
                    from: msg.from?.name || msg.from?.id || 'Unknown',
                    text: msg.message,
                  }));

                if (messagesToAnalyze.length > 0) {
                  aiContext = await analyzeConversation(messagesToAnalyze);
                }
              } catch (error) {
                console.error(`[Background Sync ${jobId}] Failed to analyze conversation for ${participant.id}:`, error);
              }
            }

            await prisma.contact.upsert({
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
            
            if (convo.messages?.data && convo.messages.data.length > 0) {
              try {
                const messagesToAnalyze = convo.messages.data
                  .filter((msg: any) => msg.message)
                  .map((msg: any) => ({
                    from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
                    text: msg.message,
                  }));

                if (messagesToAnalyze.length > 0) {
                  aiContext = await analyzeConversation(messagesToAnalyze);
                }
              } catch (error) {
                console.error(`[Background Sync ${jobId}] Failed to analyze IG conversation for ${participant.id}:`, error);
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

              if (existingContact) {
                await prisma.contact.update({
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
                await prisma.contact.create({
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

