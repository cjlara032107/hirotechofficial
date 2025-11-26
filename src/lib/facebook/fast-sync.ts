import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';

interface FastSyncResult {
  success: boolean;
  jobId: string;
  message: string;
}

interface ParticipantInfo {
  participantId: string;
  updatedTime: string;
  name?: string;
}

/**
 * Concurrency limiter utility for parallel operations
 */
class ConcurrencyLimiter {
  private queue: Array<{ 
    fn: () => Promise<unknown>; 
    resolve: (value: unknown) => void; 
    reject: (error: unknown) => void 
  }> = [];
  private running = 0;

  constructor(private limit: number) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ 
        fn: fn as () => Promise<unknown>, 
        resolve: resolve as (value: unknown) => void, 
        reject: reject as (error: unknown) => void 
      });
      this.process();
    });
  }

  private async process() {
    while (this.running < this.limit && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;

      this.running++;
      
      task.fn()
        .then((result) => {
          task.resolve(result);
        })
        .catch((error) => {
          task.reject(error);
        })
        .finally(() => {
          this.running--;
          this.process();
        });
    }
  }
}

/**
 * Starts a fast sync job that only stores contacts (no AI analysis, no conversation storage)
 */
export async function startFastSync(facebookPageId: string): Promise<FastSyncResult> {
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
        message: 'Fast sync already in progress',
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
    // For Vercel serverless, we need to ensure the promise chain starts before response
    // Use immediate execution with proper error handling
    (async () => {
      try {
        console.log(`[Fast Sync ${syncJob.id}] 🚀 Starting background execution immediately...`);
        await executeFastSync(syncJob.id, facebookPageId);
      } catch (error) {
        console.error(`[Fast Sync ${syncJob.id}] ❌ Failed:`, error);
        // Mark job as failed in database
        try {
          await prisma.syncJob.update({
            where: { id: syncJob.id },
            data: {
              status: 'FAILED',
              errors: [
                {
                  error: error instanceof Error ? error.message : String(error),
                  timestamp: new Date().toISOString(),
                },
              ],
              completedAt: new Date(),
            },
          });
        } catch (dbError) {
          console.error(`[Fast Sync ${syncJob.id}] ❌ Failed to update job status:`, dbError);
        }
      }
    })(); // Immediately invoked async function

    return {
      success: true,
      jobId: syncJob.id,
      message: 'Fast sync started',
    };
  } catch (error) {
    console.error('Failed to start fast sync:', error);
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
 * Batch fetch existing contacts for early skip checks
 */
async function getExistingContactsMap(
  facebookPageId: string,
  participantIds: string[],
  platform: 'messenger' | 'instagram'
): Promise<Map<string, { id: string }>> {
  if (participantIds.length === 0) {
    return new Map();
  }

  const whereClause = platform === 'messenger'
    ? {
        messengerPSID: { in: participantIds },
        facebookPageId,
      }
    : {
        OR: [
          { instagramSID: { in: participantIds }, facebookPageId },
          { messengerPSID: { in: participantIds }, facebookPageId },
        ],
      };

  const contacts = await prisma.contact.findMany({
    where: whereClause,
    select: {
      id: true,
      messengerPSID: true,
      instagramSID: true,
    },
  });

  const map = new Map<string, { id: string }>();
  
  for (const contact of contacts) {
    const participantId = platform === 'messenger' 
      ? contact.messengerPSID 
      : contact.instagramSID || contact.messengerPSID;
    
    if (participantId) {
      map.set(participantId, { id: contact.id });
    }
  }

  return map;
}

/**
 * Executes the fast sync operation - only stores contacts, no AI analysis
 */
async function executeFastSync(jobId: string, facebookPageId: string): Promise<void> {
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

    console.log(`[Fast Sync ${jobId}] Starting contact sync for Facebook Page: ${page.pageId}`);

    // Set initial total contacts to 0 (will be updated once we know the count)
    await prisma.syncJob.update({
      where: { id: jobId },
      data: {
        totalContacts: 0,
      },
    });

    // Sync Messenger contacts
    try {
      console.log(`[Fast Sync ${jobId}] Fetching Messenger conversations...`);
      const messengerConvos = await client.getMessengerConversations(page.pageId);
      console.log(`[Fast Sync ${jobId}] Fetched ${messengerConvos.length} Messenger conversations`);

      // Validate conversations array
      if (!Array.isArray(messengerConvos)) {
        throw new Error(`Expected array of conversations but got: ${typeof messengerConvos}`);
      }

      if (messengerConvos.length === 0) {
        console.warn(`[Fast Sync ${jobId}] No Messenger conversations found for page ${page.pageId}. The page may not have any conversations yet.`);
        // Still mark as completed, just with 0 contacts
      }

      // Collect all unique participants from all conversations
      const participantMap = new Map<string, ParticipantInfo>();
      let conversationsWithNoParticipants = 0;
      
      for (const convo of messengerConvos) {
        // Validate conversation structure
        if (!convo || typeof convo !== 'object') {
          console.warn(`[Fast Sync ${jobId}] Skipping invalid conversation:`, convo);
          continue;
        }

        // Validate participants structure
        if (!convo.participants || !convo.participants.data || !Array.isArray(convo.participants.data)) {
          console.warn(`[Fast Sync ${jobId}] Conversation ${convo.id} has no valid participants data`);
          conversationsWithNoParticipants++;
          continue;
        }

        // Validate updated_time exists
        if (!convo.updated_time) {
          console.warn(`[Fast Sync ${jobId}] Conversation ${convo.id} has no updated_time`);
          continue;
        }

        for (const participant of convo.participants.data) {
          // Validate participant structure
          if (!participant || !participant.id) {
            console.warn(`[Fast Sync ${jobId}] Skipping invalid participant in conversation ${convo.id}:`, participant);
            continue;
          }

          if (participant.id === page.pageId) continue; // Skip page itself
          
          const existing = participantMap.get(participant.id);
          // Keep the most recent updated_time
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            participantMap.set(participant.id, {
              participantId: participant.id,
              updatedTime: convo.updated_time,
              name: participant.name,
            });
          }
        }
      }

      if (conversationsWithNoParticipants > 0) {
        console.warn(`[Fast Sync ${jobId}] ${conversationsWithNoParticipants} conversations had no valid participants data`);
      }

      const participantList = Array.from(participantMap.values());
      console.log(`[Fast Sync ${jobId}] Found ${participantList.length} unique Messenger participants from ${messengerConvos.length} conversations`);

      if (participantList.length === 0 && messengerConvos.length > 0) {
        console.warn(`[Fast Sync ${jobId}] WARNING: Found ${messengerConvos.length} conversations but 0 participants. This might indicate an issue with the Facebook API response format.`);
      }

      // Batch fetch existing contacts for early skip checks
      const participantIds = participantList.map(p => p.participantId);
      const existingContactsMap = await getExistingContactsMap(
        page.id,
        participantIds,
        'messenger'
      );

      // Filter out existing contacts (skip all existing, not just those with pipelineId)
      const contactsToProcess = participantList.filter(p => {
        const existing = existingContactsMap.get(p.participantId);
        if (existing) {
          console.log(`[Fast Sync ${jobId}] Skipping ${p.participantId} - contact already exists`);
          return false;
        }
        return true;
      });

      console.log(`[Fast Sync ${jobId}] ${contactsToProcess.length} new contacts to process (${participantList.length - contactsToProcess.length} skipped)`);

      // Update total contacts
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          totalContacts: contactsToProcess.length,
        },
      });

      // Process contacts in batches
      const BATCH_SIZE = 50; // Process 50 contacts at a time
      const batches = [];
      for (let i = 0; i < contactsToProcess.length; i += BATCH_SIZE) {
        batches.push(contactsToProcess.slice(i, i + BATCH_SIZE));
      }

      const contactLimiter = new ConcurrencyLimiter(10); // 10 concurrent contact upserts

      for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
        const batch = batches[batchIndex];
        
        if (await isJobCancelled(jobId)) {
          console.log(`[Fast Sync ${jobId}] Sync cancelled by user`);
          return;
        }

        console.log(`[Fast Sync ${jobId}] Processing batch ${batchIndex + 1}/${batches.length} (${batch.length} contacts)...`);

        await Promise.all(
          batch.map(participant =>
            contactLimiter.execute(async () => {
              try {
                // Validate participant data
                if (!participant || !participant.participantId) {
                  throw new Error('Invalid participant data: missing participantId');
                }

                // Extract name
                let firstName = `User ${participant.participantId.slice(-6)}`;
                let lastName: string | null = null;

                if (participant.name) {
                  const nameParts = participant.name.trim().split(' ');
                  firstName = nameParts[0] || firstName;
                  if (nameParts.length > 1) {
                    lastName = nameParts.slice(1).join(' ');
                  }
                }

                // Validate updatedTime
                let lastInteraction: Date;
                try {
                  lastInteraction = new Date(participant.updatedTime);
                  if (isNaN(lastInteraction.getTime())) {
                    console.warn(`[Fast Sync ${jobId}] Invalid updatedTime for participant ${participant.participantId}, using current date`);
                    lastInteraction = new Date();
                  }
                } catch {
                  console.warn(`[Fast Sync ${jobId}] Error parsing updatedTime for participant ${participant.participantId}, using current date`);
                  lastInteraction = new Date();
                }

                // Upsert contact (no AI analysis, no pipeline assignment)
                await prisma.contact.upsert({
                  where: {
                    messengerPSID_facebookPageId: {
                      messengerPSID: participant.participantId,
                      facebookPageId: page.id,
                    },
                  },
                  create: {
                    messengerPSID: participant.participantId,
                    firstName,
                    lastName,
                    hasMessenger: true,
                    organizationId: page.organizationId,
                    facebookPageId: page.id,
                    lastInteraction,
                  },
                  update: {
                    firstName,
                    lastName,
                    lastInteraction,
                    hasMessenger: true,
                  },
                });

                syncedCount++;
              } catch (error) {
                failedCount++;
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                const participantId = participant?.participantId || 'unknown';
                
                console.error(`[Fast Sync ${jobId}] Failed to sync Messenger contact ${participantId}:`, error);
                
                errors.push({
                  platform: 'Messenger',
                  id: participantId,
                  error: errorMessage,
                  code: errorCode,
                });
                if (error instanceof FacebookApiError && error.isTokenExpired) {
                  tokenExpired = true;
                }
              }
            })
          )
        );

        // Update progress after each batch
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            syncedContacts: syncedCount,
            failedContacts: failedCount,
          },
        });

        console.log(`[Fast Sync ${jobId}] Batch ${batchIndex + 1}/${batches.length} complete: ${syncedCount} synced, ${failedCount} failed`);
      }
    } catch (error) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }

      console.error(`[Fast Sync ${jobId}] Failed to fetch Messenger conversations for page ${page.pageId}:`, error);
      
      // Log detailed error information
      if (error instanceof Error) {
        console.error(`[Fast Sync ${jobId}] Error details:`, {
          message: error.message,
          stack: error.stack,
          name: error.name,
        });
      }
      
      errors.push({
        platform: 'Messenger',
        id: 'conversations',
        error: errorMessage,
        code: errorCode,
      });

      // Update job status to indicate conversation fetch failure
      await prisma.syncJob.update({
        where: { id: jobId },
        data: {
          status: tokenExpired ? 'FAILED' : 'FAILED',
          errors: errors.length > 0 ? errors : Prisma.JsonNull,
          tokenExpired,
          completedAt: new Date(),
        },
      });
    }

    // Sync Instagram contacts (if connected)
    if (page.instagramAccountId) {
      try {
        console.log(`[Fast Sync ${jobId}] Fetching Instagram conversations...`);
        const igConvos = await client.getInstagramConversations(page.instagramAccountId);
        console.log(`[Fast Sync ${jobId}] Fetched ${igConvos.length} Instagram conversations`);

        // Validate conversations array
        if (!Array.isArray(igConvos)) {
          console.error(`[Fast Sync ${jobId}] Expected array of IG conversations but got: ${typeof igConvos}`);
          throw new Error(`Invalid Instagram conversations data type: ${typeof igConvos}`);
        }

        if (igConvos.length === 0) {
          console.warn(`[Fast Sync ${jobId}] No Instagram conversations found for account ${page.instagramAccountId}.`);
        }

        // Collect all unique participants
        const igParticipantMap = new Map<string, ParticipantInfo>();
        let igConversationsWithNoParticipants = 0;
        
        for (const convo of igConvos) {
          // Validate conversation structure
          if (!convo || typeof convo !== 'object') {
            console.warn(`[Fast Sync ${jobId}] Skipping invalid IG conversation:`, convo);
            continue;
          }

          // Validate participants structure
          if (!convo.participants || !convo.participants.data || !Array.isArray(convo.participants.data)) {
            console.warn(`[Fast Sync ${jobId}] IG Conversation ${convo.id} has no valid participants data`);
            igConversationsWithNoParticipants++;
            continue;
          }

          // Validate updated_time exists
          if (!convo.updated_time) {
            console.warn(`[Fast Sync ${jobId}] IG Conversation ${convo.id} has no updated_time`);
            continue;
          }

          for (const participant of convo.participants.data) {
            // Validate participant structure
            if (!participant || !participant.id) {
              console.warn(`[Fast Sync ${jobId}] Skipping invalid IG participant in conversation ${convo.id}:`, participant);
              continue;
            }

            if (participant.id === page.instagramAccountId) continue; // Skip page itself
            
            const existing = igParticipantMap.get(participant.id);
            if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
              igParticipantMap.set(participant.id, {
                participantId: participant.id,
                updatedTime: convo.updated_time,
                name: participant.name,
              });
            }
          }
        }

        if (igConversationsWithNoParticipants > 0) {
          console.warn(`[Fast Sync ${jobId}] ${igConversationsWithNoParticipants} IG conversations had no valid participants data`);
        }

        const igParticipantList = Array.from(igParticipantMap.values());
        console.log(`[Fast Sync ${jobId}] Found ${igParticipantList.length} unique Instagram participants from ${igConvos.length} conversations`);

        if (igParticipantList.length === 0 && igConvos.length > 0) {
          console.warn(`[Fast Sync ${jobId}] WARNING: Found ${igConvos.length} IG conversations but 0 participants. This might indicate an issue with the Facebook API response format.`);
        }

        // Batch fetch existing contacts
        const igParticipantIds = igParticipantList.map(p => p.participantId);
        const existingIgContactsMap = await getExistingContactsMap(
          page.id,
          igParticipantIds,
          'instagram'
        );

        // Filter out existing contacts
        const igContactsToProcess = igParticipantList.filter(p => {
          const existing = existingIgContactsMap.get(p.participantId);
          if (existing) {
            console.log(`[Fast Sync ${jobId}] Skipping IG ${p.participantId} - contact already exists`);
            return false;
          }
          return true;
        });

        console.log(`[Fast Sync ${jobId}] ${igContactsToProcess.length} new IG contacts to process (${igParticipantList.length - igContactsToProcess.length} skipped)`);

        // Update total contacts to include Instagram
        const currentTotal = await prisma.syncJob.findUnique({
          where: { id: jobId },
          select: { totalContacts: true },
        });
        const newTotal = (currentTotal?.totalContacts || 0) + igContactsToProcess.length;
        await prisma.syncJob.update({
          where: { id: jobId },
          data: {
            totalContacts: newTotal,
          },
        });

        // Process Instagram contacts in batches
        const IG_BATCH_SIZE = 50;
        const igBatches = [];
        for (let i = 0; i < igContactsToProcess.length; i += IG_BATCH_SIZE) {
          igBatches.push(igContactsToProcess.slice(i, i + IG_BATCH_SIZE));
        }

        const igContactLimiter = new ConcurrencyLimiter(10);

        for (let batchIndex = 0; batchIndex < igBatches.length; batchIndex++) {
          const batch = igBatches[batchIndex];
          
          if (await isJobCancelled(jobId)) {
            console.log(`[Fast Sync ${jobId}] Sync cancelled by user`);
            return;
          }

          console.log(`[Fast Sync ${jobId}] Processing IG batch ${batchIndex + 1}/${igBatches.length} (${batch.length} contacts)...`);

          await Promise.all(
            batch.map(participant =>
              igContactLimiter.execute(async () => {
                try {
                  // Validate participant data
                  if (!participant || !participant.participantId) {
                    throw new Error('Invalid participant data: missing participantId');
                  }

                  // Extract name
                  let firstName = `IG User ${participant.participantId.slice(-6)}`;
                  let lastName: string | null = null;

                  if (participant.name) {
                    const nameParts = participant.name.trim().split(' ');
                    firstName = nameParts[0] || firstName;
                    if (nameParts.length > 1) {
                      lastName = nameParts.slice(1).join(' ');
                    }
                  }

                  // Validate updatedTime
                  let lastInteraction: Date;
                  try {
                    lastInteraction = new Date(participant.updatedTime);
                    if (isNaN(lastInteraction.getTime())) {
                      console.warn(`[Fast Sync ${jobId}] Invalid updatedTime for IG participant ${participant.participantId}, using current date`);
                      lastInteraction = new Date();
                    }
                  } catch {
                    console.warn(`[Fast Sync ${jobId}] Error parsing updatedTime for IG participant ${participant.participantId}, using current date`);
                    lastInteraction = new Date();
                  }

                  // Check if contact exists by Instagram ID or Messenger PSID
                  const existingContact = await prisma.contact.findFirst({
                    where: {
                      OR: [
                        { instagramSID: participant.participantId, facebookPageId: page.id },
                        { messengerPSID: participant.participantId, facebookPageId: page.id },
                      ],
                    },
                  });

                  if (existingContact) {
                    // Update existing contact
                    await prisma.contact.update({
                      where: { id: existingContact.id },
                      data: {
                        instagramSID: participant.participantId,
                        firstName,
                        lastName,
                        hasInstagram: true,
                        lastInteraction,
                      },
                    });
                  } else {
                    // Create new contact
                    await prisma.contact.create({
                      data: {
                        instagramSID: participant.participantId,
                        firstName,
                        lastName,
                        hasInstagram: true,
                        organizationId: page.organizationId,
                        facebookPageId: page.id,
                        lastInteraction,
                      },
                    });
                  }

                  syncedCount++;
                } catch (error) {
                  failedCount++;
                  const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                  const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                  const participantId = participant?.participantId || 'unknown';
                  
                  console.error(`[Fast Sync ${jobId}] Failed to sync Instagram contact ${participantId}:`, error);
                  
                  errors.push({
                    platform: 'Instagram',
                    id: participantId,
                    error: errorMessage,
                    code: errorCode,
                  });
                  if (error instanceof FacebookApiError && error.isTokenExpired) {
                    tokenExpired = true;
                  }
                }
              })
            )
          );

          // Update progress after each batch
          await prisma.syncJob.update({
            where: { id: jobId },
            data: {
              syncedContacts: syncedCount,
              failedContacts: failedCount,
            },
          });

          console.log(`[Fast Sync ${jobId}] IG Batch ${batchIndex + 1}/${igBatches.length} complete: ${syncedCount} synced, ${failedCount} failed`);
        }
      } catch (error) {
        const errorCode = error instanceof FacebookApiError ? error.code : undefined;
        const errorMessage = error instanceof Error ? error.message : 'Failed to fetch conversations';

        if (error instanceof FacebookApiError && error.isTokenExpired) {
          tokenExpired = true;
        }

        console.error(`[Fast Sync ${jobId}] Failed to fetch Instagram conversations for account ${page.instagramAccountId}:`, error);
        
        // Log detailed error information
        if (error instanceof Error) {
          console.error(`[Fast Sync ${jobId}] IG Error details:`, {
            message: error.message,
            stack: error.stack,
            name: error.name,
          });
        }
        
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

    console.log(`[Fast Sync ${jobId}] Completed: ${syncedCount} synced, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`[Fast Sync ${jobId}] Fatal error:`, error);

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
 * Gets the status of a fast sync job
 */
export async function getFastSyncJobStatus(jobId: string) {
  const job = await prisma.syncJob.findUnique({
    where: { id: jobId },
  });

  if (!job) {
    throw new Error('Sync job not found');
  }

  return job;
}

/**
 * Gets the latest fast sync job for a Facebook page
 */
export async function getLatestFastSyncJob(facebookPageId: string) {
  return prisma.syncJob.findFirst({
    where: {
      facebookPageId,
    },
    orderBy: {
      createdAt: 'desc',
    },
  });
}

