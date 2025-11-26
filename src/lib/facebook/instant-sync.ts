import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { FacebookClient, FacebookApiError } from './client';
import { startBackgroundAnalysis } from './background-analysis';

interface InstantSyncResult {
  success: boolean;
  jobId: string;
  message: string;
  contactsStored: number;
  aiAnalysisQueued: boolean;
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
 * Starts an instant sync that stores contacts immediately (< 1 minute)
 * and queues AI analysis as a background job
 */
export async function startInstantSync(
  facebookPageId: string,
  userId: string
): Promise<InstantSyncResult> {
  const startTime = Date.now();
  
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
        contactsStored: 0,
        aiAnalysisQueued: false,
      };
    }

    // Create a new sync job
    const syncJob = await prisma.syncJob.create({
      data: {
        facebookPageId,
        status: 'IN_PROGRESS',
        startedAt: new Date(),
      },
    });

    console.log(`[Instant Sync ${syncJob.id}] 🚀 Starting instant sync...`);

    // Get page info
    const page = await prisma.facebookPage.findUnique({
      where: { id: facebookPageId },
      select: {
        id: true,
        pageId: true,
        pageAccessToken: true,
        instagramAccountId: true,
        organizationId: true,
      },
    });

    if (!page) {
      throw new Error('Facebook page not found');
    }

    const client = new FacebookClient(page.pageAccessToken);
    let contactsStored = 0;
    const contactIds: string[] = [];
    const errors: Array<{ platform: string; id: string; error: string }> = [];

    // Phase 1: Fast contact storage (NO AI ANALYSIS)
    try {
      // Fetch Messenger conversations
      console.log(`[Instant Sync ${syncJob.id}] Fetching Messenger conversations...`);
      const messengerConvos = await client.getMessengerConversations(page.pageId);
      console.log(`[Instant Sync ${syncJob.id}] Found ${messengerConvos.length} Messenger conversations`);

      // Collect unique participants
      const participantMap = new Map<string, { updatedTime: string; name?: string }>();
      for (const convo of messengerConvos) {
        if (!convo.participants?.data) continue;
        
        for (const participant of convo.participants.data) {
          if (participant.id === page.pageId) continue;
          
          const existing = participantMap.get(participant.id);
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            participantMap.set(participant.id, {
              updatedTime: convo.updated_time,
              name: participant.name,
            });
          }
        }
      }

      const participants = Array.from(participantMap.entries());
      console.log(`[Instant Sync ${syncJob.id}] Processing ${participants.length} Messenger participants...`);

      // Batch fetch existing contacts
      const participantIds = participants.map(([id]) => id);
      const existingContacts = await prisma.contact.findMany({
        where: {
          messengerPSID: { in: participantIds },
          facebookPageId: page.id,
        },
        select: { id: true, messengerPSID: true },
      });

      const existingMap = new Map(existingContacts.map(c => [c.messengerPSID!, c.id]));

      // Process contacts in parallel (fast storage, no AI)
      const contactLimiter = new ConcurrencyLimiter(100); // High concurrency for fast storage
      const BATCH_SIZE = 100;

      for (let i = 0; i < participants.length; i += BATCH_SIZE) {
        const batch = participants.slice(i, i + BATCH_SIZE);
        
        await Promise.all(
          batch.map(([participantId, info]) =>
            contactLimiter.execute(async () => {
              try {
                // Extract name
                let firstName = `User ${participantId.slice(-6)}`;
                let lastName: string | null = null;

                if (info.name) {
                  const nameParts = info.name.trim().split(' ');
                  firstName = nameParts[0] || firstName;
                  if (nameParts.length > 1) {
                    lastName = nameParts.slice(1).join(' ');
                  }
                }

                // Store contact (NO AI ANALYSIS)
                const existingId = existingMap.get(participantId);
                let savedContact;

                if (existingId) {
                  savedContact = await prisma.contact.update({
                    where: { id: existingId },
                    data: {
                      firstName,
                      lastName,
                      lastInteraction: new Date(info.updatedTime),
                      hasMessenger: true,
                    },
                  });
                } else {
                  savedContact = await prisma.contact.create({
                    data: {
                      messengerPSID: participantId,
                      firstName,
                      lastName,
                      hasMessenger: true,
                      organizationId: page.organizationId,
                      facebookPageId: page.id,
                      lastInteraction: new Date(info.updatedTime),
                    },
                  });
                }

                contactIds.push(savedContact.id);
                contactsStored++;
              } catch (error) {
                console.error(`[Instant Sync ${syncJob.id}] Failed to store contact ${participantId}:`, error);
                errors.push({
                  platform: 'Messenger',
                  id: participantId,
                  error: error instanceof Error ? error.message : 'Unknown error',
                });
              }
            })
          )
        );

        // Update progress
        await prisma.syncJob.update({
          where: { id: syncJob.id },
          data: {
            syncedContacts: contactsStored,
            totalContacts: participants.length,
          },
        });
      }

      console.log(`[Instant Sync ${syncJob.id}] ✅ Stored ${contactsStored} Messenger contacts`);
    } catch (error) {
      console.error(`[Instant Sync ${syncJob.id}] Failed to fetch Messenger conversations:`, error);
      errors.push({
        platform: 'Messenger',
        id: 'conversations',
        error: error instanceof Error ? error.message : 'Failed to fetch conversations',
      });
    }

    // Handle Instagram if connected
    if (page.instagramAccountId) {
      try {
        console.log(`[Instant Sync ${syncJob.id}] Fetching Instagram conversations...`);
        const igConvos = await client.getInstagramConversations(page.instagramAccountId);
        console.log(`[Instant Sync ${syncJob.id}] Found ${igConvos.length} Instagram conversations`);

        // Collect unique participants
        const igParticipantMap = new Map<string, { updatedTime: string; name?: string }>();
        for (const convo of igConvos) {
          if (!convo.participants?.data) continue;
          
          for (const participant of convo.participants.data) {
            if (participant.id === page.instagramAccountId) continue;
            
            const existing = igParticipantMap.get(participant.id);
            if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
              igParticipantMap.set(participant.id, {
                updatedTime: convo.updated_time,
                name: participant.name,
              });
            }
          }
        }

        const igParticipants = Array.from(igParticipantMap.entries());
        console.log(`[Instant Sync ${syncJob.id}] Processing ${igParticipants.length} Instagram participants...`);

        // Batch fetch existing contacts
        const igParticipantIds = igParticipants.map(([id]) => id);
        const existingIgContacts = await prisma.contact.findMany({
          where: {
            OR: [
              { instagramSID: { in: igParticipantIds }, facebookPageId: page.id },
              { messengerPSID: { in: igParticipantIds }, facebookPageId: page.id },
            ],
          },
          select: { id: true, instagramSID: true, messengerPSID: true },
        });

        const existingIgMap = new Map<string, string>();
        for (const contact of existingIgContacts) {
          const id = contact.instagramSID || contact.messengerPSID;
          if (id) existingIgMap.set(id, contact.id);
        }

        // Process Instagram contacts
        const igContactLimiter = new ConcurrencyLimiter(100);
        const IG_BATCH_SIZE = 100;

        for (let i = 0; i < igParticipants.length; i += IG_BATCH_SIZE) {
          const batch = igParticipants.slice(i, i + IG_BATCH_SIZE);
          
          await Promise.all(
            batch.map(([participantId, info]) =>
              igContactLimiter.execute(async () => {
                try {
                  // Extract name
                  let firstName = `IG User ${participantId.slice(-6)}`;
                  let lastName: string | null = null;

                  if (info.name) {
                    const nameParts = info.name.trim().split(' ');
                    firstName = nameParts[0] || firstName;
                    if (nameParts.length > 1) {
                      lastName = nameParts.slice(1).join(' ');
                    }
                  }

                  // Store contact (NO AI ANALYSIS)
                  const existingId = existingIgMap.get(participantId);
                  let savedContact;

                  if (existingId) {
                    savedContact = await prisma.contact.update({
                      where: { id: existingId },
                      data: {
                        instagramSID: participantId,
                        firstName,
                        lastName,
                        hasInstagram: true,
                        lastInteraction: new Date(info.updatedTime),
                      },
                    });
                  } else {
                    savedContact = await prisma.contact.create({
                      data: {
                        instagramSID: participantId,
                        firstName,
                        lastName,
                        hasInstagram: true,
                        organizationId: page.organizationId,
                        facebookPageId: page.id,
                        lastInteraction: new Date(info.updatedTime),
                      },
                    });
                  }

                  contactIds.push(savedContact.id);
                  contactsStored++;
                } catch (error) {
                  console.error(`[Instant Sync ${syncJob.id}] Failed to store IG contact ${participantId}:`, error);
                  errors.push({
                    platform: 'Instagram',
                    id: participantId,
                    error: error instanceof Error ? error.message : 'Unknown error',
                  });
                }
              })
            )
          );

          // Update progress
          await prisma.syncJob.update({
            where: { id: syncJob.id },
            data: {
              syncedContacts: contactsStored,
            },
          });
        }

        console.log(`[Instant Sync ${syncJob.id}] ✅ Stored ${contactsStored} total contacts (including Instagram)`);
      } catch (error) {
        console.error(`[Instant Sync ${syncJob.id}] Failed to fetch Instagram conversations:`, error);
        errors.push({
          platform: 'Instagram',
          id: 'conversations',
          error: error instanceof Error ? error.message : 'Failed to fetch conversations',
        });
      }
    }

    // Update last synced time
    await prisma.facebookPage.update({
      where: { id: page.id },
      data: { lastSyncedAt: new Date() },
    });

    // Phase 2: Queue AI analysis as background job
    let aiAnalysisQueued = false;
    if (contactIds.length > 0) {
      try {
        console.log(`[Instant Sync ${syncJob.id}] 🧠 Queuing AI analysis for ${contactIds.length} contacts...`);
        await startBackgroundAnalysis(
          contactIds,
          page.organizationId,
          userId
        );
        aiAnalysisQueued = true;
        console.log(`[Instant Sync ${syncJob.id}] ✅ AI analysis queued successfully`);
      } catch (error) {
        console.error(`[Instant Sync ${syncJob.id}] Failed to queue AI analysis:`, error);
        // Don't fail the sync if AI queueing fails
      }
    }

    // Mark sync as completed
    await prisma.syncJob.update({
      where: { id: syncJob.id },
      data: {
        status: 'COMPLETED',
        syncedContacts: contactsStored,
        totalContacts: contactsStored,
        failedContacts: errors.length,
        errors: errors.length > 0 ? errors : Prisma.JsonNull,
        completedAt: new Date(),
      },
    });

    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[Instant Sync ${syncJob.id}] ✅ Completed in ${elapsedTime}s: ${contactsStored} contacts stored, AI analysis queued: ${aiAnalysisQueued}`);

    return {
      success: true,
      jobId: syncJob.id,
      message: `Synced ${contactsStored} contacts in ${elapsedTime}s`,
      contactsStored,
      aiAnalysisQueued,
    };
  } catch (error) {
    console.error('Failed to start instant sync:', error);
    throw error;
  }
}

