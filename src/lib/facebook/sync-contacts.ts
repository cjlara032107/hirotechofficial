import { prisma } from '@/lib/db';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { applyStageScoreRanges } from '@/lib/pipelines/stage-analyzer';
import { computeAndStoreBestContactTimes } from '@/lib/contacts/compute-contact-times';

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
        reject 
      });
      this.process();
    });
  }

  private process() {
    if (this.running >= this.limit || this.queue.length === 0) {
      return;
    }

    this.running++;
    const { fn, resolve, reject } = this.queue.shift()!;

    fn()
      .then(resolve)
      .catch(reject)
      .finally(() => {
        this.running--;
        this.process();
      });
  }
}

interface SyncResult {
  success: boolean;
  synced: number;
  failed: number;
  errors: Array<{ platform: string; id: string; error: string; code?: number }>;
  tokenExpired?: boolean;
}

export async function syncContacts(facebookPageId: string): Promise<SyncResult> {
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

  if (!page) throw new Error('Facebook page not found');

  const client = new FacebookClient(page.pageAccessToken);
  let syncedCount = 0;
  let failedCount = 0;
  let tokenExpired = false;
  const errors: Array<{ platform: string; id: string; error: string; code?: number }> = [];

  console.log(`[Sync] Starting contact sync for Facebook Page: ${page.pageId}`);
  console.log('[Auto-Pipeline] Enabled:', !!page.autoPipelineId);
  if (page.autoPipelineId && page.autoPipeline) {
    console.log('[Auto-Pipeline] Target Pipeline:', page.autoPipeline.name);
    console.log('[Auto-Pipeline] Mode:', page.autoPipelineMode);
    console.log('[Auto-Pipeline] Stages:', page.autoPipeline.stages.length);
    
    // Auto-generate score ranges if stages still have defaults
    const hasDefaultRanges = page.autoPipeline.stages.some(
      s => s.leadScoreMin === 0 && s.leadScoreMax === 100
    );
    
    if (hasDefaultRanges) {
      console.log('[Auto-Pipeline] Detected default score ranges, auto-generating intelligent ranges...');
      await applyStageScoreRanges(page.autoPipelineId);
      console.log('[Auto-Pipeline] Score ranges applied successfully');
      
      // Reload page with updated ranges
      const updatedPage = await prisma.facebookPage.findUnique({
        where: { id: page.id },
        include: {
          autoPipeline: {
            include: {
              stages: { orderBy: { order: 'asc' } }
            }
          }
        }
      });
      
      if (updatedPage?.autoPipeline) {
        page.autoPipeline = updatedPage.autoPipeline;
      }
    }
  }

  // Initialize concurrency limiters for batch processing (30-50 concurrent jobs)
  const messageFetchLimiter = new ConcurrencyLimiter(50);
  const analysisLimiter = new ConcurrencyLimiter(100); // Increased to 100 to maximize parallel processing with 20 API keys

  // Sync Messenger contacts
  try {
    console.log('[Sync] Fetching Messenger conversations (with pagination)...');
    const messengerConvos = await client.getMessengerConversations(page.pageId);
    console.log(`[Sync] Fetched ${messengerConvos.length} Messenger conversations`);

    // Step 1: Collect all participants into tasks
    interface MessengerTask {
      participantId: string;
      conversationId: string;
      updatedTime: string;
    }

    const messengerTasks: MessengerTask[] = [];
    for (const convo of messengerConvos) {
      for (const participant of convo.participants.data) {
        if (participant.id !== page.pageId) {
          messengerTasks.push({
            participantId: participant.id,
            conversationId: convo.id,
            updatedTime: convo.updated_time,
          });
        }
      }
    }

    console.log(`[Sync] Processing ${messengerTasks.length} Messenger contacts continuously...`);

    // Process all contacts continuously - each contact completes independently
    await Promise.all(
      messengerTasks.map(async (task) => {
        try {
          // Step 1: Fetch messages (concurrency limited)
          const messages = await messageFetchLimiter.execute(async () => {
            try {
              return await client.getAllMessagesForConversation(task.conversationId);
            } catch (error) {
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              const errorCode = error instanceof FacebookApiError ? error.code : undefined;
              throw { message: errorMessage, code: errorCode };
            }
          });

          // Step 2: Extract name
          let firstName = `User ${task.participantId.slice(-6)}`;
          let lastName: string | null = null;

          if (messages && messages.length > 0) {
            const userMessage = messages.find(
              (msg: { from?: { id?: string; name?: string } }) => msg.from?.id === task.participantId
            );

            if (userMessage?.from?.name) {
              const nameParts = userMessage.from.name.trim().split(' ');
              firstName = nameParts[0] || firstName;
              if (nameParts.length > 1) {
                lastName = nameParts.slice(1).join(' ');
              }
            }
          }

          // Step 3: Analyze with AI (concurrency limited)
          let aiContext: string | null = null;
          let aiAnalysis = null;

          if (messages && messages.length > 0) {
            const messagesToAnalyze = messages
              .filter((msg: { message?: string }) => msg.message)
              .map((msg: { from?: { name?: string; id?: string }; message?: string; created_time?: string }) => ({
                from: msg.from?.name || msg.from?.id || 'Unknown',
                text: msg.message || '',
                timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
              }))
              .reverse();

            if (messagesToAnalyze.length > 0) {
              const { analysis, usedFallback } = await analysisLimiter.execute(async () => {
                return await analyzeWithFallback(
                  messagesToAnalyze,
                  page.autoPipelineId && page.autoPipeline ? page.autoPipeline.stages : undefined,
                  new Date(task.updatedTime)
                );
              });

              aiAnalysis = analysis;
              aiContext = analysis.summary;

              if (usedFallback) {
                console.warn(`[Sync] Used fallback scoring for ${task.participantId} - Score: ${analysis.leadScore}`);
              }
            }
          }

          // Step 4: Save to database (immediate - contact appears in pipeline now)
          const savedContact = await prisma.contact.upsert({
            where: {
              messengerPSID_facebookPageId: {
                messengerPSID: task.participantId,
                facebookPageId: page.id,
              },
            },
            create: {
              messengerPSID: task.participantId,
              firstName: firstName,
              lastName: lastName,
              hasMessenger: true,
              organizationId: page.organizationId,
              facebookPageId: page.id,
              lastInteraction: new Date(task.updatedTime),
              aiContext: aiContext,
              aiContextUpdatedAt: aiContext ? new Date() : null,
            },
            update: {
              firstName: firstName,
              lastName: lastName,
              lastInteraction: new Date(task.updatedTime),
              hasMessenger: true,
              aiContext: aiContext,
              aiContextUpdatedAt: aiContext ? new Date() : null,
            },
          });

          // Step 5: Assign to pipeline (immediate, non-blocking - contact appears in pipeline now)
          if (aiAnalysis && page.autoPipelineId) {
            autoAssignContactToPipeline({
              contactId: savedContact.id,
              aiAnalysis: aiAnalysis,
              pipelineId: page.autoPipelineId,
              updateMode: page.autoPipelineMode,
            }).catch((error) => {
              console.error(`[Auto-Pipeline] Failed to assign contact ${savedContact.id} to pipeline:`, error);
            });
          }

          // Step 6: Compute best contact times (non-blocking, runs in background)
          computeAndStoreBestContactTimes(savedContact.id).catch((error) => {
            console.error(`[BestContactTimes] Failed to compute for contact ${savedContact.id}:`, error);
          });

          syncedCount++;
        } catch (error: unknown) {
          failedCount++;
          const errorMessage = error instanceof Error ? error.message : (typeof error === 'object' && error !== null && 'message' in error ? String(error.message) : 'Unknown error');
          const errorCode = error instanceof FacebookApiError ? error.code : (typeof error === 'object' && error !== null && 'code' in error ? (typeof error.code === 'number' ? error.code : undefined) : undefined);
          
          if (error instanceof FacebookApiError && error.isTokenExpired) {
            tokenExpired = true;
          }
          
          errors.push({
            platform: 'Messenger',
            id: task.participantId,
            error: errorMessage,
            code: errorCode,
          });
        }
      })
    );

    console.log(`[Sync] Messenger contacts complete: ${syncedCount} synced, ${failedCount} failed`);
  } catch (error: unknown) {
    const errorCode = error instanceof FacebookApiError ? error.code : undefined;
    
    // Check if token is expired
    if (error instanceof FacebookApiError && error.isTokenExpired) {
      tokenExpired = true;
    }
    
    console.error('Failed to fetch Messenger conversations:', error);
    errors.push({
      platform: 'Messenger',
      id: 'conversations',
      error: error instanceof Error ? error.message : 'Failed to fetch conversations',
      code: errorCode,
    });
  }

  // Sync Instagram contacts (if connected)
  if (page.instagramAccountId) {
    try {
      console.log('[Sync] Fetching Instagram conversations (with pagination)...');
      const igConvos = await client.getInstagramConversations(page.instagramAccountId);
      console.log(`[Sync] Fetched ${igConvos.length} Instagram conversations`);

      // Step 1: Collect all participants into tasks
      interface InstagramTask {
        participantId: string;
        conversationId: string;
        updatedTime: string;
      }

      const instagramTasks: InstagramTask[] = [];
      for (const convo of igConvos) {
        for (const participant of convo.participants.data) {
          if (participant.id !== page.instagramAccountId) {
            instagramTasks.push({
              participantId: participant.id,
              conversationId: convo.id,
              updatedTime: convo.updated_time,
            });
          }
        }
      }

      console.log(`[Sync] Processing ${instagramTasks.length} Instagram contacts continuously...`);

      // Process all contacts continuously - each contact completes independently
      await Promise.all(
        instagramTasks.map(async (task) => {
          try {
            // Step 1: Fetch messages (concurrency limited)
            const messages = await messageFetchLimiter.execute(async () => {
              try {
                return await client.getAllMessagesForConversation(task.conversationId);
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error';
                const errorCode = error instanceof FacebookApiError ? error.code : undefined;
                throw { message: errorMessage, code: errorCode };
              }
            });

            // Step 2: Extract name
            let firstName = `IG User ${task.participantId.slice(-6)}`;
            let lastName: string | null = null;

            if (messages && messages.length > 0) {
              const userMessage = messages.find(
                (msg: { from?: { id?: string; name?: string; username?: string } }) => msg.from?.id === task.participantId
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

            // Step 3: Analyze with AI (concurrency limited)
            let aiContext: string | null = null;
            let aiAnalysis = null;

            if (messages && messages.length > 0) {
              const messagesToAnalyze = messages
                .filter((msg: { message?: string }) => msg.message)
                .map((msg: { from?: { name?: string; username?: string; id?: string }; message?: string; created_time?: string }) => ({
                  from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
                  text: msg.message || '',
                  timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
                }))
                .reverse();

              if (messagesToAnalyze.length > 0) {
                const { analysis, usedFallback } = await analysisLimiter.execute(async () => {
                  return await analyzeWithFallback(
                    messagesToAnalyze,
                    page.autoPipelineId && page.autoPipeline ? page.autoPipeline.stages : undefined,
                    new Date(task.updatedTime)
                  );
                });

                aiAnalysis = analysis;
                aiContext = analysis.summary;

                if (usedFallback) {
                  console.warn(`[Sync] IG: Used fallback scoring for ${task.participantId} - Score: ${analysis.leadScore}`);
                }
              }
            }

            // Validate Instagram SID format
            const { isValidSID, normalizeContactId, hasValidContactId } = await import('./contact-validation');
            const normalizedId = normalizeContactId(task.participantId);
            if (!normalizedId || !isValidSID(normalizedId)) {
              console.warn(`[Sync] Skipping invalid Instagram SID: ${task.participantId}`);
              failedCount++;
              errors.push({
                platform: 'Instagram',
                id: task.participantId,
                error: 'Invalid Instagram SID format',
                code: undefined,
              });
              return;
            }

            // Step 4: Check if contact exists by Instagram ID or Messenger PSID
            const existingContact = await prisma.contact.findFirst({
              where: {
                OR: [
                  { instagramSID: normalizedId, facebookPageId: page.id },
                  { messengerPSID: normalizedId, facebookPageId: page.id },
                ],
              },
              select: { id: true, messengerPSID: true, instagramSID: true },
            });

            // Step 5: Save to database (immediate - contact appears in pipeline now)
            let savedContact;
            if (existingContact) {
              // Handle contacts with both Messenger and Instagram IDs
              const updateData: {
                instagramSID: string;
                firstName: string;
                lastName: string | null;
                hasInstagram: boolean;
                lastInteraction: Date;
                aiContext: string | null;
                aiContextUpdatedAt: Date | null;
                hasMessenger?: boolean;
                messengerPSID?: string;
              } = {
                instagramSID: normalizedId,
                firstName: firstName,
                lastName: lastName,
                hasInstagram: true,
                lastInteraction: new Date(task.updatedTime),
                aiContext: aiContext,
                aiContextUpdatedAt: aiContext ? new Date() : null,
              };

              // Preserve Messenger ID if contact already has it
              if (existingContact.messengerPSID) {
                updateData.hasMessenger = true;
                updateData.messengerPSID = existingContact.messengerPSID;
              }

              savedContact = await prisma.contact.update({
                where: { id: existingContact.id },
                data: updateData,
              });
            } else {
              // Ensure contact has at least one valid ID before creating
              if (!hasValidContactId(null, normalizedId)) {
                console.warn(`[Sync] Cannot create contact without valid ID: ${normalizedId}`);
                failedCount++;
                errors.push({
                  platform: 'Instagram',
                  id: normalizedId,
                  error: 'Contact must have at least one valid ID',
                  code: undefined,
                });
                return;
              }

              savedContact = await prisma.contact.create({
                data: {
                  instagramSID: normalizedId,
                  firstName: firstName,
                  lastName: lastName,
                  hasInstagram: true,
                  organizationId: page.organizationId,
                  facebookPageId: page.id,
                  lastInteraction: new Date(task.updatedTime),
                  aiContext: aiContext,
                  aiContextUpdatedAt: aiContext ? new Date() : null,
                },
              });
            }

            // Step 6: Assign to pipeline (immediate, non-blocking - contact appears in pipeline now)
            if (aiAnalysis && page.autoPipelineId) {
              autoAssignContactToPipeline({
                contactId: savedContact.id,
                aiAnalysis: aiAnalysis,
                pipelineId: page.autoPipelineId,
                updateMode: page.autoPipelineMode,
              }).catch((error) => {
                console.error(`[Auto-Pipeline] Failed to assign IG contact ${savedContact.id} to pipeline:`, error);
              });
            }

            // Step 7: Compute best contact times (non-blocking, runs in background)
            computeAndStoreBestContactTimes(savedContact.id).catch((error) => {
              console.error(`[BestContactTimes] Failed to compute for IG contact ${savedContact.id}:`, error);
            });

            syncedCount++;
          } catch (error: unknown) {
            failedCount++;
            const errorMessage = error instanceof Error ? error.message : (typeof error === 'object' && error !== null && 'message' in error ? String(error.message) : 'Unknown error');
            const errorCode = error instanceof FacebookApiError ? error.code : (typeof error === 'object' && error !== null && 'code' in error ? (typeof error.code === 'number' ? error.code : undefined) : undefined);
            
            if (error instanceof FacebookApiError && error.isTokenExpired) {
              tokenExpired = true;
            }
            
            errors.push({
              platform: 'Instagram',
              id: task.participantId,
              error: errorMessage,
              code: errorCode,
            });
          }
        })
      );

      console.log(`[Sync] Instagram contacts complete: ${syncedCount} synced, ${failedCount} failed`);
    } catch (error: unknown) {
      const errorCode = error instanceof FacebookApiError ? error.code : undefined;
      
      // Check if token is expired
      if (error instanceof FacebookApiError && error.isTokenExpired) {
        tokenExpired = true;
      }
      
      console.error('Failed to fetch Instagram conversations:', error);
      errors.push({
        platform: 'Instagram',
        id: 'conversations',
        error: error instanceof Error ? error.message : 'Failed to fetch conversations',
        code: errorCode,
      });
    }
  }

  // Update last synced time only if sync was at least partially successful
  if (syncedCount > 0 || !tokenExpired) {
    await prisma.facebookPage.update({
      where: { id: page.id },
      data: { lastSyncedAt: new Date() },
    });
  }

  console.log(`[Sync] Sync completed: ${syncedCount} synced, ${failedCount} failed${tokenExpired ? ' (Token expired)' : ''}`);

  return {
    success: true,
    synced: syncedCount,
    failed: failedCount,
    errors,
    tokenExpired,
  };
}


