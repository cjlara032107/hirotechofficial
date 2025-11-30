/**
 * Streaming processor with adaptive chunking, progress updates, and error handling
 * Processes conversations as they stream in, adjusting chunk size based on processing speed
 */

import { prisma } from '@/lib/db';
import { FacebookClient, FacebookApiError } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { computeAndStoreBestContactTimes } from '@/lib/contacts/compute-contact-times';

interface ParticipantTask {
  participantId: string;
  conversationId: string;
  updatedTime: string;
}

interface ProcessChunkOptions {
  jobId: string;
  chunk: ParticipantTask[];
  chunkIndex: number;
  page: any;
  existingContactsMap: Map<string, { 
    id: string; 
    pipelineId: string | null;
    lastInteraction: Date | null;
    aiContextUpdatedAt: Date | null;
  }>;
  messageFetchLimiter: any;
  analysisLimiter: any;
  cancellationSignal: AbortSignal;
  client: FacebookClient;
  syncedCount: { value: number };
  failedCount: { value: number };
  errors: Array<{ platform: string; id: string; error: string; code?: number }>;
  tokenExpired: { value: boolean };
}

/**
 * Process a chunk of participants with error handling
 * Returns processing time in milliseconds for adaptive chunking
 */
export async function processChunkWithErrorHandling(
  options: ProcessChunkOptions
): Promise<number> {
  const {
    jobId,
    chunk,
    chunkIndex,
    page,
    existingContactsMap,
    messageFetchLimiter,
    analysisLimiter,
    cancellationSignal,
    client,
    syncedCount,
    failedCount,
    errors,
    tokenExpired,
  } = options;

  const chunkStartTime = Date.now();
  
  try {
    // Check if cancelled
    if (cancellationSignal.aborted) {
      throw new Error('Sync cancelled by user');
    }

    console.log(`[Background Sync ${jobId}] Processing chunk ${chunkIndex + 1} (${chunk.length} contacts)...`);

    // Step 1: Fetch messages for this chunk (with error handling per contact)
    const messageResults = await Promise.allSettled(
      chunk.map(task =>
        messageFetchLimiter.execute(async () => {
          try {
            const existing = existingContactsMap.get(task.participantId);
            
            // Check cancellation before fetching messages
            if (cancellationSignal.aborted) {
              throw new Error('Sync cancelled');
            }

            // Fetch recent messages (200) for AI analysis
            const messages = await Promise.race([
              client.getRecentMessagesForConversation(task.conversationId, 200, cancellationSignal),
              new Promise<any[]>((_, reject) => {
                const timeoutId = setTimeout(() => reject(new Error(`Timeout: Fetching messages for conversation ${task.conversationId} took longer than 15 seconds`)), 15000);
                cancellationSignal.addEventListener('abort', () => {
                  clearTimeout(timeoutId);
                  reject(new Error('Sync cancelled'));
                }, { once: true });
              })
            ]);
            return { task, messages, error: null, existing };
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const errorCode = error instanceof FacebookApiError ? error.code : undefined;
            console.warn(`[Background Sync ${jobId}] Failed to fetch messages for conversation ${task.conversationId}: ${errorMessage}`);
            return { task, messages: null, error: { message: errorMessage, code: errorCode }, existing: undefined };
          }
        })
      )
    );

    // Check cancellation after message fetching, before analysis
    if (cancellationSignal.aborted) {
      throw new Error('Sync cancelled after message fetch');
    }

    // Step 2: Analyze this chunk (with error handling per contact)
    const analysisResults = await Promise.allSettled(
      messageResults.map((result, idx) => {
        if (result.status === 'rejected') {
          // Use the correct task from the chunk
          const task = chunk[idx];
          return Promise.resolve({ status: 'fulfilled' as const, value: { task, processed: null, error: { message: result.reason?.message || 'Unknown error', code: undefined } } });
        }
        const { task, messages, error, existing } = result.value;
        
        return analysisLimiter.execute(async () => {
          if (error) {
            return { task, processed: null, error };
          }

          if (!messages || messages.length === 0) {
            return {
              task,
              processed: {
                participantId: task.participantId,
                firstName: `User ${task.participantId.slice(-6)}`,
                lastName: null,
                aiContext: null,
                aiAnalysis: null,
                lastInteraction: new Date(task.updatedTime),
                skipAI: false,
              },
              error: null,
              messages: null, // No messages available
            };
          }

          try {
            // Extract name
            let firstName = `User ${task.participantId.slice(-6)}`;
            let lastName: string | null = null;

            const userMessage = messages.find(
              (msg: { from?: { id?: string } }) => msg.from?.id === task.participantId
            );

            if (userMessage?.from?.name) {
              const nameParts = userMessage.from.name.trim().split(' ');
              firstName = nameParts[0] || firstName;
              if (nameParts.length > 1) {
                lastName = nameParts.slice(1).join(' ');
              }
            }

            // Skip AI analysis if conversation hasn't changed since last analysis
            const conversationUpdatedTime = new Date(task.updatedTime);
            const shouldSkipAI = existing?.aiContextUpdatedAt && 
                               conversationUpdatedTime <= existing.aiContextUpdatedAt;
            
            let aiContext: string | null = null;
            let aiAnalysis = null;
            
            if (shouldSkipAI && existing?.aiContextUpdatedAt) {
              console.log(`[Background Sync ${jobId}] Skipping AI analysis for ${task.participantId} - conversation unchanged since ${existing.aiContextUpdatedAt.toISOString()}`);
              aiContext = null;
              aiAnalysis = null;
            } else {
              // Analyze with AI
              const messagesToAnalyze = messages
                .filter((msg: { message?: string }) => msg.message)
                .map((msg: { from?: { name?: string; id?: string }; message?: string; created_time?: string }) => ({
                  from: msg.from?.name || msg.from?.id || 'Unknown',
                  text: msg.message || '',
                  timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
                }))
                .reverse(); // Oldest first

              if (messagesToAnalyze.length > 0) {
                // Check cancellation before AI analysis
                if (cancellationSignal.aborted) {
                  throw new Error('Sync cancelled before AI analysis');
                }

                const { analysis, usedFallback } = await analyzeWithFallback(
                  messagesToAnalyze,
                  page.autoPipelineId && page.autoPipeline ? page.autoPipeline.stages : undefined,
                  new Date(task.updatedTime)
                );
                
                // Check cancellation after AI analysis
                if (cancellationSignal.aborted) {
                  throw new Error('Sync cancelled after AI analysis');
                }
                
                aiAnalysis = analysis;
                aiContext = analysis.summary;
                
                if (usedFallback) {
                  console.warn(`[Background Sync ${jobId}] Used fallback scoring for ${task.participantId} - Score: ${analysis.leadScore}`);
                }
              }
            }

            return {
              task,
              processed: {
                participantId: task.participantId,
                firstName,
                lastName,
                aiContext,
                aiAnalysis,
                lastInteraction: new Date(task.updatedTime),
                skipAI: shouldSkipAI,
              },
              error: null,
              messages, // Include messages so we can save them later
            };
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return { task, processed: null, error: { message: errorMessage, code: undefined }, messages: null };
          }
        });
      })
    );

    // Check cancellation after analysis, before database update
    if (cancellationSignal.aborted) {
      throw new Error('Sync cancelled after analysis');
    }

    // Step 3: Save this chunk to database (with error handling per contact)
    await Promise.allSettled(
      analysisResults.map((result) => {
        // Check cancellation before each database update
        if (cancellationSignal.aborted) {
          return Promise.resolve(null);
        }
        if (result.status === 'rejected') {
          return Promise.resolve({ status: 'fulfilled' as const, value: null });
        }
        const resolved = result.value.status === 'fulfilled' ? result.value.value : null;
        if (!resolved) {
          return Promise.resolve(null);
        }
        const { task, processed, error, messages } = resolved;
        
        if (error || !task) {
          failedCount.value++;
          if (task) {
            errors.push({
              platform: 'Messenger',
              id: task.participantId,
              error: error?.message || 'Unknown error',
              code: error?.code,
            });
            if (error?.code === 190) {
              tokenExpired.value = true;
            }
          }
          return Promise.resolve(null);
        }

        if (!processed) {
          return Promise.resolve(null);
        }

        // Preserve existing AI context if we skipped analysis
        const updateData: any = {
          firstName: processed.firstName,
          lastName: processed.lastName,
          lastInteraction: processed.lastInteraction,
          hasMessenger: true,
        };
        
        // Only update AI context if we actually analyzed (not skipped)
        if (!processed.skipAI) {
          updateData.aiContext = processed.aiContext;
          updateData.aiContextUpdatedAt = processed.aiContext ? new Date() : null;
        }
        
        return prisma.contact
          .upsert({
            where: {
              messengerPSID_facebookPageId: {
                messengerPSID: task.participantId,
                facebookPageId: page.id,
              },
            },
            create: {
              messengerPSID: task.participantId,
              firstName: processed.firstName,
              lastName: processed.lastName,
              hasMessenger: true,
              organizationId: page.organizationId,
              facebookPageId: page.id,
              lastInteraction: processed.lastInteraction,
              aiContext: processed.aiContext,
              aiContextUpdatedAt: processed.aiContext ? new Date() : null,
            },
            update: updateData,
          })
          .then(async (savedContact) => {
            // Save messages to database if we have them
            if (messages && messages.length > 0 && !error) {
              try {
                console.log(`[Background Sync ${jobId}] Saving ${messages.length} messages for contact ${savedContact.id}`);
                
                // Find or create conversation
                let conversation = await prisma.conversation.findFirst({
                  where: {
                    contactId: savedContact.id,
                    platform: 'MESSENGER',
                  },
                });

                if (!conversation) {
                  conversation = await prisma.conversation.create({
                    data: {
                      contactId: savedContact.id,
                      facebookPageId: page.id,
                      platform: 'MESSENGER',
                      status: 'OPEN',
                      lastMessageAt: new Date(task.updatedTime),
                    },
                  });
                  console.log(`[Background Sync ${jobId}] Created conversation ${conversation.id} for contact ${savedContact.id}`);
                } else {
                  console.log(`[Background Sync ${jobId}] Found existing conversation ${conversation.id} for contact ${savedContact.id}`);
                }

                // Prepare messages for bulk insert
                const messagesToSave = messages
                  .filter((msg: any) => {
                    // Only save messages with content and timestamp
                    if (!msg.message && !msg.attachments) {
                      return false; // Skip messages without content or attachments
                    }
                    if (!msg.created_time) {
                      return false; // Skip messages without timestamp
                    }
                    return true;
                  })
                  .map((msg: any) => {
                    // Determine if message is from business (page) or contact
                    // Messages from the page itself are from business, messages from the participant are from contact
                    const isFromBusiness = msg.from?.id === page.pageId;
                    const createdAt = new Date(msg.created_time);
                    
                    return {
                      contactId: savedContact.id,
                      conversationId: conversation.id,
                      content: msg.message || msg.attachments ? '[Media]' : '[No content]',
                      platform: 'MESSENGER',
                      facebookMessageId: msg.id,
                      isFromBusiness,
                      status: 'DELIVERED',
                      createdAt,
                      sentAt: createdAt,
                      deliveredAt: createdAt,
                    };
                  });

                // Save messages in batches to avoid overwhelming the database
                if (messagesToSave.length > 0) {
                  const BATCH_SIZE = 100;
                  let savedCount = 0;
                  
                  // Check which messages already exist (by facebookMessageId) to avoid duplicates
                  const messageIds = messagesToSave
                    .map((m: { facebookMessageId?: string }) => m.facebookMessageId)
                    .filter((id: string | undefined): id is string => !!id);
                  
                  const existingMessages = messageIds.length > 0
                    ? await prisma.message.findMany({
                        where: {
                          facebookMessageId: { in: messageIds },
                          conversationId: conversation.id,
                        },
                        select: { facebookMessageId: true },
                      })
                    : [];
                  
                  const existingIds = new Set(
                    existingMessages
                      .map(m => m.facebookMessageId)
                      .filter((id): id is string => !!id)
                  );
                  
                  // Filter out messages that already exist
                  const newMessagesToSave = messagesToSave.filter(
                    (msg: { facebookMessageId?: string }) => !msg.facebookMessageId || !existingIds.has(msg.facebookMessageId)
                  );
                  
                  console.log(`[Background Sync ${jobId}] ${newMessagesToSave.length} new messages to save (${existingIds.size} already exist)`);
                  
                  for (let i = 0; i < newMessagesToSave.length; i += BATCH_SIZE) {
                    const batch = newMessagesToSave.slice(i, i + BATCH_SIZE);
                    try {
                      await prisma.message.createMany({
                        data: batch,
                      });
                      savedCount += batch.length;
                    } catch (batchError) {
                      // If batch fails, try individual inserts
                      console.warn(`[Background Sync ${jobId}] Batch insert failed, trying individual inserts:`, batchError);
                      for (const msg of batch) {
                        try {
                          await prisma.message.create({
                            data: msg,
                          });
                          savedCount++;
                        } catch (individualError: any) {
                          // Log but continue - message might already exist
                          console.warn(`[Background Sync ${jobId}] Failed to save individual message (may already exist):`, individualError?.message);
                        }
                      }
                    }
                  }
                  
                  // Update conversation's lastMessageAt to the most recent message
                  if (savedCount > 0 && messagesToSave.length > 0) {
                    const mostRecentMessage = messagesToSave.reduce((latest: { createdAt: Date }, msg: { createdAt: Date }) => {
                      return msg.createdAt > latest.createdAt ? msg : latest;
                    });
                    await prisma.conversation.update({
                      where: { id: conversation.id },
                      data: { lastMessageAt: mostRecentMessage.createdAt },
                    });
                  }
                  
                  console.log(`[Background Sync ${jobId}] Saved ${savedCount} messages for contact ${savedContact.id}`);
                }
              } catch (msgError) {
                // Log but don't fail the sync if message saving fails
                console.error(`[Background Sync ${jobId}] Failed to save messages for contact ${savedContact.id}:`, msgError);
              }
            }

            // Auto-assign to pipeline if enabled
            if (processed.aiAnalysis && page.autoPipelineId) {
              await autoAssignContactToPipeline({
                contactId: savedContact.id,
                aiAnalysis: processed.aiAnalysis,
                pipelineId: page.autoPipelineId,
                updateMode: page.autoPipelineMode,
              });
            }
            // Compute best contact times (non-blocking, runs in background)
            computeAndStoreBestContactTimes(savedContact.id).catch((error) => {
              console.error(`[BestContactTimes] Failed to compute for contact ${savedContact.id}:`, error);
            });
            syncedCount.value++;
            return savedContact;
          })
          .catch((err) => {
            failedCount.value++;
            const errorMessage = err instanceof Error ? err.message : 'Unknown error';
            const errorCode = err instanceof FacebookApiError ? err.code : undefined;
            errors.push({
              platform: 'Messenger',
              id: task.participantId,
              error: errorMessage,
              code: errorCode,
            });
            if (err instanceof FacebookApiError && err.isTokenExpired) {
              tokenExpired.value = true;
            }
            return null;
          });
      })
    );

    // Update progress after each chunk (per-chunk progress updates)
    const { updateSyncJobProgress } = await import('./pipeline-analyzer/update-progress');
    await updateSyncJobProgress(jobId, {
      syncedContacts: syncedCount.value,
      failedContacts: failedCount.value,
    }).catch(() => {}); // Non-blocking

    const chunkProcessingTime = Date.now() - chunkStartTime;
    const contactsPerSecond = chunk.length / (chunkProcessingTime / 1000);
    
    console.log(`[Background Sync ${jobId}] Chunk ${chunkIndex + 1} complete: ${syncedCount.value} synced, ${failedCount.value} failed (${contactsPerSecond.toFixed(2)} contacts/sec)`);

    return chunkProcessingTime;
  } catch (chunkError) {
    // Chunk-level error handling: Log but continue processing
    console.error(`[Background Sync ${jobId}] Chunk ${chunkIndex + 1} failed:`, chunkError);
    
    // Mark all contacts in this chunk as failed
    for (const task of chunk) {
      failedCount.value++;
      errors.push({
        platform: 'Messenger',
        id: task.participantId,
        error: chunkError instanceof Error ? chunkError.message : 'Chunk processing failed',
        code: undefined,
      });
    }

    // Update progress even on chunk failure
    const { updateSyncJobProgress } = await import('./pipeline-analyzer/update-progress');
    await updateSyncJobProgress(jobId, {
      syncedContacts: syncedCount.value,
      failedContacts: failedCount.value,
    }).catch(() => {}); // Non-blocking

    // Return processing time even on failure (for adaptive chunking)
    return Date.now() - chunkStartTime;
  }
}

/**
 * Calculate adaptive chunk size based on processing speed
 */
export function calculateAdaptiveChunkSize(
  currentChunkSize: number,
  chunkProcessingTimes: number[],
  minChunkSize: number = 10,
  maxChunkSize: number = 200
): number {
  if (chunkProcessingTimes.length < 3) {
    return currentChunkSize; // Need at least 3 samples
  }

  const avgTime = chunkProcessingTimes.reduce((a, b) => a + b, 0) / chunkProcessingTimes.length;
  const avgContactsPerSecond = currentChunkSize / (avgTime / 1000);

  // If processing is fast (>2 contacts/sec), increase chunk size
  if (avgContactsPerSecond > 2 && currentChunkSize < maxChunkSize) {
    return Math.min(maxChunkSize, Math.floor(currentChunkSize * 1.2));
  }
  // If processing is slow (<0.5 contacts/sec), decrease chunk size
  else if (avgContactsPerSecond < 0.5 && currentChunkSize > minChunkSize) {
    return Math.max(minChunkSize, Math.floor(currentChunkSize * 0.8));
  }

  return currentChunkSize;
}

