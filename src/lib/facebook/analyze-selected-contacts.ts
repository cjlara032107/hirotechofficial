import { prisma } from '@/lib/db';
import { FacebookClient } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { analyzeConversation } from '@/lib/ai/google-ai-service';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { extractContactInfo } from '@/lib/ai/contact-info-extraction';
import { analyzeReplyTimes } from '@/lib/ai/reply-time-analyzer';

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

interface AnalyzeSelectedContactsResult {
  successCount: number;
  failedCount: number;
  errors: Array<{ contactId: string; error: string }>;
}

/**
 * Analyzes selected contacts by fetching their conversations and assigning to pipeline
 */
export async function analyzeSelectedContacts(
  contactIds: string[],
  organizationId: string,
  onProgress?: (analyzed: number, failed: number, total: number) => void
): Promise<AnalyzeSelectedContactsResult> {
  // Use atomic counters to avoid race conditions
  let successCount = 0;
  let failedCount = 0;
  const errors: Array<{ contactId: string; error: string }> = [];
  const overallStartTime = Date.now();
  let batchStartTime: number | undefined;
  
  // Helper to safely increment and call progress callback
  const incrementSuccess = () => {
    successCount++;
    if (onProgress) {
      onProgress(successCount, failedCount, contactIds.length);
    }
  };
  
  const incrementFailed = (error: string, contactId: string) => {
    failedCount++;
    errors.push({ contactId, error });
    if (onProgress) {
      onProgress(successCount, failedCount, contactIds.length);
    }
  };

  console.log(`[Analyze Selected] 🚀 Starting analysis for ${contactIds.length} contacts at ${new Date().toISOString()}`);
  console.log(`[Analyze Selected] Contact IDs received:`, contactIds);

  // CRITICAL VALIDATION: Ensure we're not accidentally analyzing all contacts
  if (contactIds.length > 50) {
    console.error(`[Analyze Selected] 🚨 WARNING: Received ${contactIds.length} contacts! This might be an error.`);
    console.error(`[Analyze Selected] Contact IDs:`, contactIds);
    console.error(`[Analyze Selected] If user only selected 1 contact, this is a BUG!`);
  }
  
  // ADDITIONAL VALIDATION: Log the exact count to help debug
  if (contactIds.length === 1) {
    console.log(`[Analyze Selected] ✅ Processing exactly 1 contact - this is correct for single selection`);
    console.log(`[Analyze Selected] Contact ID: ${contactIds[0]}`);
  } else {
    console.log(`[Analyze Selected] ⚠️ Processing ${contactIds.length} contacts - ensure this matches user's selection`);
  }

  // CRITICAL: Validate contactIds array before querying
  if (!Array.isArray(contactIds) || contactIds.length === 0) {
    console.error('[Analyze Selected] 🚨 CRITICAL: Invalid contactIds array!', contactIds);
    return { successCount: 0, failedCount: 0, errors: [] };
  }
  
  // CRITICAL: If only 1 contact ID provided, ensure we only fetch 1 contact
  if (contactIds.length === 1) {
    console.log(`[Analyze Selected] 🔒 SINGLE CONTACT MODE: Fetching exactly 1 contact from database`);
    console.log(`[Analyze Selected] Contact ID to fetch: ${contactIds[0]}`);
  }

  // Fetch contacts with their Facebook page info
  const contacts = await prisma.contact.findMany({
    where: {
      id: { in: contactIds },
      organizationId,
    },
    include: {
      facebookPage: {
        include: {
          autoPipeline: {
            include: {
              stages: { orderBy: { order: 'asc' } }
            }
          }
        }
      }
    },
  });

  // CRITICAL VALIDATION: Verify we fetched the correct number of contacts
  if (contactIds.length === 1 && contacts.length !== 1) {
    console.error(`[Analyze Selected] 🚨 CRITICAL BUG: Requested 1 contact but fetched ${contacts.length}!`);
    console.error(`[Analyze Selected] Requested ID: ${contactIds[0]}`);
    console.error(`[Analyze Selected] Fetched contacts:`, contacts.map(c => c.id));
    if (contacts.length > 1) {
      console.error(`[Analyze Selected] 🚨 This is a database query bug - returning only the requested contact`);
      // Filter to only the requested contact
      const requestedContact = contacts.find(c => c.id === contactIds[0]);
      if (requestedContact) {
        return await analyzeSelectedContacts([requestedContact.id], organizationId, onProgress);
      }
    }
  }

  if (contacts.length === 0) {
    console.warn(`[Analyze Selected] No contacts found for provided IDs:`, contactIds);
    return { successCount: 0, failedCount: 0, errors: [] };
  }
  
  // CRITICAL: If we requested N contacts but got more, something is wrong
  if (contacts.length > contactIds.length) {
    console.error(`[Analyze Selected] 🚨 CRITICAL: Requested ${contactIds.length} contacts but fetched ${contacts.length}!`);
    console.error(`[Analyze Selected] Requested IDs:`, contactIds);
    console.error(`[Analyze Selected] Fetched contact IDs:`, contacts.map(c => c.id));
    console.error(`[Analyze Selected] Filtering to only requested contacts`);
    // Filter to only the requested contacts
    const requestedContacts = contacts.filter(c => contactIds.includes(c.id));
    if (requestedContacts.length !== contactIds.length) {
      console.error(`[Analyze Selected] 🚨 Still have mismatch after filtering!`);
      console.error(`[Analyze Selected] Requested: ${contactIds.length}, Filtered: ${requestedContacts.length}`);
    }
    // Continue with filtered contacts
    const filteredContactIds = requestedContacts.map(c => c.id);
    return await analyzeSelectedContacts(filteredContactIds, organizationId, onProgress);
  }
  
  console.log(`[Analyze Selected] ✅ Fetched ${contacts.length} contact(s) matching ${contactIds.length} requested ID(s)`);

  // Group contacts by Facebook page (to reuse client and conversations)
  const contactsByPage = new Map<string, typeof contacts>();
  for (const contact of contacts) {
    const pageId = contact.facebookPageId;
    if (!contactsByPage.has(pageId)) {
      contactsByPage.set(pageId, []);
    }
    contactsByPage.get(pageId)!.push(contact);
  }

  // Process each page's contacts
  for (const [, pageContacts] of contactsByPage) {
    const page = pageContacts[0].facebookPage;
    
    const hasAutoPipeline = page.autoPipelineId && page.autoPipeline;
    
    if (!hasAutoPipeline) {
      console.log(`[Analyze Selected] Page ${page.pageName} has no auto-pipeline configured (autoPipelineId: ${page.autoPipelineId || 'null'}), will analyze without pipeline assignment`);
      console.log(`[Analyze Selected] To enable pipeline assignment, go to Settings → Facebook Pages → ${page.pageName} → Configure Auto-Pipeline`);
    } else {
      console.log(`[Analyze Selected] Page ${page.pageName} has auto-pipeline configured: ${page.autoPipeline?.name || 'Unknown'} (ID: ${page.autoPipelineId})`);
    }

    const client = new FacebookClient(page.pageAccessToken);

    // Build list of participant IDs we need to find
    const neededParticipantIds = new Set<string>();
    for (const contact of pageContacts) {
      if (contact.messengerPSID) neededParticipantIds.add(contact.messengerPSID);
      if (contact.instagramSID) neededParticipantIds.add(contact.instagramSID);
    }

    // Fetch conversations incrementally, stopping when we find all needed participants
    console.log(`[Analyze Selected] Fetching conversations for page ${page.pageName} (looking for ${neededParticipantIds.size} participants)...`);
    const messengerConvos = await client.getMessengerConversationsUntilFound(
      page.pageId,
      neededParticipantIds
    );
    console.log(`[Analyze Selected] Fetched ${messengerConvos.length} Messenger conversations (stopped early when all participants found)`);
    
    // Create conversation maps - only for participants we need
    const messengerConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    let foundCount = 0;
    for (const convo of messengerConvos) {
      // Early exit if we've found all needed participants
      if (foundCount >= neededParticipantIds.size) {
        console.log(`[Analyze Selected] Found all ${foundCount} participants, skipping remaining conversations`);
        break;
      }

      for (const participant of convo.participants.data) {
        if (participant.id !== page.pageId && neededParticipantIds.has(participant.id)) {
          const existing = messengerConversationMap.get(participant.id);
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            messengerConversationMap.set(participant.id, {
              conversationId: convo.id,
              updatedTime: convo.updated_time,
            });
            if (!existing) foundCount++;
          }
        }
      }
    }
    console.log(`[Analyze Selected] Found conversations for ${messengerConversationMap.size} Messenger participants`);

    // Fetch Instagram conversations if connected - only for needed participants
    const instagramConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    if (page.instagramAccountId) {
      try {
        const igConvos = await client.getInstagramConversationsUntilFound(
          page.instagramAccountId,
          neededParticipantIds
        );
        console.log(`[Analyze Selected] Fetched ${igConvos.length} Instagram conversations (stopped early when all participants found)`);
        let igFoundCount = 0;
        for (const convo of igConvos) {
          // Early exit if we've found all needed participants
          if (igFoundCount >= neededParticipantIds.size) {
            console.log(`[Analyze Selected] Found all ${igFoundCount} IG participants, skipping remaining conversations`);
            break;
          }

          for (const participant of convo.participants.data) {
            if (participant.id !== page.instagramAccountId && neededParticipantIds.has(participant.id)) {
              const existing = instagramConversationMap.get(participant.id);
              if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
                instagramConversationMap.set(participant.id, {
                  conversationId: convo.id,
                  updatedTime: convo.updated_time,
                });
                if (!existing) igFoundCount++;
              }
            }
          }
        }
        console.log(`[Analyze Selected] Found conversations for ${instagramConversationMap.size} Instagram participants`);
      } catch (error) {
        console.error(`[Analyze Selected] Failed to fetch Instagram conversations:`, error);
      }
    }

    // Process all contacts continuously - each contact completes independently
    // Increased concurrency for maximum speed
    const conversationFetchLimiter = new ConcurrencyLimiter(100); // Very high concurrency for fetching
    const analysisLimiter = new ConcurrencyLimiter(100); // Very high concurrency for AI analysis

    console.log(`[Analyze Selected] Processing ${pageContacts.length} contacts continuously...`);
    batchStartTime = Date.now();

    // Process all contacts in one continuous flow
    await Promise.all(
      pageContacts.map(async (contact) => {
        const contactStartTime = Date.now();
        try {
          // Step 1: Find conversation ID
          let conversationInfo = contact.messengerPSID 
            ? messengerConversationMap.get(contact.messengerPSID)
            : null;

          if (!conversationInfo && contact.instagramSID) {
            conversationInfo = instagramConversationMap.get(contact.instagramSID);
          }

          if (!conversationInfo) {
            incrementFailed('Conversation not found', contact.id);
            return;
          }

          // Step 2: Fetch messages (concurrency limited)
          const messages = await conversationFetchLimiter.execute(async () => {
            try {
              // Use recent messages only (last 20) for faster analysis - optimized for speed
              return await client.getRecentMessagesForConversation(conversationInfo!.conversationId, 20);
            } catch (error) {
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              throw errorMessage;
            }
          });

          if (!messages || messages.length === 0) {
            incrementFailed('No messages found', contact.id);
            return;
          }

          // Step 3: Prepare messages for analysis
          const messagesToAnalyze = messages
            .filter((msg: { message?: string }) => msg.message)
            .map((msg: { 
              from?: { name?: string; username?: string; id?: string }; 
              message?: string; 
              created_time?: string 
            }) => ({
              from: msg.from?.name || msg.from?.username || msg.from?.id || 'Unknown',
              text: msg.message || '',
              timestamp: msg.created_time ? new Date(msg.created_time) : undefined,
              isFromBusiness: msg.from?.id === page.pageId || msg.from?.name?.includes('Page') || false,
            }))
            .reverse();

          if (messagesToAnalyze.length === 0) {
            incrementFailed('No valid messages to analyze', contact.id);
            return;
          }

          // Step 3.5: Extract contact information and analyze reply times (parallel)
          const [contactInfo, replyTimeAnalysis] = await Promise.all([
            // Extract comprehensive contact information
            analysisLimiter.execute(async () => {
              try {
                const info = await extractContactInfo(messagesToAnalyze);
                if (info && Object.keys(info).length > 0) {
                  console.log(`[Analyze Selected] ✅ Successfully extracted contact info for ${contact.id}`);
                  const extractedFields = Object.keys(info).filter(key => {
                    const value = info[key as keyof typeof info];
                    if (Array.isArray(value)) return value.length > 0;
                    if (typeof value === 'object' && value !== null) return Object.keys(value).length > 0;
                    return value !== null && value !== undefined;
                  });
                  if (extractedFields.length > 0) {
                    console.log(`[Analyze Selected] Extracted fields: ${extractedFields.join(', ')}`);
                  }
                }
                return info;
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                console.warn(`[Analyze Selected] Failed to extract contact info for ${contact.id}:`, errorMessage);
                // Don't fail the entire analysis if contact info extraction fails
                return null;
              }
            }),
            // Analyze reply times for best contact times (synchronous, no API calls)
            (() => {
              try {
                const analysis = analyzeReplyTimes(messagesToAnalyze, page.pageId);
                if (analysis) {
                  console.log(`[Analyze Selected] Successfully analyzed reply times for ${contact.id}`);
                }
                return analysis;
              } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                console.warn(`[Analyze Selected] Failed to analyze reply times for ${contact.id}:`, errorMessage);
                // Don't fail the entire analysis if reply time analysis fails
                return null;
              }
            })(),
          ]);

          // Step 4: Analyze with AI (concurrency limited)
          let analysis: { summary: string; leadScore?: number; recommendedStage?: string; leadStatus?: string; confidence?: number; reasoning?: string } | null = null;
          
          if (hasAutoPipeline && page.autoPipeline) {
            // Use pipeline-based analysis with stage recommendation
            const result = await analysisLimiter.execute(async () => {
              return await analyzeWithFallback(
                messagesToAnalyze,
                page.autoPipeline!.stages,
                contact.lastInteraction || undefined
              );
            });
            analysis = result.analysis;
          } else {
            // Use simple analysis without pipeline
            const summary = await analysisLimiter.execute(async () => {
              return await analyzeConversation(messagesToAnalyze);
            });
            
            if (!summary) {
              throw new Error('AI analysis returned no summary');
            }
            
            analysis = {
              summary,
              leadScore: 50, // Default score when no pipeline
              recommendedStage: undefined,
              leadStatus: undefined,
              confidence: undefined,
              reasoning: undefined,
            };
          }
          
          if (!analysis) {
            throw new Error('Analysis failed');
          }

          // Step 5: Update contact with AI context, contact info, and best contact times
          try {
            // Build update data - only include new fields if they exist in database
            // CRITICAL: More thorough check - ensure object has meaningful data, not just keys
            const hasContactInfo = !!contactInfo && (() => {
              if (typeof contactInfo !== 'object' || contactInfo === null) return false;
              const info = contactInfo as Record<string, unknown>;
              
              // Check if any field has actual data
              const hasAge = info.age !== null && info.age !== undefined && typeof info.age === 'number';
              const hasArrays = ['phoneNumbers', 'emails', 'businessNames', 'pageLinks', 
                'facebookPages', 'locations', 'occupations', 'companies', 'websites'].some(field => {
                const value = info[field];
                return Array.isArray(value) && value.length > 0;
              });
              const hasSingles = ['phoneNumber', 'email', 'facebookPage', 'location', 
                'occupation', 'company', 'website'].some(field => {
                const value = info[field];
                return value !== null && value !== undefined && value !== '';
              });
              const hasSocial = info.socialMedia && typeof info.socialMedia === 'object' && 
                Object.values(info.socialMedia).some(v => v !== null && v !== undefined && v !== '' && 
                  (Array.isArray(v) ? v.length > 0 : true));
              const hasOther = info.otherInfo && typeof info.otherInfo === 'object' && 
                Object.keys(info.otherInfo).length > 0;
              
              return hasAge || hasArrays || hasSingles || hasSocial || hasOther;
            })();
            const hasBestContactTimes = !!replyTimeAnalysis;
            const updateData: any = {
              aiContext: analysis.summary,
              aiContextUpdatedAt: new Date(),
            };

            // Only add new fields if they have values (will fail gracefully if columns don't exist)
            if (contactInfo) {
              updateData.contactInfo = contactInfo;
            }
            if (replyTimeAnalysis) {
              updateData.bestContactTimes = replyTimeAnalysis;
            }

            await prisma.contact.update({
              where: { id: contact.id },
              data: updateData,
            });
            
            // Log success if contactInfo was saved
            if (hasContactInfo) {
              console.log(`[Analyze Selected] ✅ Successfully saved contact info for ${contact.id}`);
            }
            if (hasBestContactTimes) {
              console.log(`[Analyze Selected] ✅ Successfully saved best contact times for ${contact.id}`);
            }
          } catch (dbError: unknown) {
            // Handle database connection errors
            const dbErrorObj = dbError as { code?: string; message?: string };
            if (dbErrorObj?.code === 'P1001' || dbErrorObj?.message?.includes("Can't reach database")) {
              console.error(`[Analyze Selected] Database connection error for contact ${contact.id}:`, dbErrorObj.message);
              incrementFailed('Database connection failed. Please try again.', contact.id);
              return; // Skip pipeline assignment if DB update failed
            }
            
            // Handle missing column error (P2022) - try update without new fields
            if (dbErrorObj?.code === 'P2022' || dbErrorObj?.message?.includes('does not exist')) {
              console.warn(`[Analyze Selected] ⚠️ New columns not found in database for contact ${contact.id}, updating without them`);
              
              // CRITICAL: Log if we're losing extracted data
              if (contactInfo && Object.keys(contactInfo).length > 0) {
                console.error(`[Analyze Selected] 🚨 CRITICAL: Contact info was extracted but NOT SAVED due to missing database column!`);
                console.error(`[Analyze Selected] Contact ID: ${contact.id}`);
                console.error(`[Analyze Selected] Extracted contactInfo:`, JSON.stringify(contactInfo, null, 2));
                console.error(`[Analyze Selected] Action required: Run migration (apply-production-migration.sql) to add contactInfo column`);
                console.error(`[Analyze Selected] Migration file: apply-production-migration.sql`);
              }
              if (replyTimeAnalysis) {
                console.error(`[Analyze Selected] 🚨 CRITICAL: Best contact times were analyzed but NOT SAVED due to missing database column!`);
                console.error(`[Analyze Selected] Contact ID: ${contact.id}`);
                console.error(`[Analyze Selected] Action required: Run migration (apply-production-migration.sql) to add bestContactTimes column`);
              }
              
              try {
                // Fallback: update only existing fields
                await prisma.contact.update({
                  where: { id: contact.id },
                  data: {
                    aiContext: analysis.summary,
                    aiContextUpdatedAt: new Date(),
                  },
                });
                console.log(`[Analyze Selected] Successfully updated contact ${contact.id} without new fields`);
                console.warn(`[Analyze Selected] ⚠️ WARNING: Contact info and best contact times were NOT saved. Please run database migration.`);
              } catch (fallbackError) {
                console.error(`[Analyze Selected] Fallback update also failed for contact ${contact.id}:`, fallbackError);
                incrementFailed('Database schema mismatch. Please run migration.', contact.id);
                return;
              }
            } else {
            throw dbError; // Re-throw other errors
            }
          }

          // Step 6: Assign to pipeline (only if auto-pipeline is configured and analysis has required fields)
          if (hasAutoPipeline && page.autoPipelineId) {
            // Check if we have the minimum required fields for pipeline assignment
            const hasLeadScore = analysis.leadScore !== undefined && analysis.leadScore !== null;
            const hasRecommendedStage = analysis.recommendedStage && analysis.recommendedStage.trim().length > 0;
            
            if (!hasLeadScore || !hasRecommendedStage) {
              console.warn(`[Analyze Selected] Missing required fields for pipeline assignment for contact ${contact.id}:`, {
                hasLeadScore,
                leadScore: analysis.leadScore,
                hasRecommendedStage,
                recommendedStage: analysis.recommendedStage,
              });
              // Use fallback values if missing
              const fallbackLeadScore = analysis.leadScore ?? 50;
              const fallbackStage = analysis.recommendedStage || page.autoPipeline?.stages[0]?.name || 'New Lead';
              
              console.log(`[Analyze Selected] Using fallback values: score=${fallbackLeadScore}, stage=${fallbackStage}`);
              
              try {
                await autoAssignContactToPipeline({
                  contactId: contact.id,
                  aiAnalysis: {
                    summary: analysis.summary,
                    leadScore: fallbackLeadScore,
                    recommendedStage: fallbackStage,
                    leadStatus: analysis.leadStatus || 'NEW',
                    confidence: analysis.confidence || 50,
                    reasoning: analysis.reasoning || `AI analysis completed but some fields missing. Score: ${fallbackLeadScore}`,
                  },
                  pipelineId: page.autoPipelineId,
                  updateMode: page.autoPipelineMode,
                });
                console.log(`[Analyze Selected] Successfully assigned contact ${contact.id} to pipeline using fallback values`);
              } catch (fallbackError: unknown) {
                const fallbackErrorObj = fallbackError as { code?: string; message?: string };
                console.error(`[Analyze Selected] Failed to assign contact ${contact.id} to pipeline even with fallback values:`, fallbackErrorObj.message);
                incrementFailed(`Pipeline assignment failed: ${fallbackErrorObj.message || 'Unknown error'}`, contact.id);
              }
            } else {
              // All required fields present - normal assignment
              try {
                await autoAssignContactToPipeline({
                  contactId: contact.id,
                  aiAnalysis: {
                    summary: analysis.summary,
                    leadScore: analysis.leadScore!,
                    recommendedStage: analysis.recommendedStage!,
                    leadStatus: analysis.leadStatus || 'NEW',
                    confidence: analysis.confidence || 50,
                    reasoning: analysis.reasoning || 'AI analysis',
                  },
                  pipelineId: page.autoPipelineId,
                  updateMode: page.autoPipelineMode,
                });
                console.log(`[Analyze Selected] Successfully assigned contact ${contact.id} to pipeline`);
              } catch (pipelineError: unknown) {
                // Handle database connection errors during pipeline assignment
                const pipelineErrorObj = pipelineError as { code?: string; message?: string };
                if (pipelineErrorObj?.code === 'P1001' || pipelineErrorObj?.message?.includes("Can't reach database")) {
                  console.error(`[Analyze Selected] Database connection error during pipeline assignment for contact ${contact.id}:`, pipelineErrorObj.message);
                  // Contact was updated but pipeline assignment failed - still count as partial success
                  incrementFailed('Contact analyzed but pipeline assignment failed due to database connection issue.', contact.id);
                  return;
                }
                console.error(`[Analyze Selected] Pipeline assignment error for contact ${contact.id}:`, pipelineErrorObj.message);
                throw pipelineError; // Re-throw other errors
              }
            }
          } else {
            const reason = !hasAutoPipeline 
              ? `no auto-pipeline configured for page ${page.pageName}` 
              : !page.autoPipelineId 
                ? 'missing pipeline ID' 
                : 'unknown reason';
            console.log(`[Analyze Selected] Skipping pipeline assignment for contact ${contact.id} - ${reason}`);
          }

          const contactDuration = Date.now() - contactStartTime;
          console.log(`[Analyze Selected] ✅ Contact ${contact.id} completed in ${contactDuration}ms`);
          incrementSuccess();
        } catch (error) {
          const contactDuration = Date.now() - contactStartTime;
          const errorMessage = error instanceof Error ? error.message : (typeof error === 'string' ? error : 'Unknown error');
          console.error(`[Analyze Selected] ❌ Contact ${contact.id} failed after ${contactDuration}ms:`, errorMessage);
          incrementFailed(errorMessage, contact.id);
        }
      })
    );
    
    const batchDuration = Date.now() - (batchStartTime || Date.now());
    console.log(`[Analyze Selected] Batch completed in ${batchDuration}ms (${pageContacts.length} contacts)`);
  }

  const totalDuration = Date.now() - overallStartTime;
  console.log(`[Analyze Selected] ✅ Completed: ${successCount} analyzed, ${failedCount} failed in ${totalDuration}ms (${Math.round(totalDuration / 1000)}s)`);
  return { successCount, failedCount, errors };
}

