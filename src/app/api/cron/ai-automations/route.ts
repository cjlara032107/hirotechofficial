import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { safePrismaOperation, handlePrismaError } from '@/lib/prisma-error-handler';
import { acquireCronLock, getCronStaggerDelay } from '@/lib/cron-lock';
import { generateFollowUpMessage } from '@/lib/ai/google-ai-service';
import { FacebookClient } from '@/lib/facebook/client';
import { isContactEligibleForAutomation } from '@/lib/ai/conflict-prevention';

// Cron job that runs every minute
export async function GET(request: NextRequest) {
  try {
    // Verify cron secret if set (security for production)
    const authHeader = request.headers.get('authorization');
    if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
      console.log('[AI Automations Cron] Unauthorized request');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Stagger cron job execution to prevent simultaneous pool access
    const staggerDelay = getCronStaggerDelay('ai-automations');
    await new Promise(resolve => setTimeout(resolve, staggerDelay));

    // Acquire database lock to prevent simultaneous cron job access across instances
    const releaseLock = await acquireCronLock('ai-automations');
    
    if (!releaseLock) {
      console.log('[AI Automations Cron] Another instance is running, skipping...');
      return NextResponse.json({
        success: true,
        skipped: true,
        rulesProcessed: 0,
        totalSent: 0,
        totalFailed: 0,
        message: 'Another instance is processing',
      });
    }
    
    try {
      console.log('[AI Automations Cron] Starting execution...');
      const startTime = Date.now();

      console.log('[AI Automations Cron] Multi-DB enabled:', process.env.ENABLE_MULTI_DB === 'true');
      console.log('[AI Automations Cron] DB routing strategy:', process.env.DB_ROUTING_STRATEGY || 'hash');

      // Get all enabled automation rules (with automatic retry and error handling)
      const rules = await safePrismaOperation(
      () => prisma.aIAutomationRule.findMany({
        where: {
          enabled: true,
        },
        include: {
          FacebookPage: true,
          User: {
            select: {
              id: true,
              organizationId: true,
            },
          },
        },
      }),
      { operationName: 'find automation rules', maxRetries: 5 }
    );

    if (rules.length === 0) {
      console.log('[AI Automations Cron] No enabled rules found');
      return NextResponse.json({ 
        success: true, 
        rulesProcessed: 0,
        totalSent: 0,
        totalFailed: 0,
      });
    }

    console.log(`[AI Automations Cron] Processing ${rules.length} enabled rules`);

    let totalSent = 0;
    let totalFailed = 0;

    // Process each rule
    for (const rule of rules) {
      try {
        const now = new Date();
        const currentHour = now.getHours();

        // ⭐ MULTI-DB ROUTING: Get Prisma client for this rule's organization
        const db = getPrismaForOrg(rule.User.organizationId);
        
        // Log routing information for this rule
        console.log(`[AI Automations Cron] Processing rule "${rule.name}" (${rule.id})`);
        console.log(`[AI Automations Cron] Organization: ${rule.User.organizationId}`);
        
        // Log routed DB details if multi-DB is enabled
        if (process.env.ENABLE_MULTI_DB === 'true') {
          try {
            const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
            const router = getDatabaseRouter();
            const client = router.getClient(rule.User.organizationId);
            const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
            
            if (dbConfig) {
              const dbHost = new URL(dbConfig.url).hostname;
              console.log(`[AI Automations Cron] Rule "${rule.name}" routed to DB${dbConfig.index} (${dbHost}) - Health: ${dbConfig.health}`);
            }
          } catch (error) {
            console.warn(`[AI Automations Cron] Could not log routing details for rule "${rule.name}":`, error);
          }
        }

        // Check active hours (skip if outside active hours and not running 24/7)
        if (!rule.run24_7) {
          if (rule.activeHoursEnd > rule.activeHoursStart) {
            // Normal range (e.g., 9 AM to 9 PM)
            if (currentHour < rule.activeHoursStart || currentHour >= rule.activeHoursEnd) {
              console.log(`[AI Automations Cron] Rule "${rule.name}" outside active hours (${rule.activeHoursStart}-${rule.activeHoursEnd})`);
              continue;
            }
          } else {
            // Crosses midnight (e.g., 9 PM to 9 AM next day)
            if (currentHour >= rule.activeHoursEnd && currentHour < rule.activeHoursStart) {
              console.log(`[AI Automations Cron] Rule "${rule.name}" outside active hours (${rule.activeHoursStart}-${rule.activeHoursEnd})`);
              continue;
            }
          }
        }

        // Check daily limit
        const todayStart = new Date(now);
        todayStart.setHours(0, 0, 0, 0);

        const todayExecutions = await safePrismaOperation(
          () => db.aIAutomationExecution.findMany({
            where: {
              ruleId: rule.id,
              executedAt: {
                gte: todayStart,
              },
              status: 'sent',
            },
          }),
          { operationName: 'find today executions' }
        );

        if (todayExecutions.length >= rule.maxMessagesPerDay) {
          console.log(`[AI Automations Cron] Rule "${rule.name}" reached daily limit (${rule.maxMessagesPerDay})`);
          continue;
        }

        const remainingQuota = rule.maxMessagesPerDay - todayExecutions.length;
        console.log(`[AI Automations Cron] Rule "${rule.name}" - ${remainingQuota} messages remaining today`);

        // Calculate time threshold
        const thresholdMs =
          (rule.timeIntervalDays || 0) * 24 * 60 * 60 * 1000 +
          (rule.timeIntervalHours || 0) * 60 * 60 * 1000 +
          (rule.timeIntervalMinutes || 0) * 60 * 1000;

        // Check if rule was executed recently (respect user-set time interval)
        // 24/7 mode: respects user-set time interval (no 1-hour minimum)
        // Regular mode: respects user-set time interval
        if (rule.lastExecutedAt && thresholdMs > 0) {
          const timeSinceLastExecution = now.getTime() - rule.lastExecutedAt.getTime();
          
          if (timeSinceLastExecution < thresholdMs) {
            const remainingTime = thresholdMs - timeSinceLastExecution;
            const remainingMinutes = Math.ceil(remainingTime / (60 * 1000));
            if (rule.run24_7) {
              console.log(`[AI Automations Cron] Rule "${rule.name}" (24/7 mode) executed recently. Waiting ${remainingMinutes} more minutes before next execution (time interval: ${Math.round(thresholdMs / (60 * 1000))} min).`);
            } else {
              console.log(`[AI Automations Cron] Rule "${rule.name}" executed recently. Waiting ${remainingMinutes} more minutes before next execution.`);
            }
            continue;
          }
        }

        const thresholdDate = new Date(now.getTime() - thresholdMs);

        // Build where clause for finding eligible contacts
        // Using Record for flexible Prisma where clause
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const whereClause: Record<string, any> = {
          organizationId: rule.User.organizationId,
          lastInteraction: {
            lte: thresholdDate,
          },
          messengerPSID: {
            not: null,
          },
        };

        // Filter by Facebook page if specified
        if (rule.facebookPageId) {
          whereClause.facebookPageId = rule.facebookPageId;
        }

        // Filter by tags if specified
        if (rule.includeTags.length > 0) {
          whereClause.tags = {
            hasSome: rule.includeTags,
          };
        }

        // Pagination: Process contacts in batches to handle large numbers efficiently
        // Batch size: Process 20 contacts per cron run (adjustable)
        const BATCH_SIZE = 20;
        const batchSize = Math.min(BATCH_SIZE, remainingQuota);
        
        // Filter out contacts that have been stopped for this rule
        // Contacts are stopped if: stopOnReply is enabled and they replied, OR user removed the tag
        const stoppedContactIds = await db.aIAutomationStop.findMany({
          where: {
            ruleId: rule.id,
          },
          select: {
            contactId: true,
          },
        });

        const stoppedIds = stoppedContactIds.map(s => s.contactId);

        // Only exclude stopped contacts from the query
        // We will check time interval per-contact later to allow re-processing after interval
        if (stoppedIds.length > 0) {
          whereClause.id = {
            notIn: stoppedIds,
          };
        }

        // Debug: Check total contacts matching basic criteria
        const totalMatchingContacts = await db.contact.count({
          where: {
            organizationId: rule.User.organizationId,
            messengerPSID: { not: null },
            ...(rule.facebookPageId && { facebookPageId: rule.facebookPageId }),
            ...(rule.includeTags.length > 0 && {
              tags: { hasSome: rule.includeTags },
            }),
          },
        });
        console.log(`[AI Automations Cron] Rule "${rule.name}" - Total contacts matching basic criteria: ${totalMatchingContacts}`);
        
        // Additional debug: Check contacts matching lastInteraction criteria
        const contactsMatchingTimeThreshold = await db.contact.count({
          where: {
            organizationId: rule.User.organizationId,
            messengerPSID: { not: null },
            lastInteraction: { lte: thresholdDate },
            ...(rule.facebookPageId && { facebookPageId: rule.facebookPageId }),
          },
        });
        console.log(`[AI Automations Cron] Rule "${rule.name}" - Contacts matching time threshold (lastInteraction <= ${thresholdDate.toISOString()}): ${contactsMatchingTimeThreshold}`);

        // Get total count of eligible contacts (after all filters except per-contact time interval check)
        const totalEligibleCount = await db.contact.count({
          where: whereClause,
        });

        console.log(`[AI Automations Cron] Rule "${rule.name}" - Found ${totalEligibleCount} potentially eligible contacts (excluding ${stoppedIds.length} stopped, time interval check will be done per-contact)`);

        // Get eligible contacts with pagination
        // Use select to avoid issues with new columns that may not exist yet
        let eligibleContacts = await db.contact.findMany({
          where: whereClause,
          select: {
            id: true,
            firstName: true,
            lastName: true,
            messengerPSID: true,
            instagramSID: true,
            tags: true,
            lastInteraction: true,
            aiContext: true,
            facebookPageId: true,
            organizationId: true,
            facebookPage: {
              select: {
                id: true,
                pageId: true,
                pageName: true,
                pageAccessToken: true,
                instagramAccountId: true,
              },
            },
            conversations: {
              where: {
                platform: 'MESSENGER',
              },
              orderBy: {
                lastMessageAt: 'desc',
              },
              take: 1,
              select: {
                id: true,
                lastMessageAt: true,
                platform: true,
              },
            },
          },
          take: batchSize, // Process in batches
          orderBy: {
            lastInteraction: 'asc', // Process oldest first
          },
        });

        // Exclude contacts with excluded tags (client-side filter as Prisma doesn't support complex tag filtering)
        if (rule.excludeTags.length > 0) {
          eligibleContacts = eligibleContacts.filter(contact => {
            return !rule.excludeTags.some(tag => contact.tags.includes(tag));
          });
        }

        if (eligibleContacts.length === 0) {
          console.log(`[AI Automations Cron] Rule "${rule.name}" - No eligible contacts in this batch`);
          continue;
        }

        console.log(`[AI Automations Cron] Rule "${rule.name}" - Processing batch of ${eligibleContacts.length} contacts (${totalEligibleCount} total eligible)`);

        let ruleSent = 0;
        let ruleFailed = 0;

        // Check for contacts that were just processed recently (prevent race conditions with manual triggers)
        // Use the rule's time interval as the cooldown, with a minimum of 2 minutes
        const cooldownMs = Math.max(thresholdMs, 2 * 60 * 1000); // At least 2 minutes
        const recentExecutionCutoff = new Date(now.getTime() - cooldownMs);
        const recentlyProcessedContacts = await db.aIAutomationExecution.findMany({
          where: {
            ruleId: rule.id,
            contactId: { in: eligibleContacts.map(c => c.id) },
            status: 'sent',
            executedAt: {
              gte: recentExecutionCutoff,
            },
          },
          select: {
            contactId: true,
          },
        });

        const recentlyProcessedContactIds = new Set(recentlyProcessedContacts.map(e => e.contactId));
        const contactsToProcess = eligibleContacts.filter(c => !recentlyProcessedContactIds.has(c.id));

        if (recentlyProcessedContactIds.size > 0) {
          const cooldownMinutes = Math.ceil(cooldownMs / (60 * 1000));
          console.log(`[AI Automations Cron] Rule "${rule.name}" - Skipping ${recentlyProcessedContactIds.size} contacts that were processed in the last ${cooldownMinutes} minutes`);
        }

        // Concurrency limiter for parallel processing
        class ConcurrencyLimiter {
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
        
        // Get dynamic concurrency limit based on API keys
        const { getCachedConcurrencyLimits } = await import('@/lib/ai/dynamic-concurrency');
        const concurrencyLimits = await getCachedConcurrencyLimits();
        const automationLimiter = new ConcurrencyLimiter(concurrencyLimits.automationConcurrency);
        
        console.log(`[AI Automations Cron] Rule "${rule.name}" - Using ${concurrencyLimits.automationConcurrency} concurrent automations (${concurrencyLimits.keyCount} API keys)`);

        // Process all contacts in parallel with concurrency limit
        const results = await Promise.allSettled(
          contactsToProcess.map(contact =>
            automationLimiter.execute(async () => {
              try {
                console.log(`[AI Automations Cron] Processing contact: ${contact.firstName} (${contact.id})`);
                
                // ⭐ SAFETY CHECK: Verify contact is not stopped for this rule
                // This is a double-check in case the initial filter missed something
                const isStopped = await db.aIAutomationStop.findUnique({
                  where: {
                    ruleId_contactId: {
                      ruleId: rule.id,
                      contactId: contact.id,
                    },
                  },
                });

                if (isStopped) {
                  console.log(`[AI Automations Cron] Contact ${contact.id} is stopped for rule "${rule.name}" (reason: ${isStopped.stoppedReason}) - skipping`);
                  return { success: false, reason: 'stopped' };
                }

                // ⭐ STOP-ON-REPLY: Check if THIS SPECIFIC CONTACT has replied AFTER we sent them automation messages
                // This stops automation ONLY for the contact who replied, not for other contacts
                // This is a backup check in case webhook didn't fire
                // Only check if rule has stopOnReply enabled
                console.log(`[AI Automations Cron] Checking stopOnReply for contact ${contact.id} - rule "${rule.name}" has stopOnReply: ${rule.stopOnReply}`);
                if (rule.stopOnReply) {
                  console.log(`[AI Automations Cron] Rule "${rule.name}" has stopOnReply enabled - checking if contact ${contact.id} replied`);
                  // Get the last execution (automation message sent) for THIS SPECIFIC CONTACT and rule
                  const lastExecution = await db.aIAutomationExecution.findFirst({
                    where: {
                      contactId: contact.id, // THIS SPECIFIC CONTACT ONLY
                      ruleId: rule.id,
                      status: 'sent',
                    },
                    orderBy: {
                      executedAt: 'desc',
                    },
                    select: {
                      executedAt: true,
                    },
                  });

                  // If we've sent messages to THIS SPECIFIC CONTACT, check if THEY replied
                  if (lastExecution) {
                    console.log(`[AI Automations Cron] Found last execution for contact ${contact.id} at ${lastExecution.executedAt.toISOString()}`);
                    // Check if THIS SPECIFIC CONTACT replied AFTER we sent them the last automation message
                    const replyAfterAutomation = await db.message.findFirst({
                      where: {
                        contactId: contact.id, // THIS SPECIFIC CONTACT ONLY
                        isFromBusiness: false, // Only check messages FROM the contact (not from business)
                        createdAt: {
                          gt: lastExecution.executedAt, // Reply must be AFTER the automation message
                        },
                      },
                      orderBy: {
                        createdAt: 'desc',
                      },
                    });

                    console.log(`[AI Automations Cron] Contact ${contact.id} - Last execution: ${lastExecution.executedAt.toISOString()}, Reply found: ${replyAfterAutomation ? replyAfterAutomation.createdAt.toISOString() : 'NONE'}`);

                    // If THIS SPECIFIC CONTACT replied after we sent them a message, stop automation FOR THIS CONTACT ONLY
                    if (replyAfterAutomation) {
                      const timeSinceReply = now.getTime() - replyAfterAutomation.createdAt.getTime();
                      const minutesSinceReply = Math.floor(timeSinceReply / (60 * 1000));
                      console.log(`[AI Automations Cron] ⚠️ CONTACT ${contact.id} (${contact.firstName}) replied ${minutesSinceReply} minutes ago - STOPPING automation for THIS CONTACT ONLY (rule: "${rule.name}")`);
                    
                      try {
                        // Check if stop record already exists for THIS SPECIFIC CONTACT
                        const existingStop = await db.aIAutomationStop.findUnique({
                          where: {
                            ruleId_contactId: {
                              ruleId: rule.id,
                              contactId: contact.id, // THIS SPECIFIC CONTACT ONLY
                            },
                          },
                        });

                        if (existingStop) {
                          // THIS CONTACT already has a stop record - skip sending to THIS CONTACT
                          console.log(`[AI Automations Cron] Contact ${contact.id} (${contact.firstName}) already has stop record for rule "${rule.name}" - skipping THIS CONTACT`);
                          return { success: false, reason: 'already_stopped' };
                        }

                        // Count follow-ups sent to THIS SPECIFIC CONTACT
                        const executions = await db.aIAutomationExecution.findMany({
                          where: {
                            contactId: contact.id, // THIS SPECIFIC CONTACT ONLY
                            ruleId: rule.id,
                            status: 'sent',
                          },
                        });

                        // Create stop record FOR THIS SPECIFIC CONTACT ONLY
                        await db.aIAutomationStop.create({
                          data: {
                            id: `stop_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                            ruleId: rule.id,
                            contactId: contact.id, // THIS SPECIFIC CONTACT ONLY
                            recipientPSID: contact.messengerPSID || 'unknown',
                            stoppedReason: 'User replied to automated message (detected by cron fallback)',
                            followUpsSent: executions.length,
                          },
                        });

                        console.log(`[AI Automations Cron] ✅ STOPPED automation for CONTACT ${contact.id} (${contact.firstName}) ONLY - rule "${rule.name}" will no longer send messages to THIS CONTACT`);

                        // Remove tag from THIS SPECIFIC CONTACT if configured
                        if (rule.removeTagOnReply) {
                          const contactData = await db.contact.findUnique({
                            where: { id: contact.id }, // THIS SPECIFIC CONTACT ONLY
                            select: { tags: true },
                          });

                          if (contactData && contactData.tags.includes(rule.removeTagOnReply)) {
                            await db.contact.update({
                              where: { id: contact.id }, // THIS SPECIFIC CONTACT ONLY
                              data: {
                                tags: contactData.tags.filter(tag => tag !== rule.removeTagOnReply),
                              },
                            });
                            console.log(`[AI Automations Cron] Removed tag "${rule.removeTagOnReply}" from contact ${contact.id} (${contact.firstName})`);
                          }
                        }

                        // Skip THIS CONTACT - do not send any more messages to THIS CONTACT
                        return { success: false, reason: 'stopped_after_reply' };
                      } catch (error) {
                        console.error(`[AI Automations Cron] Error creating stop record for contact ${contact.id}:`, error);
                      }
                    }
                  }
                }
                
                // Check if this contact was processed by THIS rule within the time interval
                // Only skip if they were processed recently - otherwise process them again
                if (thresholdMs > 0) {
                  const lastExecution = await db.aIAutomationExecution.findFirst({
                    where: {
                      ruleId: rule.id,
                      contactId: contact.id,
                      status: 'sent',
                    },
                    orderBy: {
                      executedAt: 'desc',
                    },
                    select: {
                      executedAt: true,
                    },
                  });

                  if (lastExecution) {
                    const timeSinceLastExecution = now.getTime() - lastExecution.executedAt.getTime();
                    if (timeSinceLastExecution < thresholdMs) {
                      const minutesRemaining = Math.ceil((thresholdMs - timeSinceLastExecution) / (60 * 1000));
                      console.log(`[AI Automations Cron] Contact ${contact.id} processed ${Math.round(timeSinceLastExecution / (60 * 1000))} min ago, waiting ${minutesRemaining} more minutes (time interval: ${Math.round(thresholdMs / (60 * 1000))} min)`);
                      return { success: false, reason: 'too_soon' };
                    }
                  }
                }
                
                // ⭐ CONFLICT PREVENTION: Check if contact is eligible
                // Skip the recent contact check since we handle it per-rule above
                const eligibilityCheck = await isContactEligibleForAutomation(
                  contact.id,
                  rule.excludeTags,
                  { 
                    skipRecentContactCheck: true // We check per-rule time interval above
                  }
                );

                if (!eligibilityCheck.eligible) {
                  console.log(`[AI Automations Cron] Contact ${contact.id} not eligible: ${eligibilityCheck.reason}`);
                  return { success: false, reason: 'not_eligible', details: eligibilityCheck.reason };
                }

                const conversation = contact.conversations[0];
                if (!conversation) {
                  console.log(`[AI Automations Cron] No conversation for contact: ${contact.id}`);
                  return { success: false, reason: 'no_conversation' };
                }

                // Get conversation history
                const messages = await db.message.findMany({
                  where: {
                    conversationId: conversation.id,
                  },
                  orderBy: {
                    createdAt: 'desc',
                  },
                  take: 20,
                });

                // Handle conversations with no messages
                if (messages.length === 0) {
                  console.log(`[AI Automations Cron] No messages in conversation: ${conversation.id}`);
                  return { success: false, reason: 'no_messages' };
                }

                // Filter out system messages (isFromBusiness = true)
                const { filterSystemMessagesFromDB } = await import('@/lib/facebook/message-filtering');
                const userMessages = filterSystemMessagesFromDB(messages);

                // Handle conversations with only system messages
                if (userMessages.length === 0) {
                  console.log(`[AI Automations Cron] No user messages in conversation (only system messages): ${conversation.id}`);
                  return { success: false, reason: 'no_user_messages' };
                }

                // Check if contact replied recently (live check) - using filtered user messages
                const recentContactMessages = userMessages;
                console.log(`[AI Automations Cron] Contact ${contact.id} - Total messages: ${messages.length}, User messages: ${recentContactMessages.length}, System messages: ${messages.length - recentContactMessages.length}`);
                
                if (recentContactMessages.length > 0) {
                  const lastContactMessage = recentContactMessages[0];
                  const timeSinceReply = now.getTime() - lastContactMessage.createdAt.getTime();
                  
                  // If contact replied within last hour, check if we need to create stop record
                  if (timeSinceReply < 60 * 60 * 1000) {
                    // ⭐ STOP-ON-REPLY: If rule has stopOnReply enabled, create stop record
                    if (rule.stopOnReply) {
                      // Check if we've sent messages to this contact from this rule
                      const hasExecutions = await db.aIAutomationExecution.findFirst({
                        where: {
                          contactId: contact.id,
                          ruleId: rule.id,
                          status: 'sent',
                        },
                      });

                      if (hasExecutions) {
                        // Check if stop record already exists
                        const existingStop = await db.aIAutomationStop.findUnique({
                          where: {
                            ruleId_contactId: {
                              ruleId: rule.id,
                              contactId: contact.id,
                            },
                          },
                        });

                        if (!existingStop) {
                          // Count follow-ups sent
                          const executions = await db.aIAutomationExecution.findMany({
                            where: {
                              contactId: contact.id,
                              ruleId: rule.id,
                              status: 'sent',
                            },
                          });

                          // Create stop record
                          await db.aIAutomationStop.create({
                            data: {
                              id: `stop_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                              ruleId: rule.id,
                              contactId: contact.id,
                              recipientPSID: contact.messengerPSID || 'unknown',
                              stoppedReason: 'User replied to automated message (detected in conversation check)',
                              followUpsSent: executions.length,
                            },
                          });

                          console.log(`[AI Automations Cron] ✅ STOPPED automation for CONTACT ${contact.id} (${contact.firstName}) - rule "${rule.name}" - contact replied ${Math.floor(timeSinceReply / (60 * 1000))} minutes ago`);

                          // Remove tag if configured
                          if (rule.removeTagOnReply) {
                            const contactData = await db.contact.findUnique({
                              where: { id: contact.id },
                              select: { tags: true },
                            });

                            if (contactData && contactData.tags.includes(rule.removeTagOnReply)) {
                              await db.contact.update({
                                where: { id: contact.id },
                                data: {
                                  tags: contactData.tags.filter(tag => tag !== rule.removeTagOnReply),
                                },
                              });
                              console.log(`[AI Automations Cron] Removed tag "${rule.removeTagOnReply}" from contact ${contact.id}`);
                            }
                          }
                        } else {
                          console.log(`[AI Automations Cron] Contact ${contact.id} already has stop record for rule "${rule.name}"`);
                        }
                      }
                    }
                    
                    console.log(`[AI Automations Cron] Contact ${contact.id} replied recently (${Math.floor(timeSinceReply / (60 * 1000))} min ago), skipping`);
                    return { success: false, reason: 'replied_recently' };
                  }
                }

                // Format messages for AI
                // Format messages for AI (only user messages, already filtered above)
                const conversationHistory = userMessages.reverse().map(msg => ({
                  from: contact.firstName || 'Customer',
                  text: msg.content,
                  timestamp: msg.createdAt,
                }));

                // Generate AI message
                const aiResult = await generateFollowUpMessage(
                  contact.firstName || 'there',
                  conversationHistory,
                  rule.customPrompt,
                  rule.languageStyle
                );

                if (!aiResult) {
                  console.error(`[AI Automations Cron] Failed to generate message for contact: ${contact.id}`);
                  
                  // Log execution failure
                  await db.aIAutomationExecution.create({
                    data: {
                      id: `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                      ruleId: rule.id,
                      userId: rule.userId,
                      contactId: contact.id,
                      conversationId: conversation.id,
                      recipientPSID: contact.messengerPSID || 'unknown',
                      recipientName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
                      aiPromptUsed: rule.customPrompt,
                      status: 'failed',
                      errorMessage: 'Failed to generate AI message',
                      executedAt: new Date(),
                    },
                  });
                  
                  return { success: false, reason: 'ai_generation_failed' };
                }

                // Send message via Facebook
                const facebookClient = new FacebookClient(contact.facebookPage.pageAccessToken);
                const result = await facebookClient.sendMessengerMessage({
                  recipientId: contact.messengerPSID!,
                  message: aiResult.message,
                  messageTag: rule.messageTag || 'ACCOUNT_UPDATE',
                });

                if (result.success) {
                  // Log successful execution
                  await db.aIAutomationExecution.create({
                    data: {
                      id: `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                      ruleId: rule.id,
                      userId: rule.userId,
                      contactId: contact.id,
                      conversationId: conversation.id,
                      recipientPSID: contact.messengerPSID || 'unknown',
                      recipientName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
                      aiPromptUsed: rule.customPrompt,
                      generatedMessage: aiResult.message,
                      aiReasoning: aiResult.reasoning,
                      // eslint-disable-next-line @typescript-eslint/no-explicit-any
                      previousMessages: conversationHistory as any,
                      status: 'sent',
                      facebookMessageId: result.data?.message_id,
                      executedAt: new Date(),
                    },
                  });

                  // Save message to database
                  await db.message.create({
                    data: {
                      content: aiResult.message,
                      platform: 'MESSENGER',
                      status: 'SENT',
                      messageTag: rule.messageTag || 'ACCOUNT_UPDATE',
                      facebookMessageId: result.data?.message_id,
                      contactId: contact.id,
                      conversationId: conversation.id,
                      isFromBusiness: true,
                      sentAt: new Date(),
                    },
                  });

                  console.log(`[AI Automations Cron] Sent message to ${contact.firstName}`);
                  return { success: true };
                } else {
                  // Log execution failure
                  await db.aIAutomationExecution.create({
                    data: {
                      id: `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                      ruleId: rule.id,
                      userId: rule.userId,
                      contactId: contact.id,
                      conversationId: conversation.id,
                      recipientPSID: contact.messengerPSID || 'unknown',
                      recipientName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
                      aiPromptUsed: rule.customPrompt,
                      generatedMessage: aiResult.message,
                      aiReasoning: aiResult.reasoning,
                      status: 'failed',
                      errorMessage: result.error || 'Unknown error',
                      executedAt: new Date(),
                    },
                  });
                  
                  console.error(`[AI Automations Cron] Failed to send message: ${result.error}`);
                  return { success: false, reason: 'send_failed', error: result.error };
                }
              } catch (error) {
                console.error(`[AI Automations Cron] Error processing contact ${contact.id}:`, error);
                return { success: false, reason: 'error', error: error instanceof Error ? error.message : String(error) };
              }
            })
          )
        );

        // Count successes and failures from parallel results
        for (const result of results) {
          if (result.status === 'fulfilled' && result.value.success) {
            ruleSent++;
          } else {
            ruleFailed++;
          }
        }

        // Update rule statistics
        if (ruleSent > 0 || ruleFailed > 0) {
          await db.aIAutomationRule.update({
            where: { id: rule.id },
            data: {
              lastExecutedAt: now,
              executionCount: { increment: 1 },
              successCount: { increment: ruleSent },
              failureCount: { increment: ruleFailed },
              updatedAt: new Date(),
            },
          });

          console.log(`[AI Automations Cron] Rule "${rule.name}" complete: ${ruleSent} sent, ${ruleFailed} failed`);
        }

        totalSent += ruleSent;
        totalFailed += ruleFailed;
      } catch (error) {
        console.error(`[AI Automations Cron] Error processing rule ${rule.id}:`, error);
      }
    }

    const duration = Date.now() - startTime;
    console.log(`[AI Automations Cron] Execution complete in ${duration}ms: ${totalSent} sent, ${totalFailed} failed`);

      return NextResponse.json({
        success: true,
        rulesProcessed: rules.length,
        totalSent,
        totalFailed,
        duration,
      });
    } finally {
      // Always release lock
      await releaseLock();
    }
  } catch (error) {
    console.error('[AI Automations Cron] Fatal error:', error);
    const { message, status } = handlePrismaError(error, 'Failed to execute automation cron job');
    return NextResponse.json(
      { error: message },
      { status }
    );
  }
}

// Allow POST as well for manual testing
export async function POST(request: NextRequest) {
  return GET(request);
}

