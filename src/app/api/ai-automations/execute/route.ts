import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { Prisma } from '@prisma/client';
import { auth } from '@/auth';
import { generateFollowUpMessage } from '@/lib/ai/google-ai-service';
import { FacebookClient } from '@/lib/facebook/client';
import { isContactEligibleForAutomation } from '@/lib/ai/conflict-prevention';
import { logger } from '@/lib/utils/logger';

// POST /api/ai-automations/execute - Manual trigger of automation rule
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    let body;
    try {
      body = await request.json();
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }
    
    const { ruleId } = body;

    if (!ruleId) {
      return NextResponse.json(
        { error: 'Rule ID is required' },
        { status: 400 }
      );
    }

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation Execute] User has no organization', new Error('Missing organization'), { 
        userId: session.user.id,
        ruleId,
      });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    
    // Log routing information
    logger.info('[Automation Execute] Start', {
      ruleId,
      userId: session.user.id,
      organizationId: user.organizationId,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      routingStrategy: process.env.DB_ROUTING_STRATEGY || 'hash',
      triggerType: 'manual',
    });

    // Log routed DB details if multi-DB is enabled
    if (process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        
        if (dbConfig) {
          const dbHost = new URL(dbConfig.url).hostname;
          logger.info('[Automation Execute] Routed DB', {
            organizationId: user.organizationId,
            ruleId,
            dbIndex: dbConfig.index,
            dbHost,
            dbHealth: dbConfig.health,
          });
        }
      } catch (error) {
        logger.warn('[Automation Execute] Could not log routing details', { 
          error: error instanceof Error ? error.message : String(error) 
        });
      }
    }

    // Get rule from routed DB
    const rule = await db.aIAutomationRule.findFirst({
      where: {
        id: ruleId,
        userId: session.user.id,
      },
      include: {
        FacebookPage: true,
      },
    });

    if (!rule) {
      logger.warn('[Automation Execute] Rule not found in routed DB', {
        ruleId,
        userId: session.user.id,
        organizationId: user.organizationId,
      });
      
      return NextResponse.json(
        { 
          error: 'Automation rule not found',
          details: process.env.ENABLE_MULTI_DB === 'true' 
            ? 'Rule not found in routed database. Check DB1/DB2 connectivity.' 
            : undefined,
        },
        { status: 404 }
      );
    }

    logger.info('[Automation Execute] Manual execution of automation rule', { 
      ruleId: rule.id, 
      ruleName: rule.name,
      organizationId: user.organizationId,
    });

    // Calculate time threshold
    const now = new Date();
    const thresholdMs =
      (rule.timeIntervalDays || 0) * 24 * 60 * 60 * 1000 +
      (rule.timeIntervalHours || 0) * 60 * 60 * 1000 +
      (rule.timeIntervalMinutes || 0) * 60 * 1000;

    const thresholdDate = new Date(now.getTime() - thresholdMs);

    // Build where clause for finding eligible contacts
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const whereClause: Record<string, any> = {
      organizationId: user.organizationId,
      lastInteraction: {
        lte: thresholdDate,
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

    // Get eligible contacts from routed DB
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
      take: 50, // Limit for manual testing
    });

    // Exclude contacts with excluded tags
    if (rule.excludeTags.length > 0) {
      eligibleContacts = eligibleContacts.filter(contact => {
        return !rule.excludeTags.some(tag => contact.tags.includes(tag));
      });
    }

    // Filter out contacts that have been stopped for this rule
    const stoppedContactIds = await db.aIAutomationStop.findMany({
      where: {
        ruleId: rule.id,
      },
      select: {
        contactId: true,
      },
    });

    const stoppedIds = stoppedContactIds.map(s => s.contactId);
    eligibleContacts = eligibleContacts.filter(c => !stoppedIds.includes(c.id));

    logger.info('Found eligible contacts', { count: eligibleContacts.length });

    // Check for contacts that were just processed recently (prevent duplicate manual triggers)
    // Use the rule's time interval as the cooldown, with a minimum of 2 minutes
    const cooldownMs = Math.max(thresholdMs, 2 * 60 * 1000); // At least 2 minutes
    const recentExecutionCutoff = new Date(now.getTime() - cooldownMs);
    const recentlyProcessed = await db.aIAutomationExecution.findMany({
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
        executedAt: true,
      },
    });

    const recentlyProcessedIds = new Set(recentlyProcessed.map(e => e.contactId));
    const contactsToProcess = eligibleContacts.filter(c => !recentlyProcessedIds.has(c.id));

    if (recentlyProcessedIds.size > 0) {
      const cooldownMinutes = Math.ceil(cooldownMs / (60 * 1000));
      logger.debug('Skipping recently processed contacts', { 
        skippedCount: recentlyProcessedIds.size, 
        cooldownMinutes 
      });
    }

    logger.info('Processing contacts for automation', { 
      toProcess: contactsToProcess.length, 
      skipped: eligibleContacts.length - contactsToProcess.length 
    });

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
    
    logger.info(`Using ${concurrencyLimits.automationConcurrency} concurrent automations (${concurrencyLimits.keyCount} API keys)`);

    let sent = 0;
    let failed = 0;

    // Process all contacts in parallel with concurrency limit
    const results = await Promise.allSettled(
      contactsToProcess.map(contact =>
        automationLimiter.execute(async () => {
          try {
            // ⭐ CONFLICT PREVENTION: Check if contact is eligible
            // Skip recent contact check and active chat check for manual execution (allow immediate retry)
            const eligibilityCheck = await isContactEligibleForAutomation(
              contact.id,
              rule.excludeTags,
              { 
                skipRecentContactCheck: true,
                skipActiveChatCheck: true // Skip active chat session check for manual execution
              }
            );

            if (!eligibilityCheck.eligible) {
              logger.debug('Contact not eligible for automation', { 
                contactId: contact.id, 
                reason: eligibilityCheck.reason 
              });
              return { success: false, reason: 'not_eligible' };
            }

            const conversation = contact.conversations[0];
            if (!conversation) {
              logger.warn('No conversation found for contact', { contactId: contact.id });
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
              logger.warn('No messages in conversation', { conversationId: conversation.id });
              return { success: false, reason: 'no_messages' };
            }

            // Filter out system messages (isFromBusiness = true)
            const { filterSystemMessagesFromDB } = await import('@/lib/facebook/message-filtering');
            const userMessages = filterSystemMessagesFromDB(messages);

            // Handle conversations with only system messages
            if (userMessages.length === 0) {
              logger.warn('No user messages in conversation (only system messages)', { conversationId: conversation.id });
              return { success: false, reason: 'no_user_messages' };
            }

            // Format messages for AI (only user messages)
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
              logger.error('[Automation Execute] Failed to generate message for contact', new Error('AI message generation failed'), { 
                contactId: contact.id,
                ruleId: rule.id,
                organizationId: user.organizationId,
              });
              
              // Log execution failure
              await db.aIAutomationExecution.create({
                data: {
                  id: `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                  ruleId: rule.id,
                  userId: session.user.id,
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
                  userId: session.user.id,
                  contactId: contact.id,
                  conversationId: conversation.id,
                  recipientPSID: contact.messengerPSID || 'unknown',
                  recipientName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
                  aiPromptUsed: rule.customPrompt,
                  generatedMessage: aiResult.message,
                  aiReasoning: aiResult.reasoning,
                  previousMessages: conversationHistory as Prisma.InputJsonValue,
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

              logger.info('Sent automation message', { 
                contactId: contact.id, 
                contactName: contact.firstName,
                messageLength: aiResult.message.length 
              });
              
              return { success: true };
            } else {
              // Log execution failure
              await db.aIAutomationExecution.create({
                data: {
                  id: `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                  ruleId: rule.id,
                  userId: session.user.id,
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
              
              logger.error('Failed to send automation message', new Error(result.error || 'Unknown error'), { contactId: contact.id });
              return { success: false, reason: 'send_failed', error: result.error };
            }
          } catch (error) {
            logger.error('Error processing contact for automation', error instanceof Error ? error : new Error(String(error)), { contactId: contact.id });
            return { success: false, reason: 'error', error: error instanceof Error ? error.message : String(error) };
          }
        })
      )
    );

    // Count successes and failures
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.success) {
        sent++;
      } else {
        failed++;
      }
    }

    // Update rule statistics
    // Set lastExecutedAt to current time so cron respects the time interval
    // This ensures cron will wait for the full time interval before running again
    await db.aIAutomationRule.update({
      where: { id: rule.id },
      data: {
        lastExecutedAt: now, // Set to current time so cron respects the interval
        executionCount: { increment: 1 },
        successCount: { increment: sent },
        failureCount: { increment: failed },
        updatedAt: new Date(),
      },
    });

    const skippedCount = eligibleContacts.length - contactsToProcess.length;
    const cooldownMinutes = Math.ceil(cooldownMs / (60 * 1000));
    logger.info('[Automation Execute] Complete', { 
      ruleId: rule.id,
      organizationId: user.organizationId,
      sent, 
      failed, 
      skipped: skippedCount, 
      cooldownMinutes,
      triggerType: 'manual',
    });

    return NextResponse.json({
      success: true,
      sent,
      failed,
      total: contactsToProcess.length,
      skipped: skippedCount,
      message: skippedCount > 0 
        ? `${skippedCount} contacts were skipped because they were processed in the last ${cooldownMinutes} minutes. Please wait before triggering again.`
        : undefined,
    });
  } catch (error) {
    logger.error('[Automation Execute] Failed to execute automation rule', error instanceof Error ? error : new Error(String(error)), {
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    const errorMessage = error instanceof Error ? error.message : 'Failed to execute automation rule';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to execute automation rule',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
      { status: 500 }
    );
  }
}

