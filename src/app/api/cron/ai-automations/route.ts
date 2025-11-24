import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { generateFollowUpMessage } from '@/lib/ai/google-ai-service';
import { FacebookClient } from '@/lib/facebook/client';
import { isContactEligibleForAutomation } from '@/lib/ai/conflict-prevention';

export const dynamic = 'force-dynamic';
export const maxDuration = 300; // 5 minutes max execution time

// Cron job that runs every minute
export async function GET(request: NextRequest) {
  try {
    // Authentication: Vercel cron jobs are automatically authenticated
    // Only require CRON_SECRET for external/manual calls
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    
    // Log request for debugging
    console.log('[AI Automations Cron] Request received:', {
      hasAuth: !!authHeader,
      hasCronSecret: !!cronSecret,
      userAgent: request.headers.get('user-agent')?.substring(0, 50),
    });
    
    // If CRON_SECRET is set, require it for non-Vercel requests
    // Vercel cron jobs don't send authorization headers, so we allow those
    if (cronSecret && authHeader && authHeader !== `Bearer ${cronSecret}`) {
      console.log('[AI Automations Cron] Unauthorized: Invalid CRON_SECRET');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    // If no auth header and CRON_SECRET is set, assume it's Vercel cron (allow it)
    // If auth header matches CRON_SECRET, allow it
    // If no CRON_SECRET is set, allow all requests

    console.log('[AI Automations Cron] Starting execution...');
    const startTime = Date.now();

    // Get all enabled automation rules
    const rules = await prisma.aIAutomationRule.findMany({
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
    });

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

        const todayExecutions = await prisma.aIAutomationExecution.findMany({
          where: {
            ruleId: rule.id,
            executedAt: {
              gte: todayStart,
            },
            status: 'sent',
          },
        });

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

        const thresholdDate = new Date(now.getTime() - thresholdMs);

        // Build where clause for finding eligible contacts
        const whereClause: any = {
          organizationId: rule.User.organizationId,
          messengerPSID: {
            not: null,
          },
          OR: [
            {
              lastInteraction: {
                lte: thresholdDate,
              },
            },
            {
              lastInteraction: null,
              createdAt: {
                lte: thresholdDate,
              },
            },
          ],
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

        // Get eligible contacts
        let eligibleContacts = await prisma.contact.findMany({
          where: whereClause,
          include: {
            facebookPage: true,
            conversations: {
              where: {
                platform: 'MESSENGER',
              },
              orderBy: {
                lastMessageAt: 'desc',
              },
              take: 1,
            },
          },
          take: remainingQuota, // Respect daily limit
        });

        const beforeTagFilter = eligibleContacts.length;
        console.log(`[AI Automations Cron] Rule "${rule.name}" - Found ${beforeTagFilter} contacts matching time interval`);

        // Exclude contacts with excluded tags
        if (rule.excludeTags.length > 0) {
          eligibleContacts = eligibleContacts.filter(contact => {
            return !rule.excludeTags.some(tag => contact.tags.includes(tag));
          });
          console.log(`[AI Automations Cron] After exclude tags filter: ${eligibleContacts.length} contacts`);
        }

        // Filter out contacts that have been stopped for this rule
        const stoppedContactIds = await prisma.aIAutomationStop.findMany({
          where: {
            ruleId: rule.id,
          },
          select: {
            contactId: true,
          },
        });

        const stoppedIds = stoppedContactIds.map(s => s.contactId);
        const beforeStoppedFilter = eligibleContacts.length;
        eligibleContacts = eligibleContacts.filter(c => !stoppedIds.includes(c.id));
        console.log(`[AI Automations Cron] After stopped filter: ${eligibleContacts.length} contacts (${stoppedIds.length} stopped)`);

        // Check cooldown - don't send to same contact within last 12 hours
        const cooldownDate = new Date(now.getTime() - 12 * 60 * 60 * 1000);
        const recentExecutions = await prisma.aIAutomationExecution.findMany({
          where: {
            ruleId: rule.id,
            executedAt: {
              gte: cooldownDate,
            },
            status: 'sent',
          },
          select: {
            contactId: true,
            executedAt: true,
            recipientName: true,
          },
          orderBy: {
            executedAt: 'desc',
          },
        });

        // Create a map of contactId -> last execution time
        const recentContactMap = new Map<string, Date>();
        for (const exec of recentExecutions) {
          if (!recentContactMap.has(exec.contactId)) {
            recentContactMap.set(exec.contactId, exec.executedAt);
          }
        }

        const recentContactIds = Array.from(recentContactMap.keys());
        const beforeCooldownFilter = eligibleContacts.length;
        
        // Log which contacts are in cooldown
        const contactsInCooldown = eligibleContacts.filter(c => recentContactIds.includes(c.id));
        if (contactsInCooldown.length > 0) {
          console.log(`[AI Automations Cron] Contacts in cooldown:`);
          for (const contact of contactsInCooldown) {
            const lastExecTime = recentContactMap.get(contact.id);
            const hoursAgo = lastExecTime 
              ? Math.round((now.getTime() - lastExecTime.getTime()) / (60 * 60 * 1000) * 10) / 10
              : 0;
            console.log(`  - ${contact.firstName} (${contact.id}): last messaged ${hoursAgo}h ago`);
          }
        }
        
        eligibleContacts = eligibleContacts.filter(c => !recentContactIds.includes(c.id));
        console.log(`[AI Automations Cron] After cooldown filter: ${eligibleContacts.length} contacts (${recentContactIds.length} in cooldown)`);

        if (eligibleContacts.length === 0) {
          console.log(`[AI Automations Cron] Rule "${rule.name}" - No eligible contacts after all filters`);
          console.log(`[AI Automations Cron] Filter summary: ${beforeTagFilter} initial → ${beforeStoppedFilter} after tags → ${beforeCooldownFilter} after stopped → 0 after cooldown`);
          continue;
        }

        console.log(`[AI Automations Cron] Rule "${rule.name}" - Processing ${eligibleContacts.length} contacts`);
        console.log(`[AI Automations Cron] Eligible contacts:`, eligibleContacts.map(c => `${c.firstName} (${c.id})`));

        let ruleSent = 0;
        let ruleFailed = 0;

        // Process each eligible contact
        for (const contact of eligibleContacts) {
          try {
            console.log(`[AI Automations Cron] Processing contact: ${contact.firstName} (${contact.id})`);
            
            // ⭐ CONFLICT PREVENTION: Check if contact is eligible
            const eligibilityCheck = await isContactEligibleForAutomation(
              contact.id,
              rule.excludeTags
            );

            if (!eligibilityCheck.eligible) {
              console.log(`[AI Automations Cron] Contact ${contact.id} not eligible: ${eligibilityCheck.reason}`);
              continue;
            }

            // Get or create conversation
            let conversation = contact.conversations[0];
            if (!conversation) {
              // Create conversation if it doesn't exist (for contacts with messengerPSID)
              if (contact.messengerPSID && contact.facebookPageId) {
                console.log(`[AI Automations Cron] Creating conversation for contact: ${contact.firstName} (${contact.id})`);
                conversation = await prisma.conversation.create({
                  data: {
                    contactId: contact.id,
                    facebookPageId: contact.facebookPageId,
                    platform: 'MESSENGER',
                    status: 'OPEN',
                    lastMessageAt: new Date(),
                  },
                });
                console.log(`[AI Automations Cron] Created conversation: ${conversation.id}`);
              } else {
                console.log(`[AI Automations Cron] No conversation found and cannot create (missing messengerPSID or facebookPageId) for contact: ${contact.id}`);
                ruleFailed++;
                continue;
              }
            }

            // Get conversation history
            const messages = await prisma.message.findMany({
              where: {
                conversationId: conversation.id,
              },
              orderBy: {
                createdAt: 'desc',
              },
              take: 20,
            });

            // If no messages, we can still send (new conversation), but AI won't have history
            if (messages.length === 0) {
              console.log(`[AI Automations Cron] No messages in conversation: ${conversation.id} - will send without history`);
            }

            // Check if contact replied recently (live check)
            // This is a redundant check since isContactEligibleForAutomation already checks this
            // But we keep it for additional safety
            const recentContactMessages = messages.filter(msg => !msg.isFromBusiness);
            if (recentContactMessages.length > 0) {
              const lastContactMessage = recentContactMessages[0];
              const timeSinceReply = now.getTime() - lastContactMessage.createdAt.getTime();
              
              // If contact replied within last 30 minutes, skip (they're actively chatting)
              // This matches the isContactInActiveChatSession check
              if (timeSinceReply < 30 * 60 * 1000) {
                console.log(`[AI Automations Cron] Contact ${contact.id} replied recently (${Math.floor(timeSinceReply / 60000)} minutes ago), skipping`);
                continue;
              }
            }

            // Format messages for AI (or use empty array if no history)
            const conversationHistory = messages.length > 0
              ? messages.reverse().map(msg => ({
                  from: msg.isFromBusiness ? 'Business' : contact.firstName || 'Customer',
                  text: msg.content,
                  timestamp: msg.createdAt,
                }))
              : []; // Empty history for new conversations

            // Generate AI message
            const aiResult = await generateFollowUpMessage(
              contact.firstName || 'there',
              conversationHistory,
              rule.customPrompt,
              rule.languageStyle
            );

            if (!aiResult) {
              console.error(`[AI Automations Cron] Failed to generate message for contact: ${contact.id}`);
              ruleFailed++;
              
              // Log execution failure
              await prisma.aIAutomationExecution.create({
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
              
              continue;
            }

            // Verify Facebook page has access token
            if (!contact.facebookPage?.pageAccessToken) {
              console.error(`[AI Automations Cron] No access token for Facebook page: ${contact.facebookPage?.id}`);
              ruleFailed++;
              
              await prisma.aIAutomationExecution.create({
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
                  errorMessage: 'Facebook page access token missing',
                  executedAt: new Date(),
                },
              });
              
              continue;
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
              await prisma.aIAutomationExecution.create({
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
                  previousMessages: conversationHistory as any,
                  status: 'sent',
                  facebookMessageId: result.data?.message_id,
                  executedAt: new Date(),
                },
              });

              // Save message to database
              await prisma.message.create({
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

              ruleSent++;
              console.log(`[AI Automations Cron] Sent message to ${contact.firstName}`);
            } else {
              ruleFailed++;
              
              // Log execution failure
              await prisma.aIAutomationExecution.create({
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
            }
          } catch (error) {
            console.error(`[AI Automations Cron] Error processing contact ${contact.id}:`, error);
            ruleFailed++;
          }
        }

        // Update rule statistics
        if (ruleSent > 0 || ruleFailed > 0) {
          await prisma.aIAutomationRule.update({
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
  } catch (error) {
    console.error('[AI Automations Cron] Fatal error:', error);
    return NextResponse.json(
      { error: 'Failed to execute automation cron job' },
      { status: 500 }
    );
  }
}

// Allow POST as well for manual testing
export async function POST(request: NextRequest) {
  return GET(request);
}

