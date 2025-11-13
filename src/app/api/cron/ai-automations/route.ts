import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
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

        // Exclude contacts with excluded tags
        if (rule.excludeTags.length > 0) {
          eligibleContacts = eligibleContacts.filter(contact => {
            return !rule.excludeTags.some(tag => contact.tags.includes(tag));
          });
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
        eligibleContacts = eligibleContacts.filter(c => !stoppedIds.includes(c.id));

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
          },
        });

        const recentContactIds = recentExecutions.map(e => e.contactId);
        eligibleContacts = eligibleContacts.filter(c => !recentContactIds.includes(c.id));

        if (eligibleContacts.length === 0) {
          console.log(`[AI Automations Cron] Rule "${rule.name}" - No eligible contacts`);
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

            const conversation = contact.conversations[0];
            if (!conversation) {
              console.log(`[AI Automations Cron] No conversation for contact: ${contact.id}`);
              ruleFailed++;
              continue;
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

            if (messages.length === 0) {
              console.log(`[AI Automations Cron] No messages in conversation: ${conversation.id}`);
              ruleFailed++;
              continue;
            }

            // Check if contact replied recently (live check)
            const recentContactMessages = messages.filter(msg => !msg.isFromBusiness);
            if (recentContactMessages.length > 0) {
              const lastContactMessage = recentContactMessages[0];
              const timeSinceReply = now.getTime() - lastContactMessage.createdAt.getTime();
              
              // If contact replied within last hour, skip (they're active)
              if (timeSinceReply < 60 * 60 * 1000) {
                console.log(`[AI Automations Cron] Contact ${contact.id} replied recently, skipping`);
                continue;
              }
            }

            // Format messages for AI
            const conversationHistory = messages.reverse().map(msg => ({
              from: msg.isFromBusiness ? 'Business' : contact.firstName || 'Customer',
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

