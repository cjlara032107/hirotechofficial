import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import { auth } from '@/auth';
import { generateFollowUpMessage } from '@/lib/ai/google-ai-service';
import { FacebookClient } from '@/lib/facebook/client';
import { isContactEligibleForAutomation } from '@/lib/ai/conflict-prevention';

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

    // Get rule
    const rule = await prisma.aIAutomationRule.findFirst({
      where: {
        id: ruleId,
        userId: session.user.id,
      },
      include: {
        FacebookPage: true,
      },
    });

    if (!rule) {
      return NextResponse.json(
        { error: 'Automation rule not found' },
        { status: 404 }
      );
    }

    console.log(`[AI Automations] Manual execution of rule: ${rule.name}`);

    // Get user's organization
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

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

    // Get eligible contacts
    // Use select to avoid issues with new columns that may not exist yet
    let eligibleContacts = await prisma.contact.findMany({
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

    console.log(`[AI Automations] Found ${eligibleContacts.length} eligible contacts`);

    // Check for contacts that were just processed recently (prevent duplicate manual triggers)
    // Use the rule's time interval as the cooldown, with a minimum of 2 minutes
    const cooldownMs = Math.max(thresholdMs, 2 * 60 * 1000); // At least 2 minutes
    const recentExecutionCutoff = new Date(now.getTime() - cooldownMs);
    const recentlyProcessed = await prisma.aIAutomationExecution.findMany({
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
      console.log(`[AI Automations] Skipping ${recentlyProcessedIds.size} contacts that were processed in the last ${cooldownMinutes} minutes`);
    }

    console.log(`[AI Automations] Processing ${contactsToProcess.length} contacts (${eligibleContacts.length - contactsToProcess.length} skipped due to recent processing)`);

    let sent = 0;
    let failed = 0;

    // Process each eligible contact
    for (const contact of contactsToProcess) {
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
          console.log(`[AI Automations] Contact ${contact.id} not eligible: ${eligibilityCheck.reason}`);
          continue;
        }

        const conversation = contact.conversations[0];
        if (!conversation) {
          console.log(`[AI Automations] No conversation found for contact: ${contact.id}`);
          failed++;
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
          console.log(`[AI Automations] No messages in conversation: ${conversation.id}`);
          failed++;
          continue;
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
          console.error(`[AI Automations] Failed to generate message for contact: ${contact.id}`);
          failed++;
          
          // Log execution failure
          await prisma.aIAutomationExecution.create({
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

          sent++;
          console.log(`[AI Automations] Sent message to ${contact.firstName}: "${aiResult.message}"`);
        } else {
          failed++;
          
          // Log execution failure
          await prisma.aIAutomationExecution.create({
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
          
          console.error(`[AI Automations] Failed to send message: ${result.error}`);
        }
      } catch (error) {
        console.error(`[AI Automations] Error processing contact ${contact.id}:`, error);
        failed++;
      }
    }

    // Update rule statistics
    // Set lastExecutedAt to current time so cron respects the time interval
    // This ensures cron will wait for the full time interval before running again
    await prisma.aIAutomationRule.update({
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
    console.log(`[AI Automations] Manual execution complete: ${sent} sent, ${failed} failed, ${skippedCount} skipped. Next cron execution will respect ${cooldownMinutes}-minute time interval.`);

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
    console.error('[AI Automations] Execute error:', error);
    return NextResponse.json(
      { error: 'Failed to execute automation rule' },
      { status: 500 }
    );
  }
}

