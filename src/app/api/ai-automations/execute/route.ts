import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
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

    const body = await request.json();
    const { ruleId, bypassCooldown } = body;

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

    console.log(`[AI Automations] Manual execution of rule: ${rule.name} (ID: ${rule.id})`);
    
    // Warn if rule is disabled (but allow manual execution for testing)
    if (!rule.enabled) {
      console.log(`[AI Automations] Warning: Rule "${rule.name}" is disabled, but allowing manual execution`);
    }

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
      take: 50, // Limit for manual testing
    });

    const totalBeforeFilters = eligibleContacts.length;
    console.log(`[AI Automations] Found ${totalBeforeFilters} contacts matching basic criteria`);

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

    // Check cooldown - don't send to same contact within last 12 hours (unless bypassed for manual testing)
    let recentContactIds: string[] = [];
    if (!bypassCooldown) {
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

      recentContactIds = recentExecutions.map(e => e.contactId);
      eligibleContacts = eligibleContacts.filter(c => !recentContactIds.includes(c.id));
      console.log(`[AI Automations] Cooldown check: ${recentContactIds.length} contacts in cooldown period`);
    } else {
      console.log(`[AI Automations] Cooldown check bypassed for manual testing`);
    }

    console.log(`[AI Automations] Found ${eligibleContacts.length} eligible contacts after filters`);

    if (eligibleContacts.length === 0) {
      return NextResponse.json({
        success: true,
        sent: 0,
        failed: 0,
        total: 0,
        message: 'No eligible contacts found. Check: time interval, tags, stopped contacts, or cooldown period.',
        details: {
          totalBeforeFilters,
          stoppedCount: stoppedIds.length,
          recentExecutionsCount: recentContactIds.length,
        },
      });
    }

    let sent = 0;
    let failed = 0;
    const failureReasons: Array<{ contactName: string; reason: string }> = [];

    // Process each eligible contact
    for (const contact of eligibleContacts) {
      try {
        console.log(`[AI Automations] Processing contact: ${contact.firstName} (${contact.id})`);

        // ⭐ CONFLICT PREVENTION: Check if contact is eligible
        // For manual testing, we can bypass the "recently contacted" check
        const eligibilityCheck = await isContactEligibleForAutomation(
          contact.id,
          rule.excludeTags,
          bypassCooldown // Pass bypass flag to skip recent contact check
        );

        if (!eligibilityCheck.eligible) {
          const contactName = `${contact.firstName} ${contact.lastName || ''}`.trim();
          const reason = eligibilityCheck.reason || 'Unknown eligibility issue';
          console.log(`[AI Automations] Contact ${contactName} (${contact.id}) not eligible: ${reason}`);
          failureReasons.push({ contactName, reason });
          failed++;
          continue;
        }

        const conversation = contact.conversations[0];
        if (!conversation) {
          const contactName = `${contact.firstName} ${contact.lastName || ''}`.trim();
          console.log(`[AI Automations] No conversation found for contact: ${contactName} (${contact.id})`);
          failureReasons.push({ contactName, reason: 'No conversation found' });
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
          const contactName = `${contact.firstName} ${contact.lastName || ''}`.trim();
          console.log(`[AI Automations] No messages in conversation: ${conversation.id} for contact ${contactName}`);
          failureReasons.push({ contactName, reason: 'No messages in conversation' });
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

        // Verify Facebook page has access token
        if (!contact.facebookPage?.pageAccessToken) {
          console.error(`[AI Automations] No access token for Facebook page: ${contact.facebookPage?.id}`);
          failed++;
          
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
              userId: session.user.id,
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
    await prisma.aIAutomationRule.update({
      where: { id: rule.id },
      data: {
        lastExecutedAt: now,
        executionCount: { increment: 1 },
        successCount: { increment: sent },
        failureCount: { increment: failed },
        updatedAt: new Date(),
      },
    });

    console.log(`[AI Automations] Execution complete: ${sent} sent, ${failed} failed`);

    // Group failure reasons for better reporting
    const reasonCounts = new Map<string, number>();
    failureReasons.forEach(({ reason }) => {
      reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
    });

    const reasonSummary = Array.from(reasonCounts.entries())
      .map(([reason, count]) => `${count} contact(s): ${reason}`)
      .join('; ');

    return NextResponse.json({
      success: true,
      sent,
      failed,
      total: eligibleContacts.length,
      failureReasons: failureReasons.length > 0 ? failureReasons : undefined,
      reasonSummary: reasonSummary || undefined,
      message: sent > 0 
        ? `Successfully sent ${sent} message(s). ${failed > 0 ? `${failed} failed.` : ''}`
        : failed > 0
        ? `No messages sent. ${failed} contact(s) failed: ${reasonSummary || 'eligibility checks'}`
        : 'No eligible contacts found.',
    });
  } catch (error) {
    console.error('[AI Automations] Execute error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    return NextResponse.json(
      { 
        error: 'Failed to execute automation rule',
        details: errorMessage,
      },
      { status: 500 }
    );
  }
}

