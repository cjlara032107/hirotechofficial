import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';
import { GoogleAIService } from '@/lib/ai/google-ai-service';

/**
 * Create campaign with AI message generation as a background job
 * This allows the operation to continue even if the user navigates away
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const body = await request.json();
    const {
      name,
      description,
      platform,
      messageTag,
      facebookPageId,
      templateId,
      targetingType,
      targetTags,
      targetStageIds,
      targetContactIds,
      rateLimit,
      scheduledAt,
      autoFetchEnabled,
      includeTags,
      excludeTags,
      useAiPersonalization,
      aiCustomInstructions,
      templateContent,
    } = body;

    // Determine campaign status based on scheduling
    let status: 'DRAFT' | 'SCHEDULED' = 'DRAFT';
    if (scheduledAt) {
      const scheduleDate = new Date(scheduledAt);
      if (scheduleDate <= new Date()) {
        return NextResponse.json(
          { error: 'Scheduled time must be in the future' },
          { status: 400 }
        );
      }
      status = 'SCHEDULED';
    }

    // Create campaign first
    const campaign = await prisma.campaign.create({
      data: {
        name,
        description,
        platform,
        messageTag,
        facebookPageId,
        templateId,
        targetingType,
        targetTags: targetTags || [],
        targetStageIds: targetStageIds || [],
        targetContactIds: targetContactIds || [],
        rateLimit: rateLimit || 3600,
        organizationId: validatedSession.user.organizationId,
        createdById: validatedSession.user.id,
        status,
        scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
        ...(autoFetchEnabled !== undefined && { autoFetchEnabled }),
        ...(includeTags && { includeTags }),
        ...(excludeTags && { excludeTags }),
        ...(useAiPersonalization !== undefined && { useAiPersonalization }),
        ...(aiCustomInstructions && { aiCustomInstructions }),
      } as any,
    });

    // Return response immediately - don't wait for background jobs
    const response = NextResponse.json({
      ...campaign,
      messageGenerationInProgress: useAiPersonalization && targetContactIds && targetContactIds.length > 0,
    });

    // If AI personalization is enabled, generate messages in background
    // This runs after the response is sent, so user doesn't have to wait
    if (useAiPersonalization && targetContactIds && targetContactIds.length > 0) {
      // Start background generation (don't await - let it run in background)
      // This continues even if the user navigates away or closes the browser
      generateAIMessagesInBackground(
        campaign.id,
        targetContactIds,
        templateContent || 'Hello {firstName}! I wanted to reach out to you.',
        aiCustomInstructions
      ).catch((error) => {
        console.error(`[Background AI Generation] Failed for campaign ${campaign.id}:`, error);
      });
    }

    return response;
  } catch (error) {
    const err = error as Error;
    console.error('Create campaign with messages error:', err);
    return NextResponse.json(
      { error: 'Failed to create campaign' },
      { status: 500 }
    );
  }
}

/**
 * Generate AI messages in background
 * This continues even if the user navigates away
 */
async function generateAIMessagesInBackground(
  campaignId: string,
  contactIds: string[],
  templateMessage: string,
  customInstructions?: string
) {
  try {
    console.log(`[Background AI Generation] Starting for campaign ${campaignId} with ${contactIds.length} contacts`);
    
    // Fetch contacts
    const contacts = await prisma.contact.findMany({
      where: {
        id: { in: contactIds },
      },
      include: {
        conversations: {
          include: {
            messages: {
              orderBy: { createdAt: 'desc' },
              take: 10,
            },
          },
        },
      },
    });

    if (contacts.length === 0) {
      console.log(`[Background AI Generation] No contacts found for campaign ${campaignId}`);
      return;
    }

    const aiService = new GoogleAIService();
    const aiMessagesMap: Record<string, string> = {};
    const BATCH_SIZE = 3;

    for (let i = 0; i < contacts.length; i += BATCH_SIZE) {
      const batch = contacts.slice(i, i + BATCH_SIZE);
      
      const batchPromises = batch.map(async (contact) => {
        try {
          const allMessages: Array<{ from: string; message: string; timestamp: string }> = [];
          
          for (const conversation of contact.conversations) {
            for (const message of conversation.messages) {
              allMessages.push({
                from: message.isFromBusiness ? 'Business' : contact.firstName,
                message: message.content,
                timestamp: message.createdAt.toISOString(),
              });
            }
          }

          const conversationHistory = allMessages
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .slice(0, 10)
            .reverse();

          const context = {
            contactName: contact.firstName,
            conversationHistory,
            templateMessage,
            customInstructions: customInstructions || undefined,
          };

          const personalizedMessage = await aiService.generatePersonalizedMessage(context);
          aiMessagesMap[contact.id] = personalizedMessage;
        } catch (error) {
          console.error(`[Background AI Generation] Failed for contact ${contact.id}:`, error);
          const fallbackMessage = templateMessage
            .replace(/\{firstName\}/g, contact.firstName)
            .replace(/\{lastName\}/g, contact.lastName || '')
            .replace(/\{name\}/g, `${contact.firstName} ${contact.lastName || ''}`.trim());
          aiMessagesMap[contact.id] = fallbackMessage;
        }
      });

      await Promise.all(batchPromises);
      
      if (i + BATCH_SIZE < contacts.length) {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    // Update campaign with generated messages
    await prisma.campaign.update({
      where: { id: campaignId },
      data: { aiMessagesMap: aiMessagesMap as any },
    });

    console.log(`[Background AI Generation] ✅ Completed for campaign ${campaignId}: ${Object.keys(aiMessagesMap).length} messages`);
  } catch (error) {
    console.error(`[Background AI Generation] Fatal error for campaign ${campaignId}:`, error);
  }
}

