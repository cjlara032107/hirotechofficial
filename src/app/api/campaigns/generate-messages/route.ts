import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';
import { GoogleAIService } from '@/lib/ai/google-ai-service';

/**
 * Generate personalized AI messages for multiple contacts
 * Used during campaign creation to generate all messages at once
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
      contactIds,
      templateMessage,
      customInstructions,
    } = body;

    if (!contactIds || !Array.isArray(contactIds) || contactIds.length === 0) {
      return NextResponse.json(
        { error: 'Contact IDs array is required' },
        { status: 400 }
      );
    }

    // Use default template if not provided (for AI-only generation)
    const finalTemplateMessage = templateMessage || 'Hello {firstName}! I wanted to reach out to you.';

    // Fetch all contacts and verify they belong to the user's organization
    const contacts = await prisma.contact.findMany({
      where: {
        id: { in: contactIds },
        organizationId: validatedSession.user.organizationId,
      },
      include: {
        conversations: {
          include: {
            messages: {
              orderBy: {
                createdAt: 'desc',
              },
              take: 10, // Last 10 messages for context
            },
          },
        },
      },
    });

    if (contacts.length === 0) {
      return NextResponse.json(
        { error: 'No contacts found or access denied' },
        { status: 404 }
      );
    }

    // Generate personalized messages for each contact
    const aiService = new GoogleAIService();
    const aiMessagesMap: Record<string, string> = {};
    const BATCH_SIZE = 3; // Process 3 at a time to avoid rate limits

    for (let i = 0; i < contacts.length; i += BATCH_SIZE) {
      const batch = contacts.slice(i, i + BATCH_SIZE);
      
      const batchPromises = batch.map(async (contact) => {
        try {
          // Get conversation history
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

          // Sort by timestamp (most recent first) and take last 10
          const conversationHistory = allMessages
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .slice(0, 10)
            .reverse(); // Reverse to show chronological order

          const context = {
            contactName: contact.firstName,
            conversationHistory,
            templateMessage: finalTemplateMessage,
            customInstructions: customInstructions || undefined,
          };

          const personalizedMessage = await aiService.generatePersonalizedMessage(context);
          aiMessagesMap[contact.id] = personalizedMessage;
        } catch (error) {
          console.error(`[AI Generation] Failed for contact ${contact.id}:`, error);
          // Fallback to template with variable replacement
          const fallbackMessage = finalTemplateMessage
            .replace(/\{firstName\}/g, contact.firstName)
            .replace(/\{lastName\}/g, contact.lastName || '')
            .replace(/\{name\}/g, `${contact.firstName} ${contact.lastName || ''}`.trim());
          aiMessagesMap[contact.id] = fallbackMessage;
        }
      });

      await Promise.all(batchPromises);
      
      // Rate limit delay between batches (reduced for faster generation)
      if (i + BATCH_SIZE < contacts.length) {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    return NextResponse.json({
      aiMessagesMap,
      generatedCount: Object.keys(aiMessagesMap).length,
      totalContacts: contacts.length,
    });
  } catch (error) {
    const err = error as Error;
    console.error('Generate messages error:', err);
    return NextResponse.json(
      { error: 'Failed to generate personalized messages' },
      { status: 500 }
    );
  }
}

