import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';
import { GoogleAIService } from '@/lib/ai/google-ai-service';

/**
 * Preview a personalized AI-generated message for a specific contact
 * This helps users see how the message will look before creating the campaign
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
      contactId,
      templateMessage,
      customInstructions,
    } = body;

    if (!contactId || !templateMessage) {
      return NextResponse.json(
        { error: 'Contact ID and template message are required' },
        { status: 400 }
      );
    }

    // Verify the contact belongs to the user's organization
    const contact = await prisma.contact.findFirst({
      where: {
        id: contactId,
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

    if (!contact) {
      return NextResponse.json(
        { error: 'Contact not found or access denied' },
        { status: 404 }
      );
    }

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

    // Get AI context if available
    const aiContext = contact.aiContext || null;

    // Generate personalized message
    const aiService = new GoogleAIService();
    const context = {
      contactName: contact.firstName,
      conversationHistory,
      templateMessage,
      customInstructions: customInstructions || undefined,
    };

    const personalizedMessage = await aiService.generatePersonalizedMessage(context);

    return NextResponse.json({
      personalizedMessage,
      contactName: contact.firstName,
      hasConversationHistory: conversationHistory.length > 0,
      hasAiContext: !!aiContext,
      conversationHistoryCount: conversationHistory.length,
    });
  } catch (error) {
    const err = error as Error;
    console.error('Preview personalized message error:', err);
    return NextResponse.json(
      { error: 'Failed to generate personalized message preview' },
      { status: 500 }
    );
  }
}

