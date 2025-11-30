/**
 * Feedback Tracker
 * Tracks manual stage changes to learn from user corrections
 * "Bot said: 'Qualified', User changed to: 'New Lead'."
 */

import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

interface StageChangeFeedback {
  contactId: string;
  oldStageId: string | null;
  oldStageName: string | null;
  newStageId: string;
  newStageName: string;
  aiRecommendedStage: string | null;
  aiReason: string | null;
  conversationSnippet: string | null;
  userId: string;
  timestamp: Date;
}

/**
 * Record feedback when user manually changes a contact's stage
 */
export async function recordStageChangeFeedback(
  contactId: string,
  oldStageId: string | null,
  newStageId: string,
  userId: string,
  conversationSnippet?: string
): Promise<void> {
  try {
    // Get contact details
    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
      select: {
        stageId: true,
        aiContext: true,
        stage: oldStageId ? {
          select: { name: true }
        } : undefined,
      },
    });

    if (!contact) return;

    // Get stage names
    const [oldStage, newStage] = await Promise.all([
      oldStageId ? prisma.pipelineStage.findUnique({
        where: { id: oldStageId },
        select: { name: true }
      }) : null,
      prisma.pipelineStage.findUnique({
        where: { id: newStageId },
        select: { name: true }
      })
    ]);

    // Extract AI recommended stage from aiContext if available
    let aiRecommendedStage: string | null = null;
    let aiReason: string | null = null;
    
    if (contact.aiContext) {
      // Try to extract recommended stage from context
      const recommendedMatch = contact.aiContext.match(/recommendedStage[:\s]+([^\n]+)/i);
      if (recommendedMatch) {
        aiRecommendedStage = recommendedMatch[1].trim();
      }
      
      // Extract reasoning
      const reasonMatch = contact.aiContext.match(/Stage Reason[:\s]+([^\n]+)/i);
      if (reasonMatch) {
        aiReason = reasonMatch[1].trim();
      }
    }

    // Get recent conversation snippet (last 3 messages)
    let conversationSnippetText = conversationSnippet || null;
    if (!conversationSnippetText) {
      const recentMessages = await prisma.message.findMany({
        where: { 
          conversation: {
            contact: {
              id: contactId
            }
          }
        },
        orderBy: { createdAt: 'desc' },
        take: 3,
        select: {
          content: true,
          isFromBusiness: true
        }
      });
      
      if (recentMessages.length > 0) {
        conversationSnippetText = recentMessages
          .reverse()
          .map(m => `${m.isFromBusiness ? 'Business' : 'Contact'}: ${m.content}`)
          .join('\n')
          .substring(0, 500); // Limit to 500 chars
      }
    }

    // Store feedback in contact's stageChangeFeedback field
    const feedback: StageChangeFeedback = {
      contactId,
      oldStageId,
      oldStageName: oldStage?.name || null,
      newStageId,
      newStageName: newStage?.name || null,
      aiRecommendedStage,
      aiReason,
      conversationSnippet: conversationSnippetText,
      userId,
      timestamp: new Date()
    };

    // Get existing feedback array
    const existingFeedback = await prisma.contact.findUnique({
      where: { id: contactId },
      select: { stageChangeFeedback: true }
    });

    const feedbackArray = Array.isArray(existingFeedback?.stageChangeFeedback) 
      ? (existingFeedback.stageChangeFeedback as StageChangeFeedback[])
      : [];

    // Add new feedback
    feedbackArray.push(feedback);

    // Keep only last 10 feedback entries to avoid bloating
    const recentFeedback = feedbackArray.slice(-10);

    // Update contact with feedback
    await prisma.contact.update({
      where: { id: contactId },
      data: {
        stageChangeFeedback: recentFeedback as any
      }
    });

    console.log(`[Feedback Tracker] Recorded stage change: ${oldStage?.name || 'None'} → ${newStage?.name} (Contact: ${contactId})`);
  } catch (error) {
    console.error('[Feedback Tracker] Error recording feedback:', error);
    // Don't throw - feedback tracking shouldn't break the main flow
  }
}

/**
 * Get feedback statistics for learning
 */
export async function getFeedbackStatistics(organizationId: string) {
  try {
    const contacts = await prisma.contact.findMany({
      where: {
        organizationId,
        stageChangeFeedback: { not: Prisma.JsonNull }
      },
      select: {
        stageChangeFeedback: true
      }
    });

    const allFeedback: StageChangeFeedback[] = [];
    contacts.forEach(contact => {
      if (Array.isArray(contact.stageChangeFeedback)) {
        allFeedback.push(...(contact.stageChangeFeedback as StageChangeFeedback[]));
      }
    });

    // Analyze patterns
    const corrections = allFeedback.filter(f => 
      f.aiRecommendedStage && 
      f.newStageName !== f.aiRecommendedStage
    );

    return {
      totalFeedback: allFeedback.length,
      corrections: corrections.length,
      accuracy: allFeedback.length > 0 
        ? ((allFeedback.length - corrections.length) / allFeedback.length * 100).toFixed(1)
        : '0'
    };
  } catch (error) {
    console.error('[Feedback Tracker] Error getting statistics:', error);
    return { totalFeedback: 0, corrections: 0, accuracy: '0' };
  }
}

