/**
 * Compute and store best contact times for a contact based on message history.
 */

import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';
import {
  computeBestContactTimes,
  formatBestContactTimesForStorage,
  type Interaction,
} from './best-contact-times';

/**
 * Compute best contact times for a contact and store in database.
 * 
 * @param contactId - The contact ID to compute times for
 * @returns The computed best contact times data, or null if insufficient data
 */
export async function computeAndStoreBestContactTimes(
  contactId: string
): Promise<Record<string, unknown> | null> {
  try {
    console.log(`[BestContactTimes] Starting computation for contact ${contactId}`);
    
    // First, verify the contact exists
    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
      select: { id: true, firstName: true, lastName: true, organizationId: true },
    });
    
    if (!contact) {
      console.error(`[BestContactTimes] Contact ${contactId} not found in database`);
      throw new Error(`Contact ${contactId} not found`);
    }
    
    console.log(`[BestContactTimes] Contact verified: ${contact.firstName} ${contact.lastName} (org: ${contact.organizationId})`);
    
    // Check message count first for debugging
    const messageCount = await prisma.message.count({
      where: { contactId },
    });
    console.log(`[BestContactTimes] Total message count for contact ${contactId}: ${messageCount}`);
    
    // Also check if there are any conversations for this contact
    const conversationCount = await prisma.conversation.count({
      where: { contactId },
    });
    console.log(`[BestContactTimes] Total conversation count for contact ${contactId}: ${conversationCount}`);
    
    // Fetch all messages for this contact, ordered by creation time
    // First try direct contactId query
    let messages = await prisma.message.findMany({
      where: {
        contactId,
      },
      orderBy: {
        createdAt: 'asc',
      },
      select: {
        id: true,
        isFromBusiness: true,
        createdAt: true,
        sentAt: true,
        conversationId: true,
      },
    });

    console.log(`[BestContactTimes] Found ${messages.length} messages for contact ${contactId} via direct contactId query`);
    
    // If no messages found via direct contactId, try via conversations (fallback for data integrity issues)
    if (messages.length === 0) {
      console.warn(`[BestContactTimes] No messages found via direct contactId query. Trying via conversations...`);
      
      const conversations = await prisma.conversation.findMany({
        where: { contactId },
        select: { id: true },
      });
      
      if (conversations.length > 0) {
        const conversationIds = conversations.map(c => c.id);
        const messagesViaConversations = await prisma.message.findMany({
          where: {
            conversationId: { in: conversationIds },
          },
          orderBy: {
            createdAt: 'asc',
          },
          select: {
            id: true,
            isFromBusiness: true,
            createdAt: true,
            sentAt: true,
            conversationId: true,
          },
        });
        
        console.log(`[BestContactTimes] Found ${messagesViaConversations.length} messages via ${conversations.length} conversation(s)`);
        
        if (messagesViaConversations.length > 0) {
          console.warn(`[BestContactTimes] Using messages from conversations as fallback. This suggests messages may have incorrect contactId.`);
          messages = messagesViaConversations;
          
          // Try to fix the data integrity issue by updating message contactIds
          // Only update messages that don't have the correct contactId
          const messagesToFix = messagesViaConversations.filter(m => m.conversationId && conversationIds.includes(m.conversationId));
          if (messagesToFix.length > 0) {
            console.log(`[BestContactTimes] Attempting to fix data integrity: updating contactId for ${messagesToFix.length} messages`);
            try {
              await prisma.message.updateMany({
                where: {
                  id: { in: messagesToFix.map(m => m.id) },
                  contactId: { not: contactId },
                },
                data: {
                  contactId,
                },
              });
              console.log(`[BestContactTimes] Updated contactId for messages`);
            } catch (fixError) {
              console.error(`[BestContactTimes] Failed to fix message contactIds:`, fixError);
            }
          }
        }
      }
    }
    
    console.log(`[BestContactTimes] Final message count: ${messages.length}`);
    console.log(`[BestContactTimes] Messages breakdown: ${messages.filter(m => m.isFromBusiness).length} from business, ${messages.filter(m => !m.isFromBusiness).length} from contact`);
    
    // Log sample message IDs for debugging
    if (messages.length > 0) {
      console.log(`[BestContactTimes] Sample message IDs: ${messages.slice(0, 3).map(m => m.id).join(', ')}`);
    }

    if (messages.length < 2) {
      // Need at least 2 messages (one sent, one reply) to compute times
      console.log(`[BestContactTimes] Insufficient messages (${messages.length} < 2) for contact ${contactId}`);
      return null;
    }

    // Build interactions: messages sent by business with their replies
    const interactions: Interaction[] = [];
    const contactMessages: Date[] = [];

    // Track business messages and find their replies
    for (let i = 0; i < messages.length; i++) {
      const message = messages[i];
      // Ensure we have a proper Date object
      const messageTime = message.sentAt 
        ? (message.sentAt instanceof Date ? message.sentAt : new Date(message.sentAt))
        : (message.createdAt instanceof Date ? message.createdAt : new Date(message.createdAt));

      // Collect all contact messages (for activity histogram)
      if (!message.isFromBusiness) {
        contactMessages.push(messageTime);
      }

      // If this is a business message, look for the next contact reply
      if (message.isFromBusiness) {
        const sentTime = messageTime;
        let replyTime: Date | null = null;

        // Look ahead for the next contact message (reply)
        for (let j = i + 1; j < messages.length; j++) {
          const nextMessage = messages[j];
          if (!nextMessage.isFromBusiness) {
            const nextMessageTime = nextMessage.sentAt 
              ? (nextMessage.sentAt instanceof Date ? nextMessage.sentAt : new Date(nextMessage.sentAt))
              : (nextMessage.createdAt instanceof Date ? nextMessage.createdAt : new Date(nextMessage.createdAt));
            replyTime = nextMessageTime;
            break; // Found the reply, stop looking
          }
        }

        interactions.push({
          sentTime,
          replyTime,
        });
      }
    }

    // Need at least some interactions to compute
    if (interactions.length === 0) {
      console.log(`[BestContactTimes] No interactions found for contact ${contactId} (${messages.length} messages total)`);
      console.log(`[BestContactTimes] Business messages: ${messages.filter(m => m.isFromBusiness).length}, Contact messages: ${messages.filter(m => !m.isFromBusiness).length}`);
      
      // If we have messages but no interactions, it means no business messages
      // In this case, we can still compute based on contact activity patterns
      if (contactMessages.length > 0) {
        console.log(`[BestContactTimes] No business messages, but have ${contactMessages.length} contact messages. Using activity-based approach.`);
        // We'll create dummy interactions based on contact message times
        // This allows us to still compute best times based on when the contact is active
        const dummyInteractions: Interaction[] = contactMessages.map(msgTime => ({
          sentTime: new Date(msgTime.getTime() - 60 * 60 * 1000), // Assume message was 1 hour after a business message
          replyTime: msgTime,
        }));
        
        if (dummyInteractions.length > 0) {
          console.log(`[BestContactTimes] Created ${dummyInteractions.length} dummy interactions from contact activity`);
          try {
            // Use these for computation
            const bestTimeWindows = computeBestContactTimes({
              interactions: dummyInteractions,
              contactMessages,
              replyWindowHours: 1,
              candidateStepMinutes: 30,
              alpha: 0.5, // Lower alpha since we're inferring interactions
              topK: 5,
              windowMinutes: 60,
            });
            
            const bestContactTimesData = formatBestContactTimesForStorage(
              bestTimeWindows,
              messages.length,
              undefined, // Can't calculate reply times without actual interactions
              undefined,
              undefined
            );
            
            await prisma.contact.update({
              where: { id: contactId },
              data: {
                bestContactTimes: bestContactTimesData as Prisma.InputJsonValue,
              },
            });
            
            return bestContactTimesData;
          } catch (error) {
            console.error(`[BestContactTimes] Error in fallback computation:`, error);
            throw error;
          }
        }
      }
      
      return null;
    }

    // Need at least some contact messages for activity histogram
    if (contactMessages.length === 0) {
      console.log(`[BestContactTimes] No contact messages found for activity histogram, using fallback`);
      // Use a default activity pattern if no contact messages
      // This is a fallback - ideally we'd have contact messages
      contactMessages.push(new Date()); // Add at least one to avoid errors
    }

    console.log(`[BestContactTimes] Computing for contact ${contactId}: ${interactions.length} interactions, ${contactMessages.length} contact messages`);
    console.log(`[BestContactTimes] Interactions with replies: ${interactions.filter(i => i.replyTime !== null).length}`);

    // Validate interactions have valid dates
    for (let i = 0; i < interactions.length; i++) {
      const inter = interactions[i];
      if (!(inter.sentTime instanceof Date) || isNaN(inter.sentTime.getTime())) {
        throw new Error(`Invalid sentTime in interaction ${i}: ${inter.sentTime}`);
      }
      if (inter.replyTime !== null && (!(inter.replyTime instanceof Date) || isNaN(inter.replyTime.getTime()))) {
        throw new Error(`Invalid replyTime in interaction ${i}: ${inter.replyTime}`);
      }
    }

    // Validate contact messages have valid dates
    for (let i = 0; i < contactMessages.length; i++) {
      const msg = contactMessages[i];
      if (!(msg instanceof Date) || isNaN(msg.getTime())) {
        throw new Error(`Invalid date in contactMessages[${i}]: ${msg}`);
      }
    }

    // Compute best contact times
    let bestTimeWindows: ReturnType<typeof computeBestContactTimes>;
    try {
      bestTimeWindows = computeBestContactTimes({
        interactions,
        contactMessages,
        replyWindowHours: 1,
        candidateStepMinutes: 30,
        alpha: 0.7,
        topK: 5,
        windowMinutes: 60,
      });
      console.log(`[BestContactTimes] Successfully computed ${bestTimeWindows.length} best time windows`);
    } catch (error) {
      console.error(`[BestContactTimes] Error in computeBestContactTimes:`, error);
      if (error instanceof Error) {
        console.error(`[BestContactTimes] Error details:`, {
          message: error.message,
          stack: error.stack,
          interactionsCount: interactions.length,
          contactMessagesCount: contactMessages.length,
        });
      }
      throw new Error(`Failed to compute best contact times: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // Calculate average reply time statistics
    const replyTimes = interactions
      .filter((inter) => inter.replyTime !== null)
      .map((inter) => {
        if (!inter.replyTime) return null;
        return (inter.replyTime.getTime() - inter.sentTime.getTime()) / (1000 * 60);
      })
      .filter((time): time is number => time !== null);

    const averageReplyTime =
      replyTimes.length > 0
        ? Math.round(replyTimes.reduce((a, b) => a + b, 0) / replyTimes.length)
        : undefined;
    const fastestReplyTime =
      replyTimes.length > 0 ? Math.round(Math.min(...replyTimes)) : undefined;
    const slowestReplyTime =
      replyTimes.length > 0 ? Math.round(Math.max(...replyTimes)) : undefined;

    // Format for storage
    const bestContactTimesData = formatBestContactTimesForStorage(
      bestTimeWindows,
      messages.length,
      averageReplyTime,
      fastestReplyTime,
      slowestReplyTime
    );

    // Store in database
    await prisma.contact.update({
      where: { id: contactId },
      data: {
        bestContactTimes: bestContactTimesData as Prisma.InputJsonValue,
      },
    });

    return bestContactTimesData;
  } catch (error) {
    console.error(`[BestContactTimes] Error computing for contact ${contactId}:`, error);
    // Log more details about the error
    if (error instanceof Error) {
      console.error(`[BestContactTimes] Error message: ${error.message}`);
      console.error(`[BestContactTimes] Error stack: ${error.stack}`);
    }
    // Re-throw the error so the API can handle it properly
    throw error;
  }
}

/**
 * Compute best contact times for multiple contacts (batch processing).
 * 
 * @param contactIds - Array of contact IDs to process
 * @returns Map of contactId -> bestContactTimes data (or null if failed/insufficient data)
 */
export async function computeBestContactTimesBatch(
  contactIds: string[]
): Promise<Map<string, Record<string, unknown> | null>> {
  const results = new Map<string, Record<string, unknown> | null>();

  // Process in parallel with a reasonable concurrency limit
  const batchSize = 10;
  for (let i = 0; i < contactIds.length; i += batchSize) {
    const batch = contactIds.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (contactId) => {
        const result = await computeAndStoreBestContactTimes(contactId);
        return { contactId, result };
      })
    );

    for (const { contactId, result } of batchResults) {
      results.set(contactId, result);
    }
  }

  return results;
}

/**
 * Automatically assign best contact times to a contact with fallback logic.
 * Tries to compute from message history, falls back to similar contact, then defaults.
 * 
 * @param contactId - The contact ID to assign times to
 * @param organizationId - The organization ID for finding similar contacts
 * @returns The assigned best contact times data, or null if all methods failed
 */
export async function autoAssignBestContactTimes(
  contactId: string,
  organizationId: string
): Promise<Record<string, unknown> | null> {
  try {
    // Step 1: Try to compute from message history
    const computedTimes = await computeAndStoreBestContactTimes(contactId);
    if (computedTimes) {
      console.log(`[AutoAssignBestTimes] Successfully computed times for contact ${contactId} from message history`);
      return computedTimes;
    }

    // Step 2: Try to find similar contact with sufficient data
    const { findNearestContactWithBestTimes } = await import('./find-nearest-contact-times');
    const nearestContact = await findNearestContactWithBestTimes(contactId, organizationId);
    
    if (nearestContact) {
      // Use the nearest contact's best contact times
      const borrowedTimes = {
        ...nearestContact.bestContactTimes,
        borrowedFrom: nearestContact.contactId,
        borrowedSource: nearestContact.source,
        isBorrowed: true,
        originalContactId: contactId,
      };

      // Store borrowed times in database
      const { prisma } = await import('@/lib/db');
      await prisma.contact.update({
        where: { id: contactId },
        data: {
          bestContactTimes: borrowedTimes as Prisma.InputJsonValue,
        },
      });

      console.log(`[AutoAssignBestTimes] Assigned times from similar contact for ${contactId}`);
      return borrowedTimes;
    }

    // Step 3: Use default best contact times as final fallback
    const { getDefaultBestContactTimes } = await import('./default-contact-times');
    const defaultTimes = getDefaultBestContactTimes({ markAsDefault: true });

    // Store default times in database
    const { prisma } = await import('@/lib/db');
    await prisma.contact.update({
      where: { id: contactId },
      data: {
        bestContactTimes: defaultTimes as Prisma.InputJsonValue,
      },
    });

    console.log(`[AutoAssignBestTimes] Assigned default times for contact ${contactId}`);
    return defaultTimes;
  } catch (error) {
    console.error(`[AutoAssignBestTimes] Error assigning times for contact ${contactId}:`, error);
    return null;
  }
}





