/**
 * Conflict Prevention Utilities for AI Automations
 * Prevents conflicts with Campaigns, Pipelines, and Team activities
 */

import { prisma } from '@/lib/db';

/**
 * Check if contact is currently in an active campaign
 * Prevents AI automation from messaging contacts in campaigns
 */
export async function isContactInActiveCampaign(contactId: string): Promise<boolean> {
  try {
    const activeCampaignMessage = await prisma.message.findFirst({
      where: {
        contactId,
        campaignId: {
          not: null,
        },
        campaign: {
          status: {
            in: ['SENDING', 'SCHEDULED'],
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return !!activeCampaignMessage;
  } catch (error) {
    console.error('[Conflict Prevention] Error checking campaign status:', error);
    return false; // Fail open - allow automation
  }
}

/**
 * Check if contact was recently contacted (within last N hours)
 * Prevents spam from multiple automation sources
 */
export async function wasContactRecentlyContacted(
  contactId: string,
  hoursThreshold: number = 12
): Promise<boolean> {
  try {
    const thresholdDate = new Date();
    thresholdDate.setHours(thresholdDate.getHours() - hoursThreshold);

    const recentMessage = await prisma.message.findFirst({
      where: {
        contactId,
        isFromBusiness: true,
        sentAt: {
          gte: thresholdDate,
        },
      },
      orderBy: {
        sentAt: 'desc',
      },
    });

    return !!recentMessage;
  } catch (error) {
    console.error('[Conflict Prevention] Error checking recent contact:', error);
    return false;
  }
}

/**
 * Check if contact is in a "closed" pipeline stage (Won/Lost/Archived)
 * Prevents messaging contacts who already converted or were lost
 */
export async function isContactInClosedStage(contactId: string): Promise<boolean> {
  try {
    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
      include: {
        stage: {
          select: {
            type: true,
          },
        },
      },
    });

    if (!contact?.stage) {
      return false;
    }

    // Check if stage type is WON, LOST, or ARCHIVED
    const closedStageTypes = ['WON', 'LOST', 'ARCHIVED'];
    return closedStageTypes.includes(contact.stage.type);
  } catch (error) {
    console.error('[Conflict Prevention] Error checking stage status:', error);
    return false;
  }
}

/**
 * Check if contact has any of the excluded tags
 */
export async function hasExcludedTags(
  contactId: string,
  excludedTags: string[]
): Promise<boolean> {
  if (excludedTags.length === 0) {
    return false;
  }

  try {
    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
      select: { tags: true },
    });

    if (!contact) {
      return false;
    }

    // Check if contact has any of the excluded tags
    return excludedTags.some(tag => contact.tags.includes(tag));
  } catch (error) {
    console.error('[Conflict Prevention] Error checking excluded tags:', error);
    return false;
  }
}

/**
 * Check if there's an active team conversation with this contact
 * Prevents interrupting live chat sessions
 */
export async function isContactInActiveChatSession(contactId: string): Promise<boolean> {
  try {
    // Check for recent messages (within last 2 hours)
    const twoHoursAgo = new Date();
    twoHoursAgo.setHours(twoHoursAgo.getHours() - 2);

    const recentActivity = await prisma.message.findFirst({
      where: {
        contactId,
        createdAt: {
          gte: twoHoursAgo,
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    // If there's recent activity (within 2 hours), consider it an active session
    if (recentActivity) {
      const timeDiff = new Date().getTime() - recentActivity.createdAt.getTime();
      const minutesAgo = Math.floor(timeDiff / (1000 * 60));
      
      // Active if last message was within 30 minutes
      return minutesAgo <= 30;
    }

    return false;
  } catch (error) {
    console.error('[Conflict Prevention] Error checking chat session:', error);
    return false;
  }
}

/**
 * Comprehensive eligibility check for AI automation
 * Combines all conflict prevention checks
 */
export async function isContactEligibleForAutomation(
  contactId: string,
  excludedTags: string[] = [],
  bypassRecentContactCheck: boolean = false
): Promise<{
  eligible: boolean;
  reason?: string;
}> {
  try {
    // Check 1: In active campaign?
    if (await isContactInActiveCampaign(contactId)) {
      return {
        eligible: false,
        reason: 'Contact is in an active campaign',
      };
    }

    // Check 2: Recently contacted? (can be bypassed for manual testing)
    if (!bypassRecentContactCheck && await wasContactRecentlyContacted(contactId, 12)) {
      return {
        eligible: false,
        reason: 'Contact was messaged within last 12 hours',
      };
    }

    // Check 3: In closed stage?
    if (await isContactInClosedStage(contactId)) {
      return {
        eligible: false,
        reason: 'Contact is in Won/Lost/Archived stage',
      };
    }

    // Check 4: Has excluded tags?
    if (await hasExcludedTags(contactId, excludedTags)) {
      return {
        eligible: false,
        reason: 'Contact has excluded tag',
      };
    }

    // Check 5: In active chat session?
    if (await isContactInActiveChatSession(contactId)) {
      return {
        eligible: false,
        reason: 'Contact is in active chat session',
      };
    }

    return { eligible: true };
  } catch (error) {
    console.error('[Conflict Prevention] Error checking eligibility:', error);
    return {
      eligible: false,
      reason: 'Error during eligibility check',
    };
  }
}

/**
 * Get safe send time window
 * Returns current time if within safe window, or next safe time
 */
export function getSafeSendTimeWindow(
  activeHoursStart: number,
  activeHoursEnd: number,
  run24_7: boolean = false
): {
  canSendNow: boolean;
  nextSafeTime?: Date;
} {
  if (run24_7) {
    return { canSendNow: true };
  }

  const now = new Date();
  const currentHour = now.getHours();

  // Normal time range (e.g., 9 AM - 9 PM)
  if (activeHoursEnd > activeHoursStart) {
    const isWithinHours = currentHour >= activeHoursStart && currentHour < activeHoursEnd;
    
    if (isWithinHours) {
      return { canSendNow: true };
    }

    // Calculate next safe time
    const nextSafe = new Date(now);
    if (currentHour >= activeHoursEnd) {
      // After end time, wait until tomorrow's start time
      nextSafe.setDate(nextSafe.getDate() + 1);
      nextSafe.setHours(activeHoursStart, 0, 0, 0);
    } else {
      // Before start time, wait until today's start time
      nextSafe.setHours(activeHoursStart, 0, 0, 0);
    }

    return {
      canSendNow: false,
      nextSafeTime: nextSafe,
    };
  }

  // Crosses midnight (e.g., 9 PM - 9 AM)
  const isWithinHours = currentHour >= activeHoursStart || currentHour < activeHoursEnd;
  
  if (isWithinHours) {
    return { canSendNow: true };
  }

  // Calculate next safe time
  const nextSafe = new Date(now);
  nextSafe.setHours(activeHoursStart, 0, 0, 0);

  return {
    canSendNow: false,
    nextSafeTime: nextSafe,
  };
}

/**
 * Check if daily limit has been reached
 */
export async function hasReachedDailyLimit(
  ruleId: string,
  maxMessagesPerDay: number
): Promise<boolean> {
  try {
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const todayCount = await prisma.aIAutomationExecution.count({
      where: {
        ruleId,
        executedAt: {
          gte: todayStart,
        },
        status: 'sent',
      },
    });

    return todayCount >= maxMessagesPerDay;
  } catch (error) {
    console.error('[Conflict Prevention] Error checking daily limit:', error);
    return true; // Fail safe - don't send if error
  }
}

