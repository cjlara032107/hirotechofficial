import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { auth } from '@/auth';

// GET /api/ai-automations/[id]/details - Get detailed information about a rule
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { id } = await params;

    // Get rule
    const rule = await prisma.aIAutomationRule.findFirst({
      where: {
        id,
        userId: session.user.id,
      },
      include: {
        FacebookPage: {
          select: {
            id: true,
            pageName: true,
            pageId: true,
          },
        },
      },
    });

    if (!rule) {
      return NextResponse.json(
        { error: 'Automation rule not found' },
        { status: 404 }
      );
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

    // Build where clause for finding eligible contacts
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const whereClause: Record<string, any> = {
      organizationId: user.organizationId,
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

    // Get all contacts that match the rule criteria
    let matchingContacts = await prisma.contact.findMany({
      where: whereClause,
      include: {
        facebookPage: {
          select: {
            id: true,
            pageName: true,
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
        },
      },
    });

    // Exclude contacts with excluded tags
    if (rule.excludeTags.length > 0) {
      matchingContacts = matchingContacts.filter(contact => {
        return !rule.excludeTags.some(tag => contact.tags.includes(tag));
      });
    }

    // Get stopped contacts for this rule
    const stoppedContacts = await prisma.aIAutomationStop.findMany({
      where: {
        ruleId: rule.id,
      },
      select: {
        contactId: true,
        stoppedReason: true,
        followUpsSent: true,
        createdAt: true,
      },
    });

    const stoppedContactIds = new Set(stoppedContacts.map(s => s.contactId));
    const stoppedMap = new Map(
      stoppedContacts.map(s => [s.contactId, s])
    );

    // Get recent executions for each contact
    const recentExecutions = await prisma.aIAutomationExecution.findMany({
      where: {
        ruleId: rule.id,
        contactId: {
          in: matchingContacts.map(c => c.id),
        },
      },
      orderBy: {
        executedAt: 'desc',
      },
      take: 100, // Limit to recent executions
    });

    // Group executions by contact
    const executionsByContact = new Map<string, typeof recentExecutions>();
    for (const execution of recentExecutions) {
      if (!executionsByContact.has(execution.contactId)) {
        executionsByContact.set(execution.contactId, []);
      }
      executionsByContact.get(execution.contactId)!.push(execution);
    }

    // Process contacts and calculate trigger times
    const contactsData = matchingContacts.map(contact => {
      const lastInteraction = contact.lastInteraction || contact.createdAt;
      const nextTriggerTime = new Date(lastInteraction.getTime() + thresholdMs);
      const isEligible = now >= nextTriggerTime;
      const isStopped = stoppedContactIds.has(contact.id);
      const stopInfo = stoppedMap.get(contact.id);
      const executions = executionsByContact.get(contact.id) || [];

      // Calculate time until trigger or time since eligible
      const timeUntilTrigger = isEligible 
        ? 0 
        : Math.max(0, nextTriggerTime.getTime() - now.getTime());
      
      const timeSinceEligible = isEligible
        ? Math.max(0, now.getTime() - nextTriggerTime.getTime())
        : 0;

      return {
        id: contact.id,
        firstName: contact.firstName,
        lastName: contact.lastName,
        profilePicUrl: contact.profilePicUrl,
        tags: contact.tags,
        lastInteraction: lastInteraction.toISOString(),
        nextTriggerTime: nextTriggerTime.toISOString(),
        isEligible,
        isStopped,
        stopInfo: stopInfo ? {
          reason: stopInfo.stoppedReason,
          followUpsSent: stopInfo.followUpsSent,
          stoppedAt: stopInfo.createdAt.toISOString(),
        } : null,
        executions: executions.map(e => ({
          id: e.id,
          status: e.status,
          executedAt: e.executedAt.toISOString(),
          generatedMessage: e.generatedMessage,
          errorMessage: e.errorMessage,
        })),
        timeUntilTriggerMs: timeUntilTrigger,
        timeSinceEligibleMs: timeSinceEligible,
        facebookPage: contact.facebookPage,
      };
    });

    // Sort contacts: eligible first, then by next trigger time
    contactsData.sort((a, b) => {
      if (a.isEligible !== b.isEligible) {
        return a.isEligible ? -1 : 1;
      }
      if (a.isStopped !== b.isStopped) {
        return a.isStopped ? 1 : -1;
      }
      return a.nextTriggerTime.localeCompare(b.nextTriggerTime);
    });

    // Calculate statistics
    const eligibleCount = contactsData.filter(c => c.isEligible && !c.isStopped).length;
    const stoppedCount = contactsData.filter(c => c.isStopped).length;
    const totalMatching = contactsData.length;

    return NextResponse.json({
      rule: {
        id: rule.id,
        name: rule.name,
        includeTags: rule.includeTags,
        excludeTags: rule.excludeTags,
        timeIntervalMinutes: rule.timeIntervalMinutes,
        timeIntervalHours: rule.timeIntervalHours,
        timeIntervalDays: rule.timeIntervalDays,
        enabled: rule.enabled,
        facebookPage: rule.FacebookPage,
      },
      contacts: contactsData,
      statistics: {
        totalMatching,
        eligibleCount,
        stoppedCount,
        ineligibleCount: totalMatching - eligibleCount - stoppedCount,
      },
    });
  } catch (error) {
    console.error('[AI Automations] Details error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch automation details' },
      { status: 500 }
    );
  }
}

