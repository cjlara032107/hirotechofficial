import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { auth } from '@/auth';

// GET /api/ai-automations - List all automation rules for current user
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const rules = await prisma.aIAutomationRule.findMany({
      where: {
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
        _count: {
          select: {
            AIAutomationExecution: true,
            AIAutomationStop: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    // Transform to match frontend expectations
    const transformedRules = rules.map(rule => ({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      enabled: rule.enabled,
      customPrompt: rule.customPrompt,
      languageStyle: rule.languageStyle,
      timeIntervalMinutes: rule.timeIntervalMinutes,
      timeIntervalHours: rule.timeIntervalHours,
      timeIntervalDays: rule.timeIntervalDays,
      includeTags: rule.includeTags,
      excludeTags: rule.excludeTags,
      maxMessagesPerDay: rule.maxMessagesPerDay,
      activeHoursStart: rule.activeHoursStart,
      activeHoursEnd: rule.activeHoursEnd,
      run24_7: rule.run24_7,
      stopOnReply: rule.stopOnReply,
      removeTagOnReply: rule.removeTagOnReply,
      messageTag: rule.messageTag,
      facebookPageId: rule.facebookPageId,
      executionCount: rule.executionCount,
      successCount: rule.successCount,
      failureCount: rule.failureCount,
      lastExecutedAt: rule.lastExecutedAt?.toISOString() || null,
      createdAt: rule.createdAt.toISOString(),
      updatedAt: rule.updatedAt.toISOString(),
      facebookPage: rule.FacebookPage,
      _count: {
        executions: rule._count.AIAutomationExecution,
        stops: rule._count.AIAutomationStop,
      },
    }));

    return NextResponse.json({ rules: transformedRules });
  } catch (error) {
    console.error('[AI Automations] List error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch automation rules' },
      { status: 500 }
    );
  }
}

// POST /api/ai-automations - Create new automation rule
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
    
    const {
      name,
      description,
      customPrompt,
      languageStyle,
      facebookPageId,
      timeIntervalMinutes,
      timeIntervalHours,
      timeIntervalDays,
      maxMessagesPerDay,
      activeHoursStart,
      activeHoursEnd,
      run24_7,
      stopOnReply,
      removeTagOnReply,
      messageTag,
      enabled,
      includeTags,
      excludeTags,
    } = body;

    // Validation
    if (!name || !customPrompt) {
      return NextResponse.json(
        { error: 'Name and custom prompt are required' },
        { status: 400 }
      );
    }

    // Ensure at least one time interval is set
    if (!timeIntervalMinutes && !timeIntervalHours && !timeIntervalDays) {
      return NextResponse.json(
        { error: 'At least one time interval must be set' },
        { status: 400 }
      );
    }

    // Verify Facebook page belongs to user if specified
    if (facebookPageId) {
      const user = await prisma.user.findUnique({
        where: { id: session.user.id },
        select: { organizationId: true },
      });

      const page = await prisma.facebookPage.findFirst({
        where: {
          id: facebookPageId,
          organizationId: user?.organizationId,
        },
      });

      if (!page) {
        return NextResponse.json(
          { error: 'Invalid Facebook page' },
          { status: 400 }
        );
      }
    }

    // Create rule
    const rule = await prisma.aIAutomationRule.create({
      data: {
        id: `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        userId: session.user.id,
        name,
        description: description || null,
        customPrompt,
        languageStyle: languageStyle || 'taglish',
        facebookPageId: facebookPageId || null,
        timeIntervalMinutes: timeIntervalMinutes || null,
        timeIntervalHours: timeIntervalHours || null,
        timeIntervalDays: timeIntervalDays || null,
        maxMessagesPerDay: maxMessagesPerDay || 100,
        activeHoursStart: activeHoursStart || 9,
        activeHoursEnd: activeHoursEnd || 21,
        run24_7: run24_7 || false,
        stopOnReply: stopOnReply !== false, // Default true
        removeTagOnReply: removeTagOnReply || null,
        messageTag: messageTag || 'ACCOUNT_UPDATE',
        enabled: enabled !== false, // Default true
        includeTags: includeTags || [],
        excludeTags: excludeTags || [],
        updatedAt: new Date(),
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

    console.log(`[AI Automations] Created rule: ${rule.id} - ${rule.name}`);

    return NextResponse.json({
      rule: {
        ...rule,
        facebookPage: rule.FacebookPage,
      },
    });
  } catch (error) {
    console.error('[AI Automations] Create error:', error);
    return NextResponse.json(
      { error: 'Failed to create automation rule' },
      { status: 500 }
    );
  }
}

