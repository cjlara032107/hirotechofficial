import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { auth } from '@/auth';
import { validateBodySize, BodySizeLimits } from '@/lib/api/validate-body-size';
import { NumericPresets, validateNumeric } from '@/lib/api/validate-numeric';
import { RateLimitPresets } from '@/lib/api/rate-limit';
import { sanitizeForStorage, sanitizeStringArray } from '@/lib/security/sanitize';
import { logger } from '@/lib/utils/logger';

// GET /api/ai-automations - List all automation rules for current user
export async function GET(request: NextRequest) {
  // Apply rate limiting
  const rateLimitResponse = await RateLimitPresets.standard(request);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }
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
      respectBestContactTime: rule.respectBestContactTime ?? false,
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
    logger.error('AI Automations list error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json(
      { error: 'Failed to fetch automation rules' },
      { status: 500 }
    );
  }
}

// POST /api/ai-automations - Create new automation rule
export async function POST(request: NextRequest) {
  try {
    // Apply rate limiting
    const rateLimitResponse = await RateLimitPresets.standard(request);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    // Validate body size
    const bodySizeResponse = await validateBodySize(request, {
      maxSizeBytes: BodySizeLimits.MEDIUM,
    });
    if (bodySizeResponse) {
      return bodySizeResponse;
    }

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
      respectBestContactTime,
      removeTagOnReply,
      messageTag,
      enabled,
      includeTags,
      excludeTags,
    } = body;

    // Sanitize user input to prevent XSS
    const sanitizedName = name && typeof name === 'string' ? sanitizeForStorage(name) : '';
    const sanitizedDescription = description && typeof description === 'string' ? sanitizeForStorage(description) : null;
    const sanitizedCustomPrompt = customPrompt && typeof customPrompt === 'string' ? sanitizeForStorage(customPrompt) : '';
    const sanitizedLanguageStyle = languageStyle && typeof languageStyle === 'string' ? sanitizeForStorage(languageStyle) : 'taglish';
    const sanitizedMessageTag: MessageTag | null = messageTag && typeof messageTag === 'string' && Object.values(MessageTag).includes(messageTag as MessageTag) 
      ? (messageTag as MessageTag) 
      : MessageTag.ACCOUNT_UPDATE;
    const sanitizedRemoveTagOnReply = removeTagOnReply && typeof removeTagOnReply === 'string' ? sanitizeForStorage(removeTagOnReply) : null;
    const sanitizedIncludeTags = Array.isArray(includeTags) ? sanitizeStringArray(includeTags) : [];
    const sanitizedExcludeTags = Array.isArray(excludeTags) ? sanitizeStringArray(excludeTags) : [];

    // Validation
    if (!sanitizedName || !sanitizedCustomPrompt) {
      return NextResponse.json(
        { error: 'Name and custom prompt are required' },
        { status: 400 }
      );
    }

    // Validate numeric inputs
    const numericValidations = [
      timeIntervalMinutes !== null && timeIntervalMinutes !== undefined
        ? NumericPresets.timeIntervalMinutes(timeIntervalMinutes, 'Time interval (minutes)')
        : null,
      timeIntervalHours !== null && timeIntervalHours !== undefined
        ? NumericPresets.timeIntervalHours(timeIntervalHours, 'Time interval (hours)')
        : null,
      timeIntervalDays !== null && timeIntervalDays !== undefined
        ? NumericPresets.timeIntervalDays(timeIntervalDays, 'Time interval (days)')
        : null,
      maxMessagesPerDay !== null && maxMessagesPerDay !== undefined
        ? NumericPresets.count(maxMessagesPerDay, 10000, 'Max messages per day')
        : null,
      activeHoursStart !== null && activeHoursStart !== undefined
        ? NumericPresets.hourOfDay(activeHoursStart, 'Active hours start')
        : null,
      activeHoursEnd !== null && activeHoursEnd !== undefined
        ? NumericPresets.hourOfDay(activeHoursEnd, 'Active hours end')
        : null,
    ].filter((v): v is NonNullable<typeof v> => v !== null);

    for (const validation of numericValidations) {
      if (!validation.valid) {
        return NextResponse.json(
          { error: validation.errors.join(', ') },
          { status: 400 }
        );
      }
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
        name: sanitizedName,
        description: sanitizedDescription,
        customPrompt: sanitizedCustomPrompt,
        languageStyle: sanitizedLanguageStyle,
        facebookPageId: facebookPageId || null,
        timeIntervalMinutes: timeIntervalMinutes || null,
        timeIntervalHours: timeIntervalHours || null,
        timeIntervalDays: timeIntervalDays || null,
        maxMessagesPerDay: maxMessagesPerDay || 100,
        activeHoursStart: activeHoursStart || 9,
        activeHoursEnd: activeHoursEnd || 21,
        run24_7: run24_7 || false,
        stopOnReply: stopOnReply !== false, // Default true
        removeTagOnReply: sanitizedRemoveTagOnReply,
        messageTag: sanitizedMessageTag,
        enabled: enabled !== false, // Default true
        includeTags: sanitizedIncludeTags,
        excludeTags: sanitizedExcludeTags,
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

    logger.info('AI Automation rule created', { ruleId: rule.id, ruleName: rule.name, userId: session.user.id });

    return NextResponse.json({
      rule: {
        ...rule,
        facebookPage: rule.FacebookPage,
      },
    });
  } catch (error) {
    logger.error('AI Automations create error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json(
      { error: 'Failed to create automation rule' },
      { status: 500 }
    );
  }
}

