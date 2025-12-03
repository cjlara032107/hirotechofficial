import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { auth } from '@/auth';
import { validateBodySize, BodySizeLimits } from '@/lib/api/validate-body-size';
import { NumericPresets, validateNumeric } from '@/lib/api/validate-numeric';
import { RateLimitPresets } from '@/lib/api/rate-limit';
import { sanitizeForStorage, sanitizeStringArray } from '@/lib/security/sanitize';
import { logger } from '@/lib/utils/logger';
import { MessageTag } from '@prisma/client';

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

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation API] User has no organization', new Error('Missing organization'), { userId: session.user.id });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    
    // Log routing information
    logger.info('[Automation API] List', {
      userId: session.user.id,
      organizationId: user.organizationId,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      routingStrategy: process.env.DB_ROUTING_STRATEGY || 'hash',
    });

    // Log routed DB details if multi-DB is enabled
    if (process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        
        if (dbConfig) {
          const dbHost = new URL(dbConfig.url).hostname;
          logger.info('[Automation API] Routed DB', {
            organizationId: user.organizationId,
            dbIndex: dbConfig.index,
            dbHost,
            dbHealth: dbConfig.health,
          });
        }
      } catch (error) {
        logger.warn('[Automation API] Could not log routing details', { error: error instanceof Error ? error.message : String(error) });
      }
    }

    const rules = await db.aIAutomationRule.findMany({
      where: {
        userId: session.user.id,
        // Org integrity: Only return automations for this org's user
        // (userId already scopes this, but being explicit for clarity)
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

    logger.info('[Automation API] List success', {
      userId: session.user.id,
      organizationId: user.organizationId,
      rulesCount: transformedRules.length,
    });

    return NextResponse.json({ rules: transformedRules });
  } catch (error) {
    logger.error('AI Automations list error', error instanceof Error ? error : new Error(String(error)), {
      userId: session?.user?.id,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    // Provide helpful error message
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch automation rules';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to fetch automation rules',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
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

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation API] Create: User has no organization', new Error('Missing organization'), { userId: session.user.id });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    
    // Log routing information
    logger.info('[Automation API] Create start', {
      userId: session.user.id,
      organizationId: user.organizationId,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      routingStrategy: process.env.DB_ROUTING_STRATEGY || 'hash',
    });

    // Log routed DB details if multi-DB is enabled
    if (process.env.ENABLE_MULTI_DB === 'true') {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        
        if (dbConfig) {
          const dbHost = new URL(dbConfig.url).hostname;
          logger.info('[Automation API] Create: Routed DB', {
            organizationId: user.organizationId,
            dbIndex: dbConfig.index,
            dbHost,
            dbHealth: dbConfig.health,
          });
        }
      } catch (error) {
        logger.warn('[Automation API] Create: Could not log routing details', { error: error instanceof Error ? error.message : String(error) });
      }
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

    // Verify Facebook page belongs to user's organization if specified
    if (facebookPageId) {
      const page = await db.facebookPage.findFirst({
        where: {
          id: facebookPageId,
          organizationId: user.organizationId,
        },
      });

      if (!page) {
        logger.warn('[Automation API] Create: Invalid Facebook page', {
          facebookPageId,
          organizationId: user.organizationId,
          userId: session.user.id,
        });
        return NextResponse.json(
          { error: 'Invalid Facebook page or page does not belong to your organization' },
          { status: 403 }
        );
      }
    }

    // Create rule
    const rule = await db.aIAutomationRule.create({
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

    logger.info('[Automation API] Create success', { 
      ruleId: rule.id, 
      ruleName: rule.name, 
      userId: session.user.id,
      organizationId: user.organizationId,
      facebookPageId: rule.facebookPageId || 'none',
    });

    return NextResponse.json({
      rule: {
        ...rule,
        facebookPage: rule.FacebookPage,
      },
    });
  } catch (error) {
    logger.error('[Automation API] Create error', error instanceof Error ? error : new Error(String(error)), {
      userId: session?.user?.id,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    // Provide helpful error message
    const errorMessage = error instanceof Error ? error.message : 'Failed to create automation rule';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to create automation rule',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
      { status: 500 }
    );
  }
}

