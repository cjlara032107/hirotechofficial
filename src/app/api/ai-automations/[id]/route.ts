import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { auth } from '@/auth';
import { logger } from '@/lib/utils/logger';

// Helper function to log DB routing
async function logDbRouting(organizationId: string, operation: string) {
  logger.info(`[Automation API] ${operation}`, {
    organizationId,
    multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    routingStrategy: process.env.DB_ROUTING_STRATEGY || 'hash',
  });

  if (process.env.ENABLE_MULTI_DB === 'true') {
    try {
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const client = router.getClient(organizationId);
      const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
      
      if (dbConfig) {
        const dbHost = new URL(dbConfig.url).hostname;
        logger.info(`[Automation API] ${operation}: Routed DB`, {
          organizationId,
          dbIndex: dbConfig.index,
          dbHost,
          dbHealth: dbConfig.health,
        });
      }
    } catch (error) {
      logger.warn(`[Automation API] ${operation}: Could not log routing details`, { 
        error: error instanceof Error ? error.message : String(error) 
      });
    }
  }
}

// GET /api/ai-automations/[id] - Get specific automation rule
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

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation API] Get: User has no organization', new Error('Missing organization'), { 
        userId: session.user.id,
        ruleId: id,
      });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    await logDbRouting(user.organizationId, `Get rule ${id}`);

    const rule = await db.aIAutomationRule.findFirst({
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
        _count: {
          select: {
            AIAutomationExecution: true,
            AIAutomationStop: true,
          },
        },
      },
    });

    if (!rule) {
      logger.warn('[Automation API] Get: Rule not found in routed DB', {
        ruleId: id,
        userId: session.user.id,
        organizationId: user.organizationId,
      });
      
      return NextResponse.json(
        { 
          error: 'Automation rule not found',
          details: process.env.ENABLE_MULTI_DB === 'true' 
            ? 'Rule not found in routed database. Check DB1/DB2 connectivity.' 
            : undefined,
        },
        { status: 404 }
      );
    }

    logger.info('[Automation API] Get success', {
      ruleId: id,
      userId: session.user.id,
      organizationId: user.organizationId,
    });

    return NextResponse.json({
      rule: {
        ...rule,
        facebookPage: rule.FacebookPage,
        _count: {
          executions: rule._count.AIAutomationExecution,
          stops: rule._count.AIAutomationStop,
        },
      },
    });
  } catch (error) {
    const { id } = await params;
    logger.error('[Automation API] Get error', error instanceof Error ? error : new Error(String(error)), {
      ruleId: id,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch automation rule';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to fetch automation rule',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
      { status: 500 }
    );
  }
}

// PATCH /api/ai-automations/[id] - Update automation rule
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  let id: string | undefined;
  try {
    const session = await auth();
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const paramsData = await params;
    id = paramsData.id;
    const body = await request.json();

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation API] Update: User has no organization', new Error('Missing organization'), { 
        userId: session.user.id,
        ruleId: id,
      });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    await logDbRouting(user.organizationId, `Update rule ${id}`);

    // Verify rule belongs to user (org integrity check)
    const existingRule = await db.aIAutomationRule.findFirst({
      where: {
        id,
        userId: session.user.id,
      },
    });

    if (!existingRule) {
      logger.warn('[Automation API] Update: Rule not found or access denied', {
        ruleId: id,
        userId: session.user.id,
        organizationId: user.organizationId,
      });
      
      return NextResponse.json(
        { 
          error: 'Automation rule not found or access denied',
          details: process.env.ENABLE_MULTI_DB === 'true' 
            ? 'Rule not found in routed database. Check DB1/DB2 connectivity.' 
            : undefined,
        },
        { status: 404 }
      );
    }

    // Verify Facebook page belongs to user's organization if being updated
    if (body.facebookPageId) {
      const page = await db.facebookPage.findFirst({
        where: {
          id: body.facebookPageId,
          organizationId: user.organizationId,
        },
      });

      if (!page) {
        logger.warn('[Automation API] Update: Invalid Facebook page', {
          facebookPageId: body.facebookPageId,
          organizationId: user.organizationId,
          ruleId: id,
          userId: session.user.id,
        });
        
        return NextResponse.json(
          { error: 'Invalid Facebook page or page does not belong to your organization' },
          { status: 403 }
        );
      }
    }

    // Update rule
    const updatedRule = await db.aIAutomationRule.update({
      where: { id },
      data: {
        ...body,
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

    logger.info('[Automation API] Update success', { 
      ruleId: id, 
      userId: session.user.id,
      organizationId: user.organizationId,
      changedFields: Object.keys(body),
    });

    return NextResponse.json({
      rule: {
        ...updatedRule,
        facebookPage: updatedRule.FacebookPage,
      },
    });
  } catch (error) {
    logger.error('[Automation API] Update error', error instanceof Error ? error : new Error(String(error)), {
      ruleId: id,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    const errorMessage = error instanceof Error ? error.message : 'Failed to update automation rule';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to update automation rule',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
      { status: 500 }
    );
  }
}

// DELETE /api/ai-automations/[id] - Delete automation rule
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  let id: string | undefined;
  try {
    const session = await auth();
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const paramsData = await params;
    id = paramsData.id;

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation API] Delete: User has no organization', new Error('Missing organization'), { 
        userId: session.user.id,
        ruleId: id,
      });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    await logDbRouting(user.organizationId, `Delete rule ${id}`);

    // Verify rule belongs to user (org integrity check)
    const existingRule = await db.aIAutomationRule.findFirst({
      where: {
        id,
        userId: session.user.id,
      },
    });

    if (!existingRule) {
      logger.warn('[Automation API] Delete: Rule not found or access denied', {
        ruleId: id,
        userId: session.user.id,
        organizationId: user.organizationId,
      });
      
      return NextResponse.json(
        { 
          error: 'Automation rule not found or access denied',
          details: process.env.ENABLE_MULTI_DB === 'true' 
            ? 'Rule not found in routed database. Check DB1/DB2 connectivity.' 
            : undefined,
        },
        { status: 404 }
      );
    }

    // Delete rule (cascade will delete executions and stops)
    await db.aIAutomationRule.delete({
      where: { id },
    });

    logger.info('[Automation API] Delete success', { 
      ruleId: id, 
      userId: session.user.id,
      organizationId: user.organizationId,
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error('[Automation API] Delete error', error instanceof Error ? error : new Error(String(error)), {
      ruleId: id,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    const errorMessage = error instanceof Error ? error.message : 'Failed to delete automation rule';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to delete automation rule',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
      { status: 500 }
    );
  }
}
