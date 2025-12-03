import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { auth } from '@/auth';
import { logger } from '@/lib/utils/logger';

/**
 * GET /api/ai-automations/[id]/executions
 * Get execution history for a specific automation rule
 */
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

    const { id: ruleId } = await params;

    // Get user's organization for multi-DB routing
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { organizationId: true },
    });

    if (!user?.organizationId) {
      logger.error('[Automation API] Get executions: User has no organization', new Error('Missing organization'), { 
        userId: session.user.id,
        ruleId,
      });
      return NextResponse.json(
        { error: 'User organization not found' },
        { status: 400 }
      );
    }

    // ⭐ MULTI-DB ROUTING: Get Prisma client for user's organization
    const db = getPrismaForOrg(user.organizationId);
    
    // Log routing information
    logger.info('[Automation API] Get executions start', {
      ruleId,
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
          logger.info('[Automation API] Get executions: Routed DB', {
            organizationId: user.organizationId,
            ruleId,
            dbIndex: dbConfig.index,
            dbHost,
            dbHealth: dbConfig.health,
          });
        }
      } catch (error) {
        logger.warn('[Automation API] Get executions: Could not log routing details', { 
          error: error instanceof Error ? error.message : String(error) 
        });
      }
    }

    // Verify rule belongs to user (org integrity check)
    const rule = await db.aIAutomationRule.findFirst({
      where: {
        id: ruleId,
        userId: session.user.id,
      },
    });

    if (!rule) {
      logger.warn('[Automation API] Get executions: Rule not found or access denied', {
        ruleId,
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

    // Get pagination parameters
    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    // Reduced default page size for better performance
    const limit = parseInt(searchParams.get('limit') || '25');
    const skip = (page - 1) * limit;

    // Get executions with pagination
    const [executions, total] = await Promise.all([
      db.aIAutomationExecution.findMany({
        where: {
          ruleId,
        },
        include: {
          Contact: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              profilePicUrl: true,
            },
          },
        },
        orderBy: {
          executedAt: 'desc',
        },
        skip,
        take: limit,
      }),
      db.aIAutomationExecution.count({
        where: {
          ruleId,
        },
      }),
    ]);

    // Transform executions
    const transformedExecutions = executions.map(exec => ({
      id: exec.id,
      contactId: exec.contactId,
      contact: exec.Contact,
      recipientName: exec.recipientName,
      status: exec.status,
      generatedMessage: exec.generatedMessage,
      aiReasoning: exec.aiReasoning,
      errorMessage: exec.errorMessage,
      facebookMessageId: exec.facebookMessageId,
      executedAt: exec.executedAt.toISOString(),
      createdAt: exec.createdAt.toISOString(),
    }));

    logger.info('[Automation API] Get executions success', {
      ruleId,
      userId: session.user.id,
      organizationId: user.organizationId,
      executionsCount: transformedExecutions.length,
      total,
      page,
      limit,
    });

    return NextResponse.json({
      executions: transformedExecutions,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    const { id: ruleId } = await params;
    logger.error('[Automation API] Get executions error', error instanceof Error ? error : new Error(String(error)), {
      ruleId,
      userId: session?.user?.id,
      multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
    });
    
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch execution history';
    const isDbError = errorMessage.includes('database') || errorMessage.includes('connection') || errorMessage.includes('timeout');
    
    return NextResponse.json(
      { 
        error: isDbError 
          ? 'Database connection error. Please check DB1/DB2 connectivity and try again.' 
          : 'Failed to fetch execution history',
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
      },
      { status: 500 }
    );
  }
}
