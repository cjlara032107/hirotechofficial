import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { auth } from '@/auth';
import { logger } from '@/lib/utils/logger';

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
        _count: {
          select: {
            AIAutomationExecution: true,
            AIAutomationStop: true,
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
    logger.error('AI Automations get error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json(
      { error: 'Failed to fetch automation rule' },
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

    // Verify rule belongs to user
    const existingRule = await prisma.aIAutomationRule.findFirst({
      where: {
        id,
        userId: session.user.id,
      },
    });

    if (!existingRule) {
      return NextResponse.json(
        { error: 'Automation rule not found' },
        { status: 404 }
      );
    }

    // Verify Facebook page belongs to user if being updated
    if (body.facebookPageId) {
      const user = await prisma.user.findUnique({
        where: { id: session.user.id },
        select: { organizationId: true },
      });

      const page = await prisma.facebookPage.findFirst({
        where: {
          id: body.facebookPageId,
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

    // Update rule
    const updatedRule = await prisma.aIAutomationRule.update({
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

    logger.info('AI Automation rule updated', { ruleId: id, userId: session.user.id });

    return NextResponse.json({
      rule: {
        ...updatedRule,
        facebookPage: updatedRule.FacebookPage,
      },
    });
  } catch (error) {
    logger.error('AI Automations update error', error instanceof Error ? error : new Error(String(error)), id ? { ruleId: id } : {});
    return NextResponse.json(
      { error: 'Failed to update automation rule' },
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

    // Verify rule belongs to user
    const existingRule = await prisma.aIAutomationRule.findFirst({
      where: {
        id,
        userId: session.user.id,
      },
    });

    if (!existingRule) {
      return NextResponse.json(
        { error: 'Automation rule not found' },
        { status: 404 }
      );
    }

    // Delete rule (cascade will delete executions and stops)
    await prisma.aIAutomationRule.delete({
      where: { id },
    });

    logger.info('AI Automation rule deleted', { ruleId: id, userId: session.user.id });

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error('AI Automations delete error', error instanceof Error ? error : new Error(String(error)), id ? { ruleId: id } : {});
    return NextResponse.json(
      { error: 'Failed to delete automation rule' },
      { status: 500 }
    );
  }
}

