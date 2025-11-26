import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { auth } from '@/auth';

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

    // Verify rule belongs to user
    const rule = await prisma.aIAutomationRule.findFirst({
      where: {
        id: ruleId,
        userId: session.user.id,
      },
    });

    if (!rule) {
      return NextResponse.json(
        { error: 'Automation rule not found' },
        { status: 404 }
      );
    }

    // Get pagination parameters
    const searchParams = request.nextUrl.searchParams;
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '50');
    const skip = (page - 1) * limit;

    // Get executions with pagination
    const [executions, total] = await Promise.all([
      prisma.aIAutomationExecution.findMany({
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
      prisma.aIAutomationExecution.count({
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
    console.error('[AI Automations] Get executions error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch execution history' },
      { status: 500 }
    );
  }
}



