import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';

export async function GET() {
  try {
    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const campaigns = await prisma.campaign.findMany({
      where: { organizationId: validatedSession.user.organizationId },
      orderBy: { createdAt: 'desc' },
      include: {
        template: true,
        facebookPage: true,
        _count: {
          select: { messages: true },
        },
      },
    });

    return NextResponse.json(campaigns);
  } catch (error) {
    const err = error as Error;
    console.error('Get campaigns error:', err);
    return NextResponse.json(
      { error: 'Failed to fetch campaigns' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const body = await request.json();
    const {
      name,
      description,
      platform,
      messageTag,
      facebookPageId,
      templateId,
      targetingType,
      targetTags,
      targetStageIds,
      targetContactIds,
      rateLimit,
      // Scheduling fields
      scheduledAt,
      autoFetchEnabled,
      includeTags,
      excludeTags,
      // AI Personalization fields
      useAiPersonalization,
      aiCustomInstructions,
      aiMessagesMap,
    } = body;

    // Determine campaign status based on scheduling
    let status: 'DRAFT' | 'SCHEDULED' = 'DRAFT';
    if (scheduledAt) {
      // Validate schedule time is in the future
      const scheduleDate = new Date(scheduledAt);
      if (scheduleDate <= new Date()) {
        return NextResponse.json(
          { error: 'Scheduled time must be in the future' },
          { status: 400 }
        );
      }
      status = 'SCHEDULED';
    }

    const campaign = await prisma.campaign.create({
      data: {
        name,
        description,
        platform,
        messageTag,
        facebookPageId,
        templateId,
        targetingType,
        targetTags: targetTags || [],
        targetStageIds: targetStageIds || [],
        targetContactIds: targetContactIds || [],
        rateLimit: rateLimit || 3600, // Default: 1 message per second
        organizationId: validatedSession.user.organizationId,
        createdById: validatedSession.user.id,
        // Scheduling
        status,
        scheduledAt: scheduledAt ? new Date(scheduledAt) : null,
        ...(autoFetchEnabled !== undefined && { autoFetchEnabled }),
        ...(includeTags && { includeTags }),
        ...(excludeTags && { excludeTags }),
        // AI Personalization
        ...(useAiPersonalization !== undefined && { useAiPersonalization }),
        ...(aiCustomInstructions && { aiCustomInstructions }),
        ...(aiMessagesMap && { 
          aiMessagesMap: typeof aiMessagesMap === 'string' 
            ? JSON.parse(aiMessagesMap) 
            : aiMessagesMap 
        }),
      } as any, // Type assertion needed for fields that may not be in generated types yet
    });

    return NextResponse.json(campaign);
  } catch (error) {
    const err = error as Error;
    console.error('Create campaign error:', err);
    return NextResponse.json(
      { error: 'Failed to create campaign' },
      { status: 500 }
    );
  }
}

