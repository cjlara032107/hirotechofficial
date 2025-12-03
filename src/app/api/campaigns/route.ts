import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { validateSession } from '@/lib/api/validate-session';
import { validateBodySize, BodySizeLimits } from '@/lib/api/validate-body-size';
import { NumericPresets } from '@/lib/api/validate-numeric';
import { RateLimitPresets } from '@/lib/api/rate-limit';
import { sanitizeForStorage } from '@/lib/security/sanitize';

export async function GET(request: NextRequest) {
  // Apply rate limiting
  const rateLimitResponse = await RateLimitPresets.standard(request);
  if (rateLimitResponse) {
    return rateLimitResponse;
  }
  try {
    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const multiDbEnabled = process.env.ENABLE_MULTI_DB === 'true';
    console.log('[Campaign API GET] Start', {
      orgId: validatedSession.user.organizationId,
      multiDb: multiDbEnabled,
      strategy: process.env.DB_ROUTING_STRATEGY || 'hash',
    });

    // Use multi-DB routing
    const db = getPrismaForOrg(validatedSession.user.organizationId);

    // Log routed database details
    if (multiDbEnabled) {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(validatedSession.user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        console.log('[Campaign API GET] Routed DB', {
          organizationId: validatedSession.user.organizationId,
          dbIndex: dbConfig?.index,
          dbUrlHost: dbConfig ? new URL(dbConfig.url).hostname : 'unknown',
          dbHealth: dbConfig?.health,
        });
      } catch (err) {
        console.warn('[Campaign API GET] Could not log DB routing details:', err);
      }
    }

    const campaigns = await db.campaign.findMany({
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
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    const body = await request.json();
    let {
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
      // Media fields
      mediaUrl,
      mediaType,
      // Send-to-all flag
      sendToAll,
    } = body;

    const multiDbEnabled = process.env.ENABLE_MULTI_DB === 'true';
    console.log('[Campaign API POST] Start', {
      orgId: validatedSession.user.organizationId,
      name,
      platform,
      targetingType,
      sendToAll: !!sendToAll,
      contactIdsCount: targetContactIds?.length || 0,
      scheduledAt: scheduledAt || 'immediate',
      useAiPersonalization: !!useAiPersonalization,
      hasMedia: !!(mediaUrl && mediaType),
      multiDb: multiDbEnabled,
      strategy: process.env.DB_ROUTING_STRATEGY || 'hash',
    });

    // Use multi-DB routing
    const db = getPrismaForOrg(validatedSession.user.organizationId);

    // Log routed database details
    if (multiDbEnabled) {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const client = router.getClient(validatedSession.user.organizationId);
        const dbConfig = router.getAllDatabaseConfigs().find(c => c.client === client);
        console.log('[Campaign API POST] Routed DB', {
          organizationId: validatedSession.user.organizationId,
          dbIndex: dbConfig?.index,
          dbUrlHost: dbConfig ? new URL(dbConfig.url).hostname : 'unknown',
          dbHealth: dbConfig?.health,
        });
      } catch (err) {
        console.warn('[Campaign API POST] Could not log DB routing details:', err);
      }
    }

    // Sanitize string inputs
    if (name && typeof name === 'string') {
      name = sanitizeForStorage(name);
    }
    if (description && typeof description === 'string') {
      description = sanitizeForStorage(description);
    }
    if (messageTag && typeof messageTag === 'string') {
      messageTag = sanitizeForStorage(messageTag);
    }
    if (aiCustomInstructions && typeof aiCustomInstructions === 'string') {
      aiCustomInstructions = sanitizeForStorage(aiCustomInstructions);
    }

    // Validate numeric inputs
    if (rateLimit !== null && rateLimit !== undefined) {
      const rateLimitValidation = NumericPresets.rateLimit(rateLimit, 'Rate limit');
      if (!rateLimitValidation.valid) {
        return NextResponse.json(
          { error: rateLimitValidation.errors.join(', ') },
          { status: 400 }
        );
      }
    }

    // Validate send-to-all vs specific contacts
    if (sendToAll && targetContactIds && targetContactIds.length > 0) {
      console.error('[Campaign API POST] Error: sendToAll and targetContactIds are mutually exclusive', {
        orgId: validatedSession.user.organizationId,
        sendToAll,
        contactIdsCount: targetContactIds.length,
      });
      return NextResponse.json(
        { error: 'Cannot specify both sendToAll and targetContactIds. Choose one targeting method.' },
        { status: 400 }
      );
    }

    // If sendToAll is true, validate facebook page exists and belongs to org
    if (sendToAll || targetingType === 'ALL_CONTACTS') {
      if (!facebookPageId) {
        return NextResponse.json(
          { error: 'Facebook page is required for send-to-all campaigns' },
          { status: 400 }
        );
      }

      const page = await db.facebookPage.findFirst({
        where: {
          id: facebookPageId,
          organizationId: validatedSession.user.organizationId,
        },
      });

      if (!page) {
        console.error('[Campaign API POST] Facebook page not found or access denied', {
          orgId: validatedSession.user.organizationId,
          facebookPageId,
          dbIndex: multiDbEnabled ? 'routed' : 'default',
        });
        return NextResponse.json(
          { error: 'Facebook page not found or you do not have access to it. Check multi-DB connectivity.' },
          { status: 403 }
        );
      }
      console.log('[Campaign API POST] Send-to-all validated for page:', page.pageName);
    }

    // If specific contacts, validate they all belong to same org/page
    if (targetContactIds && targetContactIds.length > 0) {
      const contacts = await db.contact.findMany({
        where: {
          id: { in: targetContactIds },
        },
        select: {
          id: true,
          organizationId: true,
          facebookPageId: true,
        },
      });

      if (contacts.length !== targetContactIds.length) {
        console.error('[Campaign API POST] Some contacts not found', {
          orgId: validatedSession.user.organizationId,
          requested: targetContactIds.length,
          found: contacts.length,
          dbIndex: multiDbEnabled ? 'routed' : 'default',
        });
        return NextResponse.json(
          { error: `Some contacts not found. Check that all contacts exist in the routed database. Found ${contacts.length} of ${targetContactIds.length}.` },
          { status: 400 }
        );
      }

      const wrongOrg = contacts.find(c => c.organizationId !== validatedSession.user.organizationId);
      if (wrongOrg) {
        console.error('[Campaign API POST] Contact does not belong to organization', {
          orgId: validatedSession.user.organizationId,
          contactId: wrongOrg.id,
          contactOrgId: wrongOrg.organizationId,
        });
        return NextResponse.json(
          { error: 'One or more contacts do not belong to your organization' },
          { status: 403 }
        );
      }

      if (facebookPageId) {
        const wrongPage = contacts.find(c => c.facebookPageId !== facebookPageId);
        if (wrongPage) {
          console.error('[Campaign API POST] Contact does not belong to specified page', {
            orgId: validatedSession.user.organizationId,
            contactId: wrongPage.id,
            expectedPageId: facebookPageId,
            actualPageId: wrongPage.facebookPageId,
          });
          return NextResponse.json(
            { error: 'One or more contacts do not belong to the specified Facebook page' },
            { status: 400 }
          );
        }
      }

      console.log('[Campaign API POST] Validated', contacts.length, 'specific contacts');
    }

    // Determine campaign status based on scheduling
    let status: 'DRAFT' | 'SCHEDULED' | 'PENDING' = 'DRAFT';
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
    } else if (sendToAll || (targetContactIds && targetContactIds.length > 0)) {
      // Mark as PENDING if ready to send immediately
      status = 'PENDING';
    }

    const campaign = await db.campaign.create({
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
        // Media fields
        ...(mediaUrl && { mediaUrl }),
        ...(mediaType && { mediaType }),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any, // Type assertion needed for fields that may not be in generated types yet
    });

    console.log('[Campaign API POST] Created campaign', {
      campaignId: campaign.id,
      status: campaign.status,
      orgId: campaign.organizationId,
      scheduledAt: campaign.scheduledAt?.toISOString() || 'none',
      totalRecipients: campaign.totalRecipients,
      hasMedia: !!(mediaUrl && mediaType),
      useAiPersonalization,
    });

    return NextResponse.json(campaign);
  } catch (error) {
    const err = error as Error;
    console.error('[Campaign API POST] Error:', err);
    return NextResponse.json(
      { error: 'Failed to create campaign', details: err.message },
      { status: 500 }
    );
  }
}

