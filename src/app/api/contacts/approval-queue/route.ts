import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

/**
 * GET /api/contacts/approval-queue
 * Get contacts pending approval (high-risk contacts)
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    // Reduced default page size for better performance
    const limit = parseInt(searchParams.get('limit') || '25');
    const skip = (page - 1) * limit;

    // Get pending contacts for user's organization
    const [contacts, total] = await Promise.all([
      prisma.contact.findMany({
        where: {
          organizationId: session.user.organizationId,
          approvalStatus: 'PENDING',
        },
        orderBy: [
          { riskScore: 'desc' }, // Highest risk first
          { createdAt: 'desc' },
        ],
        skip,
        take: limit,
        select: {
          id: true,
          firstName: true,
          lastName: true,
          messengerPSID: true,
          instagramSID: true,
          profilePicUrl: true,
          riskScore: true,
          riskLevel: true,
          riskReasons: true,
          leadScore: true,
          leadStatus: true,
          aiContext: true,
          lastInteraction: true,
          createdAt: true,
          facebookPage: {
            select: {
              pageName: true,
            },
          },
        },
      }),
      prisma.contact.count({
        where: {
          organizationId: session.user.organizationId,
          approvalStatus: 'PENDING',
        },
      }),
    ]);

    return NextResponse.json({
      contacts,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('[Approval Queue] Error fetching pending contacts:', error);
    return NextResponse.json(
      { error: 'Failed to fetch approval queue' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/contacts/approval-queue
 * Approve or reject contacts
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { contactIds, action, feedback } = body;

    if (!Array.isArray(contactIds) || contactIds.length === 0) {
      return NextResponse.json(
        { error: 'contactIds array is required' },
        { status: 400 }
      );
    }

    if (!['approve', 'reject'].includes(action)) {
      return NextResponse.json(
        { error: 'action must be "approve" or "reject"' },
        { status: 400 }
      );
    }

    const now = new Date();
    const updateData = action === 'approve' 
      ? {
          approvalStatus: 'APPROVED' as const,
          approvedAt: now,
          approvedBy: session.user.id,
        }
      : {
          approvalStatus: 'REJECTED' as const,
          rejectedAt: now,
          rejectedBy: session.user.id,
        };

    // Update contacts
    const result = await prisma.contact.updateMany({
      where: {
        id: { in: contactIds },
        organizationId: session.user.organizationId,
        approvalStatus: 'PENDING',
      },
      data: updateData,
    });

    // If feedback provided, update feedback field
    if (feedback && typeof feedback === 'string' && feedback.trim()) {
      await prisma.contact.updateMany({
        where: {
          id: { in: contactIds },
          organizationId: session.user.organizationId,
        },
        data: {
          feedback: feedback.trim(),
          feedbackAt: now,
        },
      });
    }

    return NextResponse.json({
      success: true,
      updated: result.count,
      action,
    });
  } catch (error) {
    console.error('[Approval Queue] Error processing approval/rejection:', error);
    return NextResponse.json(
      { error: 'Failed to process approval/rejection' },
      { status: 500 }
    );
  }
}
