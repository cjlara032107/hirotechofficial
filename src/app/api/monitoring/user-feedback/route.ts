import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/**
 * GET /api/monitoring/user-feedback
 * 
 * Returns aggregated user feedback metrics
 * 
 * Query parameters:
 * - timeWindow: '24h' | '7d' | '30d' (default: '30d')
 * - organizationId: Filter by organization (optional)
 */
export async function GET(request: NextRequest) {
  try {
    // Check authentication
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const timeWindow = searchParams.get('timeWindow') || '30d';
    const organizationId = searchParams.get('organizationId');

    // Calculate time window
    const now = new Date();
    let startDate: Date;

    switch (timeWindow) {
      case '24h':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    }

    // Build where clause
    const where: any = {
      feedback: { not: null },
      feedbackAt: {
        gte: startDate,
      },
    };

    // If user is not admin, filter by their organization
    const userOrgId = organizationId || session.user.organizationId;
    if (userOrgId) {
      where.organizationId = userOrgId;
    }

    // Get total feedback count
    const totalFeedback = await prisma.contact.count({ where });

    // Get feedback by date (grouped by day)
    const contactsWithFeedback = await prisma.contact.findMany({
      where,
      select: {
        feedback: true,
        feedbackAt: true,
        id: true,
        firstName: true,
        lastName: true,
      },
      orderBy: {
        feedbackAt: 'desc',
      },
    });

    // Group by day
    const feedbackByDay: Record<string, number> = {};
    const feedbackDetails: Array<{
      date: string;
      contactId: string;
      contactName: string;
      feedback: string;
    }> = [];

    contactsWithFeedback.forEach((contact) => {
      if (!contact.feedbackAt) return;

      const date = new Date(contact.feedbackAt);
      const dateKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;

      feedbackByDay[dateKey] = (feedbackByDay[dateKey] || 0) + 1;

      feedbackDetails.push({
        date: dateKey,
        contactId: contact.id,
        contactName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
        feedback: contact.feedback || '',
      });
    });

    // Analyze feedback sentiment (simple keyword-based)
    const positiveKeywords = ['good', 'great', 'excellent', 'helpful', 'thanks', 'thank', 'love', 'perfect', 'amazing', 'wonderful'];
    const negativeKeywords = ['bad', 'terrible', 'awful', 'horrible', 'hate', 'disappointed', 'frustrated', 'angry', 'poor', 'worst'];
    const neutralKeywords = ['ok', 'okay', 'fine', 'alright', 'average'];

    let positiveCount = 0;
    let negativeCount = 0;
    let neutralCount = 0;

    contactsWithFeedback.forEach((contact) => {
      if (!contact.feedback) return;

      const feedbackLower = contact.feedback.toLowerCase();
      const hasPositive = positiveKeywords.some((keyword) => feedbackLower.includes(keyword));
      const hasNegative = negativeKeywords.some((keyword) => feedbackLower.includes(keyword));
      const hasNeutral = neutralKeywords.some((keyword) => feedbackLower.includes(keyword));

      if (hasPositive && !hasNegative) {
        positiveCount++;
      } else if (hasNegative) {
        negativeCount++;
      } else if (hasNeutral || (!hasPositive && !hasNegative)) {
        neutralCount++;
      } else {
        neutralCount++;
      }
    });

    // Calculate feedback rate (feedback per day)
    const daysInWindow = (now.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24);
    const feedbackRate = daysInWindow > 0 ? totalFeedback / daysInWindow : 0;

    // Get recent feedback (last 20)
    const recentFeedback = contactsWithFeedback.slice(0, 20).map((contact) => ({
      contactId: contact.id,
      contactName: `${contact.firstName} ${contact.lastName || ''}`.trim(),
      feedback: contact.feedback || '',
      feedbackAt: contact.feedbackAt?.toISOString() || null,
    }));

    return NextResponse.json(
      {
        success: true,
        data: {
          timeWindow,
          totalFeedback,
          feedbackRate: Math.round(feedbackRate * 100) / 100,
          sentiment: {
            positive: positiveCount,
            negative: negativeCount,
            neutral: neutralCount,
            positivePercent: totalFeedback > 0 ? Math.round((positiveCount / totalFeedback) * 100) : 0,
            negativePercent: totalFeedback > 0 ? Math.round((negativeCount / totalFeedback) * 100) : 0,
            neutralPercent: totalFeedback > 0 ? Math.round((neutralCount / totalFeedback) * 100) : 0,
          },
          feedbackByDay: Object.entries(feedbackByDay)
            .map(([date, count]) => ({ date, count }))
            .sort((a, b) => a.date.localeCompare(b.date)),
          recentFeedback,
        },
      },
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    console.error('[User Feedback API] Error fetching user feedback:', error);
    
    return NextResponse.json(
      {
        error: 'Failed to fetch user feedback',
        details: process.env.NODE_ENV === 'development' 
          ? error instanceof Error ? error.message : String(error)
          : undefined,
      },
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  }
}









