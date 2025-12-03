import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { batchAnalyzeWithFallback } from '@/lib/ai/enhanced-analysis';

/**
 * POST /api/contacts/fix-zero-scores
 * Re-analyze contacts with 0 or suspiciously low lead scores
 * Uses enhanced fallback scoring to prevent 0 scores
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { pipelineId, minScore = 0, maxScore = 15 } = body;

    console.log(`[Fix Zero Scores] Finding contacts with scores ${minScore}-${maxScore}...`);

    // Find contacts with low/zero scores
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const whereClause: Record<string, any> = {
      organizationId: session.user.organizationId,
      leadScore: {
        gte: minScore,
        lte: maxScore
      }
    };

    // Optionally filter by pipeline
    if (pipelineId) {
      whereClause.pipelineId = pipelineId;
    }

    const lowScoreContacts = await prisma.contact.findMany({
      where: whereClause,
      include: {
        conversations: {
          include: {
            messages: {
              orderBy: { createdAt: 'asc' },
              take: 50 // Get recent messages
            }
          },
          orderBy: { updatedAt: 'desc' },
          take: 1 // Most recent conversation
        },
        pipeline: {
          include: {
            stages: {
              orderBy: { order: 'asc' }
            }
          }
        }
      },
      take: 100 // Process in batches of 100
    });

    if (lowScoreContacts.length === 0) {
      return NextResponse.json({
        success: true,
        message: 'No contacts found with low scores',
        fixed: 0
      });
    }

    console.log(`[Fix Zero Scores] Found ${lowScoreContacts.length} contacts to re-analyze`);

    // Prepare contacts for batch analysis
    const contactsWithMessages = lowScoreContacts
      .filter(contact => contact.conversations[0]?.messages.length > 0)
      .map(contact => ({
        contactId: contact.id,
        messages: contact.conversations[0].messages.map(msg => ({
          from: msg.isFromBusiness ? 'Business' : (contact.firstName || 'Customer'),
          text: msg.content,
          timestamp: msg.createdAt
        })),
        conversationAge: contact.lastInteraction || undefined
      }));

    if (contactsWithMessages.length === 0) {
      return NextResponse.json({
        success: true,
        message: 'No contacts with messages to analyze',
        fixed: 0
      });
    }

    console.log(`[Fix Zero Scores] Re-analyzing ${contactsWithMessages.length} contacts...`);

    // Batch analyze with fallback
    const results = await batchAnalyzeWithFallback(
      contactsWithMessages,
      lowScoreContacts[0]?.pipeline?.stages,
      1000 // 1 second delay between analyses
    );

    // Update contacts with new scores
    let fixedCount = 0;
    for (const [contactId, result] of results.entries()) {
      try {
        await prisma.contact.update({
          where: { id: contactId },
          data: {
            leadScore: result.analysis.leadScore,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            leadStatus: result.analysis.leadStatus as any,
            aiContext: result.analysis.summary,
            aiContextUpdatedAt: new Date()
          }
        });

        // Create activity log
        await prisma.contactActivity.create({
          data: {
            contactId,
            type: 'STATUS_CHANGED',
            title: 'Lead score updated',
            description: `Score updated from low/zero to ${result.analysis.leadScore}. ${result.analysis.reasoning}`,
            metadata: {
              oldScore: 0,
              newScore: result.analysis.leadScore,
              usedFallback: result.usedFallback,
              confidence: result.analysis.confidence
            }
          }
        });

        fixedCount++;
      } catch (error) {
        console.error(`[Fix Zero Scores] Failed to update contact ${contactId}:`, error);
      }
    }

    console.log(`[Fix Zero Scores] Successfully fixed ${fixedCount} contacts`);

    return NextResponse.json({
      success: true,
      message: `Fixed ${fixedCount} contacts with low scores`,
      fixed: fixedCount,
      analyzed: contactsWithMessages.length,
      fallbackUsed: Array.from(results.values()).filter(r => r.usedFallback).length
    });

  } catch (error) {
    console.error('[Fix Zero Scores] Error:', error);
    return NextResponse.json(
      { error: 'Failed to fix zero scores' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/contacts/fix-zero-scores
 * Get count of contacts with low/zero scores
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const pipelineId = searchParams.get('pipelineId');
    const minScore = parseInt(searchParams.get('minScore') || '0');
    const maxScore = parseInt(searchParams.get('maxScore') || '15');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const whereClause: Record<string, any> = {
      organizationId: session.user.organizationId,
      leadScore: {
        gte: minScore,
        lte: maxScore
      }
    };

    if (pipelineId) {
      whereClause.pipelineId = pipelineId;
    }

    const count = await prisma.contact.count({ where: whereClause });

    return NextResponse.json({
      count,
      minScore,
      maxScore,
      pipelineId: pipelineId || 'all'
    });

  } catch (error) {
    console.error('[Get Low Score Count] Error:', error);
    return NextResponse.json(
      { error: 'Failed to get count' },
      { status: 500 }
    );
  }
}

