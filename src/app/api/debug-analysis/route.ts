import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma, connectPrisma } from '@/lib/db';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    await connectPrisma();
    
    const body = await request.json();
    const { contactId } = body;
    
    if (!contactId) {
      return NextResponse.json({ error: 'Contact ID required' }, { status: 400 });
    }

    // Get contact with messages
    const contact = await prisma.contact.findUnique({
      where: { id: contactId },
      include: {
        facebookPage: {
          include: {
            autoPipeline: {
              include: {
                stages: {
                  orderBy: { order: 'asc' }
                }
              }
            }
          }
        },
        conversations: {
          include: {
            messages: {
              orderBy: { createdAt: 'asc' },
              take: 50
            }
          }
        }
      }
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    // Flatten messages from all conversations
    const allMessages = contact.conversations.flatMap(conv => conv.messages);
    const messagesToAnalyze = allMessages.map(msg => ({
      id: msg.id,
      from: msg.isFromBusiness ? 'business' : 'contact',
      text: msg.content || '',
      timestamp: msg.createdAt,
      type: 'text' // Message model doesn't have type field
    }));

    console.log(`[Debug Analysis] Testing analysis for contact ${contactId}`);
    console.log(`[Debug Analysis] Messages: ${messagesToAnalyze.length}`);
    console.log(`[Debug Analysis] Has pipeline: ${!!contact.facebookPage?.autoPipeline}`);
    console.log(`[Debug Analysis] Pipeline stages: ${contact.facebookPage?.autoPipeline?.stages.length || 0}`);

    // Test the analysis
    let result;
    let error: any = null;
    
    try {
      if (contact.facebookPage?.autoPipeline?.stages) {
        console.log(`[Debug Analysis] Calling analyzeWithFallback WITH pipeline stages`);
        result = await analyzeWithFallback(
          messagesToAnalyze,
          contact.facebookPage.autoPipeline.stages,
          contact.lastInteraction || undefined,
          3
        );
      } else {
        console.log(`[Debug Analysis] Calling analyzeWithFallback WITHOUT pipeline stages`);
        result = await analyzeWithFallback(
          messagesToAnalyze,
          undefined,
          contact.lastInteraction || undefined,
          3
        );
      }
      
      console.log(`[Debug Analysis] ✅ Analysis completed`);
      console.log(`[Debug Analysis] Result:`, {
        hasAnalysis: !!result?.analysis,
        usedFallback: result?.usedFallback,
        retryCount: result?.retryCount,
        summary: result?.analysis?.summary?.substring(0, 100),
        leadScore: result?.analysis?.leadScore
      });
    } catch (analysisError) {
      error = {
        message: analysisError instanceof Error ? analysisError.message : String(analysisError),
        stack: analysisError instanceof Error ? analysisError.stack : undefined,
        type: analysisError instanceof Error ? analysisError.constructor.name : typeof analysisError
      };
      console.error(`[Debug Analysis] ❌ Analysis threw error:`, error);
    }

    // Check API key
    const apiKey = process.env.NVIDIA_API_KEY;
    const hasApiKey = !!apiKey;

    return NextResponse.json({
      success: true,
      contact: {
        id: contact.id,
        messageCount: messagesToAnalyze.length,
        hasPipeline: !!contact.facebookPage?.autoPipeline,
        pipelineStages: contact.facebookPage?.autoPipeline?.stages.length || 0
      },
      environment: {
        hasApiKey,
        apiKeyPreview: apiKey ? `${apiKey.substring(0, 20)}...` : 'MISSING',
        useEdgeFunction: process.env.USE_EDGE_FUNCTION_FOR_AI === 'true'
      },
      analysis: result ? {
        success: true,
        hasAnalysis: !!result.analysis,
        usedFallback: result.usedFallback,
        retryCount: result.retryCount,
        summary: result.analysis?.summary?.substring(0, 200),
        leadScore: result.analysis?.leadScore,
        leadStatus: result.analysis?.leadStatus,
        recommendedStage: result.analysis?.recommendedStage
      } : null,
      error: error ? {
        message: error.message,
        type: error.type,
        stack: error.stack?.split('\n').slice(0, 10)
      } : null
    });
  } catch (error) {
    console.error('[Debug Analysis] Route error:', error);
    return NextResponse.json({
      success: false,
      error: {
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack?.split('\n').slice(0, 10) : undefined
      }
    }, { status: 500 });
  }
}

