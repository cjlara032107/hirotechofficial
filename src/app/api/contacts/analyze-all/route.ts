import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { analyzeExistingContacts } from '@/lib/ai/analyze-existing-contacts';
import { z } from 'zod';

// Request validation schema with production-ready limits
const AnalyzeRequestSchema = z.object({
  limit: z.number().int().min(1).max(500).optional().default(50), // Reduced from 1000 to 500 for memory safety
  skipIfHasContext: z.boolean().optional().default(true),
});

// Memory and performance tracking
interface AnalyzeMetrics {
  startTime: number;
  peakMemoryMB?: number;
  contactsProcessed: number;
}

export async function POST(req: NextRequest) {
  const requestId = `analyze-${Date.now()}-${Math.random().toString(36).substring(7)}`;
  const metrics: AnalyzeMetrics = {
    startTime: Date.now(),
    contactsProcessed: 0,
  };
  
  try {
    console.log(`[API ${requestId}] Starting analyze-all request`);
    
    // Check available memory before proceeding (Node.js specific)
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
      console.log(`[API ${requestId}] Initial memory usage: ${heapUsedMB.toFixed(2)}MB`);
      
      // Warning if memory is already high
      if (heapUsedMB > 400) {
        console.warn(`[API ${requestId}] ⚠️ High memory usage detected before analysis: ${heapUsedMB.toFixed(2)}MB`);
      }
    }
    
    // Authentication with timeout
    const authPromise = auth();
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Authentication timeout')), 5000)
    );
    
    const session = await Promise.race([authPromise, timeoutPromise]);
    
    if (!session?.user) {
      console.warn(`[API ${requestId}] Unauthorized access attempt`);
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const organizationId = session.user.organizationId;
    if (!organizationId) {
      console.error(`[API ${requestId}] User ${session.user.id} has no organizationId`);
      return NextResponse.json(
        { error: 'Organization not found' },
        { status: 400 }
      );
    }

    // Parse and validate request body
    let body: unknown;
    try {
      body = await req.json();
    } catch (parseError) {
      console.error(`[API ${requestId}] Invalid JSON in request body:`, parseError);
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }

    const validationResult = AnalyzeRequestSchema.safeParse(body);
    if (!validationResult.success) {
      console.error(`[API ${requestId}] Request validation failed:`, validationResult.error.format());
      return NextResponse.json(
        { 
          error: 'Invalid request parameters',
          details: validationResult.error.format()
        },
        { status: 400 }
      );
    }

    const { limit, skipIfHasContext } = validationResult.data;

    console.log(`[API ${requestId}] ============================================`);
    console.log(`[API ${requestId}] STARTING BATCH ANALYSIS`);
    console.log(`[API ${requestId}] - Organization: ${organizationId}`);
    console.log(`[API ${requestId}] - Limit: ${limit}`);
    console.log(`[API ${requestId}] - Skip if has context: ${skipIfHasContext}`);
    console.log(`[API ${requestId}] - User ID: ${session.user.id}`);
    console.log(`[API ${requestId}] ============================================`);

    const result = await analyzeExistingContacts({
      organizationId,
      limit,
      skipIfHasContext,
    });
    
    metrics.contactsProcessed = result.successCount + result.failedCount;
    const duration = Date.now() - metrics.startTime;

    // Track peak memory usage
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      metrics.peakMemoryMB = memUsage.heapUsed / 1024 / 1024;
    }

    console.log(`[API ${requestId}] ============================================`);
    console.log(`[API ${requestId}] ✅ BATCH ANALYSIS COMPLETE`);
    console.log(`[API ${requestId}] - Duration: ${duration}ms`);
    console.log(`[API ${requestId}] - Contacts Processed: ${metrics.contactsProcessed}`);
    console.log(`[API ${requestId}] - Success: ${result.successCount}`);
    console.log(`[API ${requestId}] - Failed: ${result.failedCount}`);
    console.log(`[API ${requestId}] - Success Rate: ${metrics.contactsProcessed > 0 ? Math.round((result.successCount / metrics.contactsProcessed) * 100) : 0}%`);
    console.log(`[API ${requestId}] - Avg Time/Contact: ${metrics.contactsProcessed > 0 ? Math.round(duration / metrics.contactsProcessed) : 0}ms`);
    if (metrics.peakMemoryMB) {
      console.log(`[API ${requestId}] - Peak Memory: ${metrics.peakMemoryMB.toFixed(2)}MB`);
    }
    console.log(`[API ${requestId}] ============================================`);

    return NextResponse.json({
      ...result,
      requestId,
      duration,
      metrics: {
        contactsProcessed: metrics.contactsProcessed,
        averageTimePerContact: metrics.contactsProcessed > 0 ? Math.round(duration / metrics.contactsProcessed) : 0,
        peakMemoryMB: metrics.peakMemoryMB,
      },
    }, {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      }
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Failed to analyze contacts';
    const errorStack = error instanceof Error ? error.stack : undefined;
    
    console.error(`[API ${requestId}] Analysis error:`, errorMessage);
    if (errorStack) {
      console.error(`[API ${requestId}] Stack trace:`, errorStack.split('\n').slice(0, 5).join('\n'));
    }
    
    // Check for specific error types
    const isTimeoutError = errorMessage.includes('timeout') || errorMessage.includes('timed out');
    const isRateLimitError = errorMessage.includes('429') || errorMessage.includes('rate limit');
    const isAuthError = errorMessage.includes('401') || errorMessage.includes('403');
    const isMemoryError = errorMessage.includes('memory') || errorMessage.includes('heap');
    const duration = Date.now() - metrics.startTime;
    
    console.error(`[API ${requestId}] ============================================`);
    console.error(`[API ${requestId}] ❌ BATCH ANALYSIS FAILED`);
    console.error(`[API ${requestId}] - Duration: ${duration}ms`);
    console.error(`[API ${requestId}] - Contacts Processed: ${metrics.contactsProcessed}`);
    console.error(`[API ${requestId}] - Error: ${errorMessage}`);
    console.error(`[API ${requestId}] - Error Type: ${error instanceof Error ? error.constructor.name : typeof error}`);
    console.error(`[API ${requestId}] - Is Timeout: ${isTimeoutError}`);
    console.error(`[API ${requestId}] - Is Rate Limit: ${isRateLimitError}`);
    console.error(`[API ${requestId}] - Is Auth Error: ${isAuthError}`);
    console.error(`[API ${requestId}] - Is Memory Error: ${isMemoryError}`);
    
    if (typeof process !== 'undefined' && process.memoryUsage) {
      const memUsage = process.memoryUsage();
      const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
      console.error(`[API ${requestId}] - Current Memory: ${heapUsedMB.toFixed(2)}MB`);
    }
    console.error(`[API ${requestId}] ============================================`);
    
    let statusCode = 500;
    let userMessage = 'Failed to analyze contacts. Please try again.';
    
    if (isTimeoutError) {
      statusCode = 504;
      userMessage = 'Analysis timed out. Please try with a smaller limit.';
    } else if (isRateLimitError) {
      statusCode = 429;
      userMessage = 'Rate limit exceeded. Please try again later.';
    } else if (isAuthError) {
      statusCode = 401;
      userMessage = 'Authentication failed. Please check your API keys.';
    } else if (isMemoryError) {
      statusCode = 507;
      userMessage = 'Server memory exceeded. Please try with a smaller batch size.';
    }
    
    return NextResponse.json(
      { 
        error: userMessage,
        requestId,
        duration,
        contactsProcessed: metrics.contactsProcessed,
        details: process.env.NODE_ENV === 'development' ? errorMessage : undefined
      },
      { status: statusCode }
    );
  }
}

