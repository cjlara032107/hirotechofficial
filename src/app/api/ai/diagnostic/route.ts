import { NextResponse } from 'next/server';
import { requireAuth } from '@/lib/api/validate-session';
import apiKeyManager from '@/lib/ai/api-key-manager';

/**
 * Diagnostic result interface for type safety
 */
interface DiagnosticResult {
  apiKey: {
    configured: boolean;
    source: 'database' | 'environment' | 'none';
    count?: number;
    valid?: boolean;
    error?: string;
  };
  model: {
    name: string;
    available?: boolean;
    error?: string;
  };
  connectivity: {
    reachable: boolean;
    latency?: number;
    error?: string;
  };
  recommendations: string[];
  timestamp: string;
}

/**
 * GET /api/ai/diagnostic
 * Diagnostic endpoint to check AI analysis configuration and connectivity
 * Includes comprehensive checks with timeout protection
 */
export async function GET() {
  const startTime = Date.now();
  const requestId = `diag-${Date.now()}`;
  
  try {
    console.log(`[AI Diagnostic ${requestId}] Starting diagnostic check`);
    
    // Authentication with timeout
    const authResult = await Promise.race([
      requireAuth(),
      new Promise<{ error: NextResponse }>((_, reject) => 
        setTimeout(() => reject(new Error('Auth timeout')), 5000)
      )
    ]);
    
    if ('error' in authResult) {
      return authResult.error;
    }

    const diagnostics: DiagnosticResult = {
      apiKey: {
        configured: false,
        source: 'none',
      },
      model: {
        name: process.env.AI_PRIMARY_MODEL || 'openai/gpt-oss-120b',
      },
      connectivity: {
        reachable: false,
      },
      recommendations: [],
      timestamp: new Date().toISOString(),
    };

    // Check API key configuration with timeout
    try {
      const keyCheckPromise = (async () => {
        const dbKey = await apiKeyManager.getNextKey({ operation: 'diagnostic' });
        if (dbKey) {
          diagnostics.apiKey.configured = true;
          diagnostics.apiKey.source = 'database';
          diagnostics.apiKey.valid = dbKey.startsWith('nvapi-') || dbKey.length > 20;
          
          // Count available keys with timeout
          const { prisma } = await import('@/lib/db');
          const { ApiKeyStatus } = await import('@prisma/client');
          
          const keyCount = await Promise.race([
            prisma.apiKey.count({
              where: {
                status: ApiKeyStatus.ACTIVE,
                rateLimitedAt: null,
              },
            }),
            new Promise<number>((_, reject) => 
              setTimeout(() => reject(new Error('Database query timeout')), 3000)
            )
          ]);
          diagnostics.apiKey.count = keyCount;
        } else {
          const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY;
          if (envKey) {
            diagnostics.apiKey.configured = true;
            diagnostics.apiKey.source = 'environment';
            diagnostics.apiKey.valid = envKey.startsWith('nvapi-') || envKey.length > 20;
          } else {
            diagnostics.recommendations.push('Add NVIDIA API key in Settings → API Keys or set NVIDIA_API_KEY environment variable');
          }
        }
      })();
      
      await Promise.race([
        keyCheckPromise,
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('API key check timeout')), 5000)
        )
      ]);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      diagnostics.apiKey.error = errorMsg;
      diagnostics.recommendations.push(
        errorMsg.includes('timeout') 
          ? 'API key check timed out. Database may be slow or unreachable.'
          : 'Error checking API key configuration. Check database connection.'
      );
      console.error(`[AI Diagnostic ${requestId}] API key check error:`, errorMsg);
    }

    // Test model connectivity with comprehensive error handling
    if (diagnostics.apiKey.configured && diagnostics.apiKey.valid) {
      try {
        console.log(`[AI Diagnostic ${requestId}] Testing model connectivity`);
        const testKey = await apiKeyManager.getNextKey({ operation: 'diagnostic' }) || 
                       process.env.NVIDIA_API_KEY || 
                       process.env.GOOGLE_AI_API_KEY;
        
        if (testKey) {
          const testStartTime = Date.now();
          const OpenAI = (await import('openai')).default;
          const client = new OpenAI({
            baseURL: 'https://integrate.api.nvidia.com/v1',
            apiKey: testKey,
            timeout: 8000, // Set OpenAI client timeout
            maxRetries: 0, // No retries for diagnostic
          });

          // Simple test request with timeout and abort controller
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            
            const testResponse = await client.chat.completions.create({
              model: diagnostics.model.name,
              messages: [{ role: 'user', content: 'test' }],
              max_tokens: 5,
            }, {
              signal: controller.signal,
            });

            clearTimeout(timeoutId);
            const latency = Date.now() - testStartTime;
            diagnostics.connectivity.reachable = true;
            diagnostics.connectivity.latency = latency;
            diagnostics.model.available = true;
            console.log(`[AI Diagnostic ${requestId}] ✅ Connectivity test passed (${latency}ms)`);
          } catch (testError: unknown) {
            const errorMsg = testError instanceof Error ? testError.message : String(testError);
            const errorCode = (testError as any)?.status || (testError as any)?.code;
            
            diagnostics.connectivity.error = errorMsg;
            diagnostics.model.error = errorMsg;
            
            console.error(`[AI Diagnostic ${requestId}] ❌ Connectivity test failed:`, errorMsg);
            
            // Categorize errors with specific recommendations
            if (errorCode === 401 || errorCode === 403 || errorMsg.includes('401') || errorMsg.includes('403')) {
              diagnostics.recommendations.push('API key authentication failed. Verify your API key is valid and not expired.');
            } else if (errorCode === 429 || errorMsg.includes('429')) {
              diagnostics.recommendations.push('API rate limit reached. Add more API keys or wait for rate limit to reset.');
            } else if (errorCode === 404 || errorMsg.includes('404') || errorMsg.includes('model')) {
              diagnostics.recommendations.push(`Model ${diagnostics.model.name} may not be available. Check NVIDIA API status or try a different model.`);
            } else if (errorMsg.includes('timeout') || errorMsg.includes('Timeout') || errorMsg.includes('abort')) {
              diagnostics.recommendations.push('API request timed out. Check network connectivity, firewall rules, or try again.');
            } else if (errorMsg.includes('ECONNREFUSED') || errorMsg.includes('ENOTFOUND')) {
              diagnostics.recommendations.push('Cannot reach NVIDIA API. Check DNS settings and network connectivity.');
            } else {
              diagnostics.recommendations.push(`API connectivity issue: ${errorMsg.substring(0, 150)}`);
            }
          }
        } else {
          diagnostics.recommendations.push('No API key available for connectivity test.');
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        diagnostics.connectivity.error = errorMsg;
        diagnostics.recommendations.push('Error initializing API connectivity test. Check network and API key configuration.');
        console.error(`[AI Diagnostic ${requestId}] Connectivity test initialization error:`, errorMsg);
      }
    } else {
      diagnostics.recommendations.push('Cannot test connectivity without valid API key.');
    }

    // Add general recommendations
    if (!diagnostics.apiKey.configured) {
      diagnostics.recommendations.push('Configure NVIDIA API key to enable AI analysis');
    }

    if (diagnostics.apiKey.configured && !diagnostics.connectivity.reachable) {
      diagnostics.recommendations.push('API key is configured but connectivity test failed. Check network and API status.');
    }

    // Add performance recommendation if latency is high
    if (diagnostics.connectivity.latency && diagnostics.connectivity.latency > 5000) {
      diagnostics.recommendations.push('High API latency detected. Consider checking network conditions.');
    }

    const duration = Date.now() - startTime;
    console.log(`[AI Diagnostic ${requestId}] ✅ Diagnostic complete in ${duration}ms`);

    return NextResponse.json(diagnostics, { 
      status: 200,
      headers: {
        'Cache-Control': 'no-store, max-age=0',
      }
    });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    const duration = Date.now() - startTime;
    
    console.error(`[AI Diagnostic ${requestId}] ❌ Error after ${duration}ms:`, errorMsg);
    
    // Return partial diagnostics even on error
    const errorResponse = {
      error: 'Failed to complete diagnostics',
      message: errorMsg,
      requestId,
      duration,
      timestamp: new Date().toISOString(),
      // Provide basic fallback info
      fallback: {
        apiKeyConfigured: !!(process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY),
        modelName: process.env.AI_PRIMARY_MODEL || 'openai/gpt-oss-120b',
      }
    };
    
    return NextResponse.json(
      errorResponse,
      { 
        status: 500,
        headers: {
          'Cache-Control': 'no-store, max-age=0',
        }
      }
    );
  }
}

