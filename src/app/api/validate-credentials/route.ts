import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import axios from 'axios';
import OpenAI from 'openai';

export const dynamic = 'force-dynamic';

interface ValidationResult {
  name: string;
  status: 'pass' | 'fail' | 'warning';
  message: string;
  details?: string;
}

/**
 * Validate environment variables and API credentials
 * GET /api/validate-credentials
 */
export async function GET() {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const results: ValidationResult[] = [];

    // Check environment variables
    const requiredVars = [
      'DATABASE_URL',
      'NEXTAUTH_SECRET',
      'NEXT_PUBLIC_SUPABASE_URL',
      'NEXT_PUBLIC_SUPABASE_ANON_KEY',
      'FACEBOOK_APP_ID',
      'FACEBOOK_APP_SECRET',
    ];

    const optionalVars = [
      'REDIS_URL',
      'NEXT_PUBLIC_APP_URL',
      'FACEBOOK_WEBHOOK_VERIFY_TOKEN',
      'NVIDIA_API_KEY',
      'GOOGLE_AI_API_KEY',
      'ENCRYPTION_KEY',
    ];

    const missing: string[] = [];
    const found: string[] = [];

    requiredVars.forEach((varName) => {
      if (process.env[varName]) {
        found.push(varName);
      } else {
        missing.push(varName);
      }
    });

    if (missing.length > 0) {
      results.push({
        name: 'Environment Variables',
        status: 'fail',
        message: `Missing ${missing.length} required variable(s)`,
        details: `Missing: ${missing.join(', ')}`,
      });
    } else {
      results.push({
        name: 'Environment Variables',
        status: 'pass',
        message: `All ${requiredVars.length} required variables present`,
      });
    }

    const optionalMissing: string[] = [];
    optionalVars.forEach((varName) => {
      if (!process.env[varName]) {
        optionalMissing.push(varName);
      }
    });

    if (optionalMissing.length > 0) {
      results.push({
        name: 'Optional Environment Variables',
        status: 'warning',
        message: `${optionalMissing.length} optional variable(s) not set`,
        details: `Missing: ${optionalMissing.join(', ')}`,
      });
    }

    // Validate Facebook API credentials
    const appId = process.env.FACEBOOK_APP_ID;
    const appSecret = process.env.FACEBOOK_APP_SECRET;

    if (appId && appSecret) {
      try {
        // Get app access token
        const tokenResponse = await axios.get(
          'https://graph.facebook.com/oauth/access_token',
          {
            params: {
              client_id: appId,
              client_secret: appSecret,
              grant_type: 'client_credentials',
            },
            timeout: 10000,
          }
        );

        if (tokenResponse.data?.access_token) {
          const accessToken = tokenResponse.data.access_token;

          // Verify token by getting app info
          const appInfoResponse = await axios.get(
            `https://graph.facebook.com/v19.0/${appId}`,
            {
              params: {
                access_token: accessToken,
                fields: 'id,name',
              },
              timeout: 10000,
            }
          );

          if (appInfoResponse.data?.id) {
            results.push({
              name: 'Facebook API Credentials',
              status: 'pass',
              message: 'Facebook credentials are valid',
              details: `App: ${appInfoResponse.data.name || appInfoResponse.data.id}`,
            });
          } else {
            throw new Error('Invalid app info response');
          }
        } else {
          throw new Error('No access token in response');
        }
      } catch (error: any) {
        const errorMessage =
          error.response?.data?.error?.message || error.message || 'Unknown error';
        const errorCode = error.response?.data?.error?.code || 'N/A';

        if (errorCode === 101 || errorCode === 190) {
          results.push({
            name: 'Facebook API Credentials',
            status: 'fail',
            message: 'Invalid Facebook credentials',
            details: `Error ${errorCode}: ${errorMessage}. Check FACEBOOK_APP_ID and FACEBOOK_APP_SECRET.`,
          });
        } else if (error.response?.status === 401 || error.response?.status === 403) {
          results.push({
            name: 'Facebook API Credentials',
            status: 'fail',
            message: 'Facebook API authentication failed',
            details: `HTTP ${error.response.status}: ${errorMessage}`,
          });
        } else {
          results.push({
            name: 'Facebook API Credentials',
            status: 'warning',
            message: 'Could not validate Facebook credentials',
            details: `Error: ${errorMessage}. This may be a network issue.`,
          });
        }
      }
    } else {
      results.push({
        name: 'Facebook API Credentials',
        status: 'fail',
        message: 'Facebook credentials not configured',
        details: 'FACEBOOK_APP_ID or FACEBOOK_APP_SECRET not set',
      });
    }

    // Validate AI Service API keys
    const nvidiaKey = process.env.NVIDIA_API_KEY;
    const googleKey = process.env.GOOGLE_AI_API_KEY;

    if (nvidiaKey || googleKey) {
      // Test NVIDIA API key if present
      if (nvidiaKey) {
        try {
          const openai = new OpenAI({
            baseURL: 'https://integrate.api.nvidia.com/v1',
            apiKey: nvidiaKey,
          });

          const completion = await Promise.race([
            openai.chat.completions.create({
              model: 'meta/llama-3.1-8b-instruct',
              messages: [
                {
                  role: 'user',
                  content: 'Say "OK" if you can read this.',
                },
              ],
              max_tokens: 10,
              temperature: 0.1,
            }),
            new Promise<never>((_, reject) =>
              setTimeout(() => reject(new Error('Timeout after 15 seconds')), 15000)
            ),
          ]);

          if (completion.choices?.[0]?.message?.content) {
            results.push({
              name: 'NVIDIA API Key',
              status: 'pass',
              message: 'NVIDIA API key is valid',
              details: 'Successfully made test API call',
            });
          } else {
            throw new Error('No response content');
          }
        } catch (error: any) {
          const errorMessage = error.message || 'Unknown error';
          const statusCode = error.status || error.response?.status;

          if (statusCode === 401 || statusCode === 403) {
            results.push({
              name: 'NVIDIA API Key',
              status: 'fail',
              message: 'NVIDIA API key is invalid or expired',
              details: `HTTP ${statusCode}: ${errorMessage}. Get a new key from https://build.nvidia.com/`,
            });
          } else if (
            errorMessage.includes('timeout') ||
            errorMessage.includes('Timeout')
          ) {
            results.push({
              name: 'NVIDIA API Key',
              status: 'warning',
              message: 'NVIDIA API test timed out',
              details: 'This may be a network issue. Key format looks correct.',
            });
          } else {
            results.push({
              name: 'NVIDIA API Key',
              status: 'warning',
              message: 'Could not validate NVIDIA API key',
              details: `Error: ${errorMessage}`,
            });
          }
        }
      }

      // Note about Google AI key
      if (googleKey && !nvidiaKey) {
        results.push({
          name: 'Google AI API Key',
          status: 'warning',
          message: 'Google AI API key is set',
          details:
            'Validation not implemented. Key will be used as fallback for NVIDIA API.',
        });
      }
    } else {
      results.push({
        name: 'AI Service API Keys',
        status: 'warning',
        message: 'No AI service API keys found in environment',
        details:
          'Neither NVIDIA_API_KEY nor GOOGLE_AI_API_KEY is set. Keys may be stored in database.',
      });
    }

    // Calculate summary
    const passCount = results.filter((r) => r.status === 'pass').length;
    const failCount = results.filter((r) => r.status === 'fail').length;
    const warningCount = results.filter((r) => r.status === 'warning').length;

    const overallStatus =
      failCount > 0 ? 'unhealthy' : warningCount > 0 ? 'degraded' : 'healthy';

    return NextResponse.json(
      {
        timestamp: new Date().toISOString(),
        status: overallStatus,
        summary: {
          total: results.length,
          passed: passCount,
          failed: failCount,
          warnings: warningCount,
        },
        results,
      },
      {
        status: overallStatus === 'unhealthy' ? 503 : 200,
      }
    );
  } catch (error) {
    console.error('Validation error:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const sanitizedMessage = errorMessage
      .replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
      .replace(/at\s+.*/g, '') // Remove stack trace lines
      .replace(/\(.*?\)/g, '') // Remove file paths
      .substring(0, 200); // Limit length
    
    return NextResponse.json(
      {
        error: 'Validation failed',
        message: sanitizedMessage,
      },
      { status: 500 }
    );
  }
}

