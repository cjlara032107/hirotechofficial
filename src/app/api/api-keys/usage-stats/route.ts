import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import apiKeyManager from '@/lib/ai/api-key-manager';

/**
 * GET /api/api-keys/usage-stats
 * Get rate limit usage statistics for API keys (developer only)
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check developer role only
    if (session.user.role !== 'DEVELOPER') {
      return NextResponse.json(
        { error: 'Forbidden - Developer access required' },
        { status: 403 }
      );
    }

    const stats = await apiKeyManager.getRateLimitUsageStats();

    return NextResponse.json(stats, {
      headers: {
        'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
      },
    });
  } catch (error) {
    console.error('[API Keys Usage Stats] Error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch usage statistics' },
      { status: 500 }
    );
  }
}









