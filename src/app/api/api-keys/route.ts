import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { encryptKey } from '@/lib/crypto/encryption';

/**
 * GET /api/api-keys
 * List all API keys (developer only)
 */
export async function GET() {
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

    const keys = await prisma.apiKey.findMany({
      orderBy: {
        createdAt: 'desc',
      },
    });

    // Return keys without encrypted data (for security)
    const safeKeys = (keys as Array<{
      id: string;
      name: string | null;
      status: string;
      rateLimitedAt: Date | null;
      lastUsedAt: Date | null;
      lastSuccessAt: Date | null;
      totalRequests: number;
      failedRequests: number;
      consecutiveFailures: number;
      metadata: unknown;
      createdAt: Date;
      updatedAt: Date;
    }>).map(key => ({
      id: key.id,
      name: key.name,
      status: key.status,
      rateLimitedAt: key.rateLimitedAt ? key.rateLimitedAt.toISOString() : null,
      lastUsedAt: key.lastUsedAt ? key.lastUsedAt.toISOString() : null,
      lastSuccessAt: key.lastSuccessAt ? key.lastSuccessAt.toISOString() : null,
      totalRequests: key.totalRequests,
      failedRequests: key.failedRequests,
      consecutiveFailures: key.consecutiveFailures,
      metadata: key.metadata,
      createdAt: key.createdAt.toISOString(),
      updatedAt: key.updatedAt.toISOString(),
      // Calculate success rate
      successRate: key.totalRequests > 0 
        ? ((key.totalRequests - key.failedRequests) / key.totalRequests * 100).toFixed(1)
        : '0',
      // Calculate time until rate limit expires (if rate-limited)
      timeUntilActive: key.rateLimitedAt && key.status === 'RATE_LIMITED'
        ? Math.max(0, 24 * 60 * 60 * 1000 - (Date.now() - new Date(key.rateLimitedAt).getTime()))
        : null,
    }));

    return NextResponse.json(safeKeys);
  } catch (error) {
    console.error('Get API keys error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch API keys' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/api-keys
 * Add a new API key (developer only)
 */
export async function POST(request: NextRequest) {
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

    const body = await request.json();

    /**
     * Support both single key and bulk keys
     * - Single:
     *   { "key": "sk-...", "name": "Key 1", "metadata": { ... } }
     * - Bulk:
     *   { "keys": [{ "key": "sk-1", "name": "Key 1" }, { "key": "sk-2" }] }
     */
    const keysPayload: Array<{ key: string; name?: string; metadata?: unknown }> = Array.isArray(
      body?.keys
    )
      ? body.keys.map((item: { key: string; name?: string; metadata?: unknown }) => ({
          key: item.key,
          name: item.name,
          metadata: item.metadata,
        }))
      : body?.key
        ? [{ key: String(body.key), name: body.name, metadata: body.metadata }]
        : [];

    if (keysPayload.length === 0) {
      return NextResponse.json(
        { error: 'API key is required. Provide `key` or `keys`.' },
        { status: 400 }
      );
    }

    const results: Array<{
      id: string;
      name: string | null;
      status: string;
      metadata: unknown;
      createdAt: string;
    }> = [];

    for (const item of keysPayload) {
      const rawKey = typeof item?.key === 'string' ? item.key.trim() : '';
      if (!rawKey) {
        continue;
      }

      // Encrypt the key
      const encryptedKey = encryptKey(rawKey);

      // Extract key prefix for metadata (first 8 chars for display)
      const keyPrefix = rawKey.substring(0, 8);
      const keyLength = rawKey.length;

      // Create API key record
      const apiKey = await prisma.apiKey.create({
        data: {
          name: item?.name?.trim() || null,
          encryptedKey,
          status: 'ACTIVE',
          metadata: {
            prefix: keyPrefix,
            length: keyLength,
            ...(item?.metadata || {}),
          },
        },
      });

      results.push({
        id: apiKey.id,
        name: apiKey.name,
        status: apiKey.status,
        metadata: apiKey.metadata,
        createdAt: apiKey.createdAt.toISOString(),
      });
    }

    if (results.length === 0) {
      return NextResponse.json(
        { error: 'No valid API keys provided' },
        { status: 400 }
      );
    }

    // If single key, return object; if multiple, return array
    const responseBody = results.length === 1 ? results[0] : results;

    // Invalidate concurrency cache so limits update with new keys
    const { invalidateConcurrencyCache } = await import('@/lib/ai/dynamic-concurrency');
    invalidateConcurrencyCache();

    return NextResponse.json(responseBody, { status: 201 });
  } catch (error) {
    console.error('Create API key error:', error);
    
    // Check if it's an encryption error
    if (error instanceof Error && error.message.includes('ENCRYPTION_KEY')) {
      return NextResponse.json(
        { error: 'Encryption configuration error. Please check ENCRYPTION_KEY environment variable.' },
        { status: 500 }
      );
    }

    return NextResponse.json(
      { error: 'Failed to create API key' },
      { status: 500 }
    );
  }
}

