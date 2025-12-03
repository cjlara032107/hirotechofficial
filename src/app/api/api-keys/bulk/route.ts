import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { encryptKey } from '@/lib/crypto/encryption';
import { ApiKeyStatus } from '@prisma/client';

/**
 * POST /api/api-keys/bulk
 * Bulk add API keys (bypasses developer check for convenience)
 * Accepts array of keys: ["nvapi-...", "nvapi-...", ...]
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const keys = body.keys || body.key ? [body.key] : [];

    if (!Array.isArray(keys) || keys.length === 0) {
      return NextResponse.json(
        { error: 'Keys array is required. Provide `keys: ["nvapi-...", ...]`' },
        { status: 400 }
      );
    }

    const results: Array<{
      id: string;
      name: string | null;
      status: string;
      added: boolean;
      skipped: boolean;
      error?: string;
    }> = [];

    let added = 0;
    let skipped = 0;
    let errors = 0;

    for (let i = 0; i < keys.length; i++) {
      const rawKey = typeof keys[i] === 'string' ? keys[i].trim() : '';
      
      if (!rawKey) {
        results.push({
          id: '',
          name: null,
          status: 'ERROR',
          added: false,
          skipped: false,
          error: 'Empty key',
        });
        errors++;
        continue;
      }

      try {
        // Encrypt the key
        const encryptedKey = encryptKey(rawKey);
        
        // Check if key already exists
        const existing = await prisma.apiKey.findFirst({
          where: {
            encryptedKey: encryptedKey,
          },
        });

        if (existing) {
          results.push({
            id: existing.id,
            name: existing.name,
            status: existing.status,
            added: false,
            skipped: true,
          });
          skipped++;
          continue;
        }

        // Create new API key
        const apiKey = await prisma.apiKey.create({
          data: {
            name: `NVIDIA API Key ${i + 1}`,
            encryptedKey: encryptedKey,
            status: ApiKeyStatus.ACTIVE,
            metadata: {
              prefix: rawKey.substring(0, 12),
              length: rawKey.length,
              addedBy: 'bulk-import',
              addedAt: new Date().toISOString(),
            },
          },
        });

        results.push({
          id: apiKey.id,
          name: apiKey.name,
          status: apiKey.status,
          added: true,
          skipped: false,
        });
        added++;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        results.push({
          id: '',
          name: null,
          status: 'ERROR',
          added: false,
          skipped: false,
          error: errorMsg,
        });
        errors++;
      }
    }

    // Invalidate concurrency cache
    try {
      const { invalidateConcurrencyCache } = await import('@/lib/ai/dynamic-concurrency');
      invalidateConcurrencyCache();
    } catch (error) {
      // Non-critical
    }

    // Get final count
    const totalActive = await prisma.apiKey.count({
      where: {
        status: ApiKeyStatus.ACTIVE,
      },
    });

    return NextResponse.json({
      summary: {
        total: keys.length,
        added,
        skipped,
        errors,
        totalActiveKeys: totalActive,
      },
      results,
    }, { status: 201 });
  } catch (error) {
    console.error('Bulk add API keys error:', error);
    return NextResponse.json(
      { 
        error: 'Failed to bulk add API keys',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}








