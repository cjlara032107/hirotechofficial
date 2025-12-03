import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { encryptKey } from '@/lib/crypto/encryption';

/**
 * POST /api/api-keys/remove-failed
 * Remove the 19 non-working API keys from the database
 */
export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // List of non-working keys (19 keys that don't work with any large models)
    const FAILED_KEYS = [
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
      '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',
    ];

    let deleted = 0;
    let notFound = 0;
    let errors = 0;
    const deletedKeys: Array<{ id: string; name: string | null }> = [];

    console.log(`[Remove Failed Keys] Starting removal of ${FAILED_KEYS.length} non-working keys...`);

    for (const rawKey of FAILED_KEYS) {
      try {
        // Encrypt the key to find it in database
        const encryptedKey = encryptKey(rawKey);
        
        // Find the key
        const existing = await prisma.apiKey.findFirst({
          where: {
            encryptedKey: encryptedKey,
          },
        });

        if (existing) {
          // Delete the key
          await prisma.apiKey.delete({
            where: {
              id: existing.id,
            },
          });

          deleted++;
          deletedKeys.push({
            id: existing.id,
            name: existing.name,
          });

          console.log(`[Remove Failed Keys] ✅ Deleted: ${existing.name || existing.id}`);
        } else {
          notFound++;
          console.log(`[Remove Failed Keys] ⏭️  Not found: ${rawKey.substring(0, 20)}...`);
        }
      } catch (error) {
        errors++;
        console.error(`[Remove Failed Keys] ❌ Error removing ${rawKey.substring(0, 20)}...:`, error);
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
        status: 'ACTIVE',
      },
    });

    console.log(`[Remove Failed Keys] ✅ Completed: ${deleted} deleted, ${notFound} not found, ${errors} errors`);

    return NextResponse.json({
      success: true,
      summary: {
        total: FAILED_KEYS.length,
        deleted,
        notFound,
        errors,
        totalActiveKeys: totalActive,
      },
      deletedKeys,
    }, { status: 200 });
  } catch (error) {
    console.error('Remove failed keys error:', error);
    return NextResponse.json(
      { 
        error: 'Failed to remove failed keys',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}








