import { createHash } from 'crypto';
import { prisma } from '@/lib/db';
import { AIContactAnalysis } from './google-ai-service';

interface CachedAnalysis {
  hash: string;
  analysis: AIContactAnalysis;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Generate a hash for conversation messages to use as cache key
 */
export function hashConversation(
  messages: Array<{ from: string; text: string; timestamp?: Date }>
): string {
  // Normalize messages for consistent hashing
  const normalized = messages
    .map(msg => ({
      from: msg.from.toLowerCase().trim(),
      text: msg.text.trim(),
      // Include timestamp only if it exists (for cache hit accuracy)
      timestamp: msg.timestamp ? new Date(msg.timestamp).toISOString().split('T')[0] : null
    }))
    .sort((a, b) => {
      // Sort by text content for consistent hashing
      if (a.text !== b.text) return a.text.localeCompare(b.text);
      return a.from.localeCompare(b.from);
    });

  const content = JSON.stringify(normalized);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Get cached analysis for a conversation hash
 */
export async function getCachedAnalysis(
  hash: string,
  maxAgeHours: number = 24
): Promise<AIContactAnalysis | null> {
  try {
    const cacheEntry = await prisma.conversationCache.findFirst({
      where: {
        hash,
        expiresAt: {
          gte: new Date()
        }
      },
      orderBy: {
        createdAt: 'desc'
      }
    });

    if (!cacheEntry) {
      return null;
    }

    // Check if cache is still valid
    const ageHours = (Date.now() - cacheEntry.createdAt.getTime()) / (1000 * 60 * 60);
    if (ageHours > maxAgeHours) {
      // Cache expired, delete it
      await prisma.conversationCache.delete({
        where: { id: cacheEntry.id }
      }).catch(() => {
        // Non-critical if deletion fails
      });
      return null;
    }

    // Parse and return cached analysis
    const analysis = JSON.parse(cacheEntry.analysisData) as AIContactAnalysis;
    console.log(`[ConversationCache] ✅ Cache hit for hash ${hash.substring(0, 8)}...`);
    return analysis;
  } catch (error) {
    console.warn('[ConversationCache] Error retrieving cache:', error);
    return null;
  }
}

/**
 * Store analysis in cache
 */
export async function setCachedAnalysis(
  hash: string,
  analysis: AIContactAnalysis,
  ttlHours: number = 24
): Promise<void> {
  try {
    const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000);

    await prisma.conversationCache.upsert({
      where: { hash },
      create: {
        hash,
        analysisData: JSON.stringify(analysis),
        expiresAt,
      },
      update: {
        analysisData: JSON.stringify(analysis),
        expiresAt,
        createdAt: new Date(),
      }
    });

    console.log(`[ConversationCache] 💾 Cached analysis for hash ${hash.substring(0, 8)}... (expires in ${ttlHours}h)`);
  } catch (error) {
    // Non-critical - cache failures shouldn't break the flow
    console.warn('[ConversationCache] Error storing cache:', error);
  }
}

/**
 * Clear expired cache entries (cleanup function)
 */
export async function clearExpiredCache(): Promise<number> {
  try {
    const result = await prisma.conversationCache.deleteMany({
      where: {
        expiresAt: {
          lt: new Date()
        }
      }
    });

    if (result.count > 0) {
      console.log(`[ConversationCache] 🗑️ Cleared ${result.count} expired cache entries`);
    }

    return result.count;
  } catch (error) {
    console.warn('[ConversationCache] Error clearing expired cache:', error);
    return 0;
  }
}









