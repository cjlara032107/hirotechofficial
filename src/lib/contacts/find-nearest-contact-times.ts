/**
 * Find the nearest contact with sufficient best contact times data
 * and return their best contact times.
 * 
 * Priority order for "nearest" contact:
 * 1. Same tags (most similar)
 * 2. Same pipeline/stage
 * 3. Same Facebook page
 * 4. Similar lead score (±10 points)
 * 5. Same timezone
 */

import { prisma } from '@/lib/db';

interface ContactSimilarity {
  contactId: string;
  similarityScore: number;
  matchingCriteria: string[];
}

/**
 * Check if a contact has sufficient best contact times data
 */
function hasSufficientBestContactTimes(
  bestContactTimes: unknown
): boolean {
  if (!bestContactTimes || typeof bestContactTimes !== 'object') {
    return false;
  }

  const times = bestContactTimes as Record<string, unknown>;
  
  // Check if it's a default/fallback (has isDefault flag)
  if (times.isDefault === true) {
    return false; // Don't use defaults from other contacts
  }

  // Check if it has actual best contact times data
  const bestTimes = times.bestContactTimes;
  if (!Array.isArray(bestTimes) || bestTimes.length === 0) {
    return false;
  }

  // Check if it has sufficient message data (not default)
  const totalMessages = times.totalMessagesAnalyzed;
  if (typeof totalMessages === 'number' && totalMessages >= 2) {
    return true;
  }

  return false;
}

/**
 * Calculate similarity score between two contacts
 */
function calculateSimilarity(
  contact1: {
    tags: string[];
    pipelineId: string | null;
    stageId: string | null;
    facebookPageId: string;
    leadScore: number;
    timezone: number | null;
  },
  contact2: {
    tags: string[];
    pipelineId: string | null;
    stageId: string | null;
    facebookPageId: string;
    leadScore: number;
    timezone: number | null;
  }
): { score: number; criteria: string[] } {
  let score = 0;
  const criteria: string[] = [];

  // 1. Tag similarity (highest weight: 100 points per matching tag)
  const contact1Tags = new Set(contact1.tags);
  const contact2Tags = new Set(contact2.tags);
  const commonTags = [...contact1Tags].filter(tag => contact2Tags.has(tag));
  if (commonTags.length > 0) {
    score += commonTags.length * 100;
    criteria.push(`${commonTags.length} shared tag${commonTags.length !== 1 ? 's' : ''}`);
  }

  // 2. Same pipeline and stage (80 points)
  if (contact1.pipelineId && contact1.pipelineId === contact2.pipelineId) {
    score += 40;
    criteria.push('same pipeline');
    if (contact1.stageId && contact1.stageId === contact2.stageId) {
      score += 40;
      criteria.push('same stage');
    }
  }

  // 3. Same Facebook page (30 points)
  if (contact1.facebookPageId === contact2.facebookPageId) {
    score += 30;
    criteria.push('same Facebook page');
  }

  // 4. Similar lead score (20 points if within ±10)
  const scoreDiff = Math.abs(contact1.leadScore - contact2.leadScore);
  if (scoreDiff <= 10) {
    score += 20;
    criteria.push('similar lead score');
  }

  // 5. Same timezone (10 points)
  if (contact1.timezone !== null && contact1.timezone === contact2.timezone) {
    score += 10;
    criteria.push('same timezone');
  }

  return { score, criteria };
}

/**
 * Find the nearest contact with sufficient best contact times data
 */
export async function findNearestContactWithBestTimes(
  contactId: string,
  organizationId: string
): Promise<{ contactId: string; bestContactTimes: Record<string, unknown>; source: string } | null> {
  try {
    // Get the target contact's details
    const targetContact = await prisma.contact.findUnique({
      where: { id: contactId },
      select: {
        id: true,
        tags: true,
        pipelineId: true,
        stageId: true,
        facebookPageId: true,
        leadScore: true,
        timezone: true,
      },
    });

    if (!targetContact) {
      console.log(`[FindNearestContact] Target contact ${contactId} not found`);
      return null;
    }

    // Get all contacts in the same organization (excluding the target contact)
    // We'll check bestContactTimes separately to include all contacts first
    const allContacts = await prisma.contact.findMany({
      where: {
        organizationId,
        id: { not: contactId },
      },
      select: {
        id: true,
        tags: true,
        pipelineId: true,
        stageId: true,
        facebookPageId: true,
        leadScore: true,
        timezone: true,
        bestContactTimes: true,
      },
    });

    console.log(`[FindNearestContact] Found ${allContacts.length} contacts in organization`);

    // Calculate similarity scores and filter for sufficient data
    const candidates: (ContactSimilarity & { bestContactTimes: Record<string, unknown> })[] = [];

    for (const contact of allContacts) {
      // Check if this contact has sufficient data
      if (!hasSufficientBestContactTimes(contact.bestContactTimes)) {
        continue; // Skip contacts with insufficient or default data
      }

      // Calculate similarity
      const { score, criteria } = calculateSimilarity(targetContact, contact);
      
      if (score > 0 && contact.bestContactTimes) {
        candidates.push({
          contactId: contact.id,
          similarityScore: score,
          matchingCriteria: criteria,
          bestContactTimes: contact.bestContactTimes as Record<string, unknown>,
        });
      }
    }

    if (candidates.length === 0) {
      console.log(`[FindNearestContact] No similar contacts found with sufficient data`);
      return null;
    }

    // Sort by similarity score (highest first)
    candidates.sort((a, b) => b.similarityScore - a.similarityScore);

    // Get the best match (already filtered for sufficient data)
    const bestMatch = candidates[0];

    console.log(`[FindNearestContact] Found nearest contact: ${bestMatch.contactId} (similarity: ${bestMatch.similarityScore}, criteria: ${bestMatch.matchingCriteria.join(', ')})`);

    return {
      contactId: bestMatch.contactId,
      bestContactTimes: bestMatch.bestContactTimes,
      source: `Similar contact (${bestMatch.matchingCriteria.join(', ')})`,
    };
  } catch (error) {
    console.error(`[FindNearestContact] Error finding nearest contact:`, error);
    return null;
  }
}

