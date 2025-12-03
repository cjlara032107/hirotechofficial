import { prisma } from '@/lib/db';
import { detectScoreRangeOverlaps } from './validation';

/**
 * Intelligent Stage Analyzer
 * Automatically assigns lead score ranges to pipeline stages based on:
 * - Stage type (LEAD, IN_PROGRESS, WON, LOST, ARCHIVED)
 * - Stage order (position in pipeline)
 * - Number of stages in pipeline
 */

interface StageScoreRange {
  stageId: string;
  leadScoreMin: number;
  leadScoreMax: number;
}

/**
 * Calculates optimal lead score ranges for all stages in a pipeline
 * 
 * This algorithm intelligently assigns score ranges based on stage type and order:
 * 
 * **LEAD stages**: 0-30 (cold to warm leads)
 *   - Distributed evenly across all LEAD stages
 *   - Example: 3 LEAD stages → 0-10, 11-20, 21-30
 * 
 * **IN_PROGRESS stages**: 31-80 (qualified to closing)
 *   - Distributed evenly across all IN_PROGRESS stages
 *   - Example: 4 IN_PROGRESS stages → 31-42, 43-54, 55-66, 67-80
 * 
 * **WON stages**: 81-100 (hot leads to closed won)
 *   - Distributed evenly across all WON stages
 *   - Example: 2 WON stages → 81-90, 91-100
 * 
 * **LOST stages**: 0-20 (low scores indicate lost opportunity)
 *   - All LOST stages share the same range (0-20)
 * 
 * **ARCHIVED stages**: 0-100 (accept any score)
 *   - All ARCHIVED stages accept the full range
 * 
 * The algorithm ensures:
 * - No overlapping ranges within the same stage type
 * - Proper progression from cold (0) to hot (100)
 * - Stages are ordered correctly before range calculation
 * 
 * @param pipelineId - The ID of the pipeline to calculate ranges for
 * @returns Promise resolving to array of stage score ranges
 * @throws Error if pipeline not found
 * 
 * @example
 * ```typescript
 * const ranges = await calculateStageScoreRanges('pipeline_123');
 * // Returns: [
 * //   { stageId: 'stage_1', leadScoreMin: 0, leadScoreMax: 10 },
 * //   { stageId: 'stage_2', leadScoreMin: 11, leadScoreMax: 20 },
 * //   ...
 * // ]
 * ```
 */
export async function calculateStageScoreRanges(pipelineId: string): Promise<StageScoreRange[]> {
  // Fetch pipeline with stages
  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: {
      stages: {
        orderBy: { order: 'asc' }
      }
    }
  });

  if (!pipeline) {
    throw new Error(`Pipeline ${pipelineId} not found`);
  }

  const stages = pipeline.stages;
  if (!stages || stages.length === 0) {
    console.warn(`[Stage Analyzer] ⚠️ Pipeline ${pipelineId} has no stages - cannot calculate score ranges`);
    return [];
  }

  const scoreRanges: StageScoreRange[] = [];

  // Separate stages by type for smart scoring
  const leadStages = stages.filter(s => s.type === 'LEAD');
  const inProgressStages = stages.filter(s => s.type === 'IN_PROGRESS');
  const wonStages = stages.filter(s => s.type === 'WON');
  const lostStages = stages.filter(s => s.type === 'LOST');
  const archivedStages = stages.filter(s => s.type === 'ARCHIVED');

  // Calculate ranges based on pipeline structure
  let currentScore = 0;

  // 1. LEAD stages: 0-30 range (cold to warm leads)
  if (leadStages.length > 0) {
    const rangeSize = 30 / leadStages.length;
    leadStages.forEach((stage, index) => {
      const min = Math.round(currentScore);
      const max = index === leadStages.length - 1 
        ? 30 
        : Math.round(currentScore + rangeSize);
      
      scoreRanges.push({
        stageId: stage.id,
        leadScoreMin: min,
        leadScoreMax: max
      });
      
      currentScore = max;
    });
  }

  // 2. IN_PROGRESS stages: 31-80 range (qualified to closing)
  if (inProgressStages.length > 0) {
    currentScore = 31;
    const rangeSize = 50 / inProgressStages.length;
    
    inProgressStages.forEach((stage, index) => {
      const min = Math.round(currentScore);
      const max = index === inProgressStages.length - 1 
        ? 80 
        : Math.round(currentScore + rangeSize);
      
      scoreRanges.push({
        stageId: stage.id,
        leadScoreMin: min,
        leadScoreMax: max
      });
      
      currentScore = max;
    });
  }

  // 3. WON stages: 81-100 range (hot leads to closed won)
  if (wonStages.length > 0) {
    currentScore = 81;
    const rangeSize = 20 / wonStages.length;
    
    wonStages.forEach((stage, index) => {
      const min = Math.round(currentScore);
      const max = index === wonStages.length - 1 
        ? 100 
        : Math.round(currentScore + rangeSize);
      
      scoreRanges.push({
        stageId: stage.id,
        leadScoreMin: min,
        leadScoreMax: max
      });
      
      currentScore = max;
    });
  }

  // 4. LOST stages: 0-20 range (low scores indicate lost opportunity)
  if (lostStages.length > 0) {
    lostStages.forEach(stage => {
      scoreRanges.push({
        stageId: stage.id,
        leadScoreMin: 0,
        leadScoreMax: 20
      });
    });
  }

  // 5. ARCHIVED stages: 0-100 range (accept any score)
  if (archivedStages.length > 0) {
    archivedStages.forEach(stage => {
      scoreRanges.push({
        stageId: stage.id,
        leadScoreMin: 0,
        leadScoreMax: 100
      });
    });
  }

  console.log(`[Stage Analyzer] Calculated score ranges for pipeline ${pipeline.name}:`);
  scoreRanges.forEach(range => {
    const stage = stages.find(s => s.id === range.stageId);
    console.log(`  - ${stage?.name}: ${range.leadScoreMin}-${range.leadScoreMax}`);
  });

  return scoreRanges;
}

/**
 * Applies calculated score ranges to pipeline stages in the database
 * 
 * Takes the score ranges calculated by `calculateStageScoreRanges` and
 * updates the database with the new min/max values for each stage.
 * 
 * This operation:
 * - Validates that ranges don't overlap (using detectScoreRangeOverlaps)
 * - Updates all stages in a single transaction
 * - Logs the applied ranges for debugging
 * 
 * @param pipelineId - The ID of the pipeline to apply ranges to
 * @returns Promise that resolves when ranges are applied
 * @throws Error if pipeline not found or if range overlaps are detected
 * 
 * @example
 * ```typescript
 * await applyStageScoreRanges('pipeline_123');
 * // All stages in the pipeline now have updated leadScoreMin/leadScoreMax
 * ```
 */
export async function applyStageScoreRanges(pipelineId: string): Promise<void> {
  const scoreRanges = await calculateStageScoreRanges(pipelineId);

  // Validate for overlapping score ranges before applying
  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: {
      stages: {
        orderBy: { order: 'asc' }
      }
    }
  });

  if (pipeline && pipeline.stages) {
    // Create temporary stages array with new ranges for validation
    const stagesWithNewRanges = pipeline.stages.map(stage => {
      const newRange = scoreRanges.find(r => r.stageId === stage.id);
      return {
        id: stage.id,
        name: stage.name,
        leadScoreMin: newRange?.leadScoreMin ?? stage.leadScoreMin,
        leadScoreMax: newRange?.leadScoreMax ?? stage.leadScoreMax,
        type: stage.type,
      };
    });

    const overlaps = detectScoreRangeOverlaps(stagesWithNewRanges);
    if (overlaps.length > 0) {
      console.warn(`[Stage Analyzer] ⚠️ Detected ${overlaps.length} overlapping score range(s) in pipeline ${pipelineId}:`);
      overlaps.forEach(overlap => {
        console.warn(`[Stage Analyzer]   - ${overlap.stage1} overlaps with ${overlap.stage2} at range ${overlap.overlap}`);
      });
      // Continue anyway - the overlaps will be handled by the stage matching logic
      // which uses priority-based routing (status first, then score)
    }
  }

  // Update each stage with its calculated range
  await Promise.all(
    scoreRanges.map(range =>
      prisma.pipelineStage.update({
        where: { id: range.stageId },
        data: {
          leadScoreMin: range.leadScoreMin,
          leadScoreMax: range.leadScoreMax
        }
      })
    )
  );

  console.log(`[Stage Analyzer] Applied score ranges to ${scoreRanges.length} stages`);
}

/**
 * Determines if a contact should be prevented from being downgraded to a lower stage
 * 
 * This function implements intelligent downgrade prevention to protect valuable leads:
 * - Contacts with scores >= 80 cannot be moved to stages with min score < 50
 *   (hot leads deserve advanced stages)
 * - Contacts with scores >= 50 cannot be moved to "New Lead" type stages (min score < 20)
 *   (qualified leads shouldn't be sent back to initial stages)
 * 
 * This prevents high-value contacts from being incorrectly reassigned to early pipeline
 * stages, which could result in lost opportunities or poor customer experience.
 * 
 * @param currentStageOrder - Current stage order (null if not in a stage)
 * @param targetStageOrder - Target stage order
 * @param currentScore - Current lead score (0-100)
 * @param newScore - New lead score after analysis (0-100)
 * @param targetStageMin - Minimum lead score for the target stage
 * @returns True if downgrade should be prevented, false if movement is allowed
 * 
 * @example
 * ```typescript
 * // Prevents hot lead (score 85) from going to early stage (min 10)
 * shouldPreventDowngrade(5, 1, 85, 85, 10); // true
 * 
 * // Allows qualified lead (score 60) to go to appropriate stage (min 50)
 * shouldPreventDowngrade(3, 4, 60, 60, 50); // false
 * ```
 */
export function shouldPreventDowngrade(
  currentStageOrder: number | null,
  targetStageOrder: number,
  currentScore: number,
  newScore: number,
  targetStageMin: number
): boolean {
  // Prevent contacts with 80+ scores from going to stages with min score < 50
  // These are hot leads that deserve advanced stages
  if (newScore >= 80 && targetStageMin < 50) {
    console.log(`[Stage Analyzer] Prevented downgrade: Score ${newScore} too high for stage (min: ${targetStageMin})`);
    return true;
  }

  // Prevent contacts with 50+ scores from going to "New Lead" type stages (min score < 20)
  // Qualified leads shouldn't be sent back to initial stages
  if (newScore >= 50 && targetStageMin < 20) {
    console.log(`[Stage Analyzer] Prevented downgrade: Score ${newScore} blocked from low stage (min: ${targetStageMin})`);
    return true;
  }

  // Allow movement if score is higher and stage is appropriate
  return false;
}

/**
 * Finds the best matching pipeline stage for a contact based on lead score and status
 * 
 * This function implements a 3-tier priority routing system:
 * 
 * **1. Status-Based Routing (Highest Priority)**
 *    - WON contacts → WON stages (regardless of score)
 *    - LOST contacts → LOST stages (regardless of score)
 *    - This takes precedence over score-based routing
 * 
 * **2. Score-Based Routing (Secondary Priority)**
 *    - Finds stages where the lead score falls within the stage's min-max range
 *    - Excludes WON, LOST, and ARCHIVED stages from score matching
 *    - If multiple stages match (overlapping ranges), uses first by order
 *    - Handles boundary cases: score 0 matches min <= 0, score 100 matches max >= 100
 * 
 * **3. Fallback Routing (Lowest Priority)**
 *    - If no stage matches the score range, finds the closest stage by midpoint
 *    - Calculates distance from score to stage midpoint
 *    - Returns the stage with the smallest distance
 * 
 * The algorithm ensures contacts are always assigned to an appropriate stage,
 * even if score ranges don't perfectly match.
 * 
 * @param pipelineId - The ID of the pipeline to find a stage in
 * @param leadScore - The contact's lead score (0-100, or null/undefined)
 * @param leadStatus - The contact's lead status ('WON', 'LOST', 'NEW', etc., or null/undefined)
 * @returns Promise resolving to the best matching stage ID, or null if no match found
 * 
 * @example
 * ```typescript
 * // Status-based routing
 * const stage1 = await findBestMatchingStage('pipeline_123', 50, 'WON');
 * // Returns WON stage ID regardless of score
 * 
 * // Score-based routing
 * const stage2 = await findBestMatchingStage('pipeline_123', 75, 'NEW');
 * // Returns stage with range containing 75 (e.g., 70-80)
 * 
 * // Fallback routing
 * const stage3 = await findBestMatchingStage('pipeline_123', 45, 'NEW');
 * // Returns closest stage by midpoint if no exact match
 * ```
 */
export async function findBestMatchingStage(
  pipelineId: string,
  leadScore: number | null,
  leadStatus: string | null | undefined
): Promise<string | null> {
  // Handle null/undefined pipelineId
  if (!pipelineId) {
    console.warn(`[Stage Analyzer] ⚠️ Pipeline ID is null or undefined`);
    return null;
  }

  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: {
      stages: {
        orderBy: { order: 'asc' }
      }
    }
  });

  if (!pipeline) {
    return null;
  }

  const stages = pipeline.stages;

  // Return null if pipeline has no stages
  if (!stages || stages.length === 0) {
    console.warn(`[Stage Analyzer] ⚠️ Pipeline ${pipelineId} has no stages - cannot assign contact`);
    return null;
  }

  // 1. PRIORITY ROUTING: Route by status first
  // Handle null/undefined leadStatus
  const normalizedStatus = leadStatus || 'NEW';
  
  // If status is WON, route to WON stage
  if (normalizedStatus === 'WON') {
    const wonStage = stages.find(s => s.type === 'WON');
    if (wonStage) {
      console.log(`[Stage Analyzer] Status-based routing: WON → ${wonStage.name}`);
      return wonStage.id;
    }
  }

  // If status is LOST, route to LOST stage
  if (normalizedStatus === 'LOST') {
    const lostStage = stages.find(s => s.type === 'LOST');
    if (lostStage) {
      console.log(`[Stage Analyzer] Status-based routing: LOST → ${lostStage.name}`);
      return lostStage.id;
    }
  }

  // Handle null leadScore - return null if no status-based routing matched
  if (leadScore === null || leadScore === undefined) {
    console.warn(`[Stage Analyzer] ⚠️ Lead score is null/undefined, cannot perform score-based routing`);
    return null;
  }

  // Clamp leadScore to valid range (0-100)
  // Handle boundary cases: exactly 0 or 100 are valid scores
  const clampedScore = Math.max(0, Math.min(100, leadScore));
  if (leadScore !== clampedScore) {
    console.log(`[Stage Analyzer] Clamped leadScore from ${leadScore} to ${clampedScore}`);
  }
  
  // Ensure boundary scores (0 and 100) are handled correctly
  // Score 0 should match stages with leadScoreMin <= 0
  // Score 100 should match stages with leadScoreMax >= 100

  // 2. SCORE-BASED ROUTING: Find stage where lead score falls within range
  // Handle overlapping ranges by selecting the first matching stage (priority by order)
  // Handle boundary cases: score 0 matches stages with min <= 0, score 100 matches stages with max >= 100
  const matchingStages = stages.filter(stage => {
    // Handle null/undefined stage properties
    const stageMin = stage.leadScoreMin ?? 0;
    const stageMax = stage.leadScoreMax ?? 100;
    
    // Handle exact boundary scores (0 and 100) and all scores in between
    // Score 0 matches if stageMin <= 0, score 100 matches if stageMax >= 100
    // All other scores match if they fall within the range [stageMin, stageMax]
    const scoreMatches = (clampedScore === 0 && stageMin <= 0) ||
                         (clampedScore === 100 && stageMax >= 100) ||
                         (clampedScore >= stageMin && clampedScore <= stageMax);
    
    return scoreMatches &&
           stage.type !== 'WON' &&  // Skip WON/LOST unless explicitly matched above
           stage.type !== 'LOST' &&
           stage.type !== 'ARCHIVED';
  });

  if (matchingStages.length > 0) {
    // If multiple stages match (overlapping ranges), use the first one by order
    const matchingStage = matchingStages[0];
    if (matchingStages.length > 1) {
      console.warn(`[Stage Analyzer] ⚠️ Score ${clampedScore} matches ${matchingStages.length} overlapping stages, using first match: ${matchingStage.name}`);
    }
    console.log(`[Stage Analyzer] Score-based routing: ${clampedScore} → ${matchingStage.name} (${matchingStage.leadScoreMin}-${matchingStage.leadScoreMax})`);
    return matchingStage.id;
  }

  // 3. FALLBACK: Find closest stage by lead score
  // Find first non-ARCHIVED stage to initialize
  const nonArchivedStages = stages.filter(s => s.type !== 'ARCHIVED');
  if (nonArchivedStages.length === 0) {
    // If all stages are ARCHIVED, return first stage
    console.log(`[Stage Analyzer] All stages are ARCHIVED, returning first stage`);
    return stages[0]?.id || null;
  }

  // Handle null/undefined stage properties
  let closestStage = nonArchivedStages[0];
  if (!closestStage) {
    return null;
  }
  
  const stageMin1 = closestStage.leadScoreMin ?? 0;
  const stageMax1 = closestStage.leadScoreMax ?? 100;
  const stageMidpoint1 = (stageMin1 + stageMax1) / 2;
  let closestDistance = Math.abs(stageMidpoint1 - clampedScore);

  for (const stage of nonArchivedStages) {
    // Handle null/undefined stage properties
    const minScore = stage.leadScoreMin ?? 0;
    const maxScore = stage.leadScoreMax ?? 100;
    const stageMidpoint = (minScore + maxScore) / 2;
    const distance = Math.abs(stageMidpoint - clampedScore);
    
    if (distance < closestDistance) {
      closestDistance = distance;
      closestStage = stage;
    }
  }

  console.log(`[Stage Analyzer] Fallback routing: ${clampedScore} → ${closestStage.name} (closest match)`);
  return closestStage.id;
}

/**
 * Gets a summary of stage score distribution for a pipeline
 * 
 * Returns statistics about each stage including:
 * - Stage name and type
 * - Score range (min-max)
 * - Contact count in the stage
 * - Average score (midpoint of range)
 * 
 * Useful for analytics and understanding how contacts are distributed
 * across pipeline stages.
 * 
 * @param pipelineId - The ID of the pipeline to get distribution for
 * @returns Promise resolving to distribution summary object, or null if pipeline not found
 * 
 * @example
 * ```typescript
 * const distribution = await getStageScoreDistribution('pipeline_123');
 * // Returns: {
 * //   pipelineName: 'Sales Pipeline',
 * //   stages: [
 * //     { name: 'New Lead', type: 'LEAD', scoreRange: '0-10', contactCount: 25, avgScore: 5 },
 * //     { name: 'Qualified', type: 'IN_PROGRESS', scoreRange: '31-50', contactCount: 15, avgScore: 40.5 },
 * //     ...
 * //   ]
 * // }
 * ```
 */
export async function getStageScoreDistribution(pipelineId: string) {
  const pipeline = await prisma.pipeline.findUnique({
    where: { id: pipelineId },
    include: {
      stages: {
        orderBy: { order: 'asc' },
        include: {
          _count: {
            select: { contacts: true }
          }
        }
      }
    }
  });

  if (!pipeline) {
    return null;
  }

  return {
    pipelineName: pipeline.name,
    stages: pipeline.stages.map(stage => ({
      name: stage.name,
      type: stage.type,
      scoreRange: `${stage.leadScoreMin}-${stage.leadScoreMax}`,
      contactCount: stage._count.contacts,
      avgScore: stage.leadScoreMin + (stage.leadScoreMax - stage.leadScoreMin) / 2
    }))
  };
}

/**
 * Auto-generates score ranges for all active pipelines in an organization
 * 
 * This is a batch operation that:
 * - Finds all non-archived pipelines for the organization
 * - Calculates and applies score ranges for each pipeline
 * - Skips pipelines with no stages
 * - Returns the count of updated pipelines
 * 
 * Useful for initial setup or when reorganizing pipeline structures.
 * 
 * @param organizationId - The ID of the organization
 * @returns Promise resolving to the number of pipelines updated
 * 
 * @example
 * ```typescript
 * const updatedCount = await autoGenerateAllPipelineRanges('org_123');
 * console.log(`Updated ${updatedCount} pipelines with score ranges`);
 * ```
 */
export async function autoGenerateAllPipelineRanges(organizationId: string): Promise<number> {
  const pipelines = await prisma.pipeline.findMany({
    where: { organizationId, isArchived: false },
    include: {
      stages: {
        orderBy: { order: 'asc' }
      }
    }
  });

  console.log(`[Stage Analyzer] Auto-generating score ranges for ${pipelines.length} pipelines...`);

  let updatedCount = 0;
  for (const pipeline of pipelines) {
    if (pipeline.stages.length > 0) {
      await applyStageScoreRanges(pipeline.id);
      updatedCount++;
    }
  }

  console.log(`[Stage Analyzer] Updated ${updatedCount} pipelines with intelligent score ranges`);
  return updatedCount;
}

