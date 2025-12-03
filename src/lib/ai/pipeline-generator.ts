/**
 * AI Pipeline Generator
 * Analyzes contacts to suggest optimal pipeline structure
 * Can create detailed pipelines based on contact behavior and stages
 */

import { prisma } from '@/lib/db';
import type { Prisma } from '@prisma/client';
import OpenAI from 'openai';
import apiKeyManager from './api-key-manager';

// Chunk 1.1: PipelineGenerationLogic Type
export type PipelineGenerationLogic = 
  | 'HYBRID' 
  | 'CONSERVATIVE' 
  | 'BALANCED' 
  | 'DETAILED' 
  | 'ADAPTIVE' 
  | 'BUSINESS_FOCUSED' 
  | 'CUSTOM';

// Chunk 1.2: BusinessContext Interface
interface BusinessContext {
  businessType: 'E_COMMERCE' | 'B2B_SALES' | 'SERVICE_BASED' | 'LEAD_GENERATION' | 'SUBSCRIPTION' | 'MIXED' | 'UNKNOWN';
  salesCycleLength: 'SHORT' | 'MEDIUM' | 'LONG' | 'VARIABLE';
  conversionPattern: 'IMMEDIATE' | 'GRADUAL' | 'NEGOTIATION' | 'MIXED';
  contactVolume: 'LOW' | 'MEDIUM' | 'HIGH';
  engagementStyle: 'HIGH_TOUCH' | 'AUTOMATED' | 'MIXED';
  industryIndicators: string[];
  requiredStages: string[];
  optionalStages: string[];
  confidence: number;
}

// Chunk 1.3: GenerationOptions Interface
interface GenerationOptions {
  logic?: PipelineGenerationLogic;
  requestedStageCount?: number;
  minContactsPerStage?: number;
  enableAutoGeneration?: boolean;
  enableBusinessIntelligence?: boolean;
  detailLevel?: number;
  allowAIStageDecision?: boolean;
  customInstructions?: string;
}

interface ContactAnalysis {
  contactId: string;
  buyerIntent: string;
  sentiment: string;
  leadScore: number;
  messageCount: number;
  productInterests: string[];
  conversionProbability: number;
  intentSignals?: {
    rapidReplies?: boolean;
    multipleQuestions?: boolean;
    offHoursResponse?: boolean;
    askingForProof?: boolean;
    responseTimeMinutes?: number;
  };
  nextBestAction?: string;
  avgMessageLength?: number;
  engagementLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
}

interface SuggestedStage {
  name: string;
  description: string;
  color: string;
  type: 'LEAD' | 'IN_PROGRESS' | 'WON' | 'LOST' | 'ARCHIVED';
  leadScoreMin: number;
  leadScoreMax: number;
  expectedContacts: number;
  characteristics: string[];
}

interface PipelineSuggestion {
  name: string;
  description: string;
  stages: SuggestedStage[];
  totalContacts: number;
  confidence: number;
}

interface ScoreRange {
  min: number;
  max: number;
}

// ============================================================================
// Chunk 3: Helper Functions for Business Analysis
// ============================================================================

// Chunk 3.1: Conversion Time Analysis
function calculateAverageConversionTime(analyses: ContactAnalysis[]): number {
  // Estimate based on message count and conversion probability
  // This is a heuristic - you may want to use actual timestamps if available
  const avgMessages = analyses.reduce((sum, a) => sum + a.messageCount, 0) / analyses.length;
  return avgMessages * 0.5; // Rough estimate: 0.5 days per message
}

// Chunk 3.2: Conversion Pattern Detection
function analyzeGradualConversion(conversionProbs: number[]): boolean {
  // Check if conversion probabilities show gradual increase pattern
  if (conversionProbs.length < 2) return false;
  
  const sorted = [...conversionProbs].sort((a, b) => a - b);
  const increases = sorted.slice(1).map((val, i) => val - sorted[i]);
  const avgIncrease = increases.reduce((a, b) => a + b, 0) / increases.length;
  return avgIncrease > 5; // Gradual if average increase > 5%
}

// Chunk 3.3: Data Profile Analysis
function analyzeDataProfile(analyses: ContactAnalysis[]): {
  diversity: number;
  distribution: { mean: number; stdDev: number; min: number; max: number };
  volume: number;
  engagement: number;
} {
  return {
    diversity: calculateDataDiversity(analyses),
    distribution: analyzeScoreDistribution(analyses),
    volume: analyses.length,
    engagement: calculateAverageEngagement(analyses)
  };
}

// Chunk 3.4: Engagement Metrics
function calculateAverageEngagement(analyses: ContactAnalysis[]): number {
  const levels = { LOW: 1, MEDIUM: 2, HIGH: 3, VERY_HIGH: 4 };
  const avg = analyses.reduce((sum, a) => sum + (levels[a.engagementLevel || 'LOW'] || 1), 0) / analyses.length;
  return avg;
}

// Chunk 3.5: Differentiation and Diversity
function calculateDifferentiation(contacts: ContactAnalysis[]): number {
  if (contacts.length === 0) return 0;
  
  const uniqueIntents = new Set(contacts.map(c => c.buyerIntent)).size;
  const uniqueSentiments = new Set(contacts.map(c => c.sentiment)).size;
  const uniqueProducts = new Set(contacts.flatMap(c => c.productInterests || [])).size;
  const scoreVariance = calculateVariance(contacts.map(c => c.leadScore));
  
  // Normalize to 0-1 scale
  const intentDiversity = uniqueIntents / Math.max(contacts.length, 5);
  const sentimentDiversity = uniqueSentiments / Math.max(contacts.length, 3);
  const productDiversity = Math.min(uniqueProducts / 5, 1);
  const scoreDiversity = Math.min(scoreVariance / 1000, 1);
  
  return (intentDiversity + sentimentDiversity + productDiversity + scoreDiversity) / 4;
}

function calculateDataDiversity(analyses: ContactAnalysis[]): number {
  return calculateDifferentiation(analyses);
}

function calculateVariance(values: number[]): number {
  if (values.length === 0) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
  return squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
}

// Chunk 3.6: Score Distribution Analysis
function analyzeScoreDistribution(analyses: ContactAnalysis[]): {
  mean: number;
  stdDev: number;
  min: number;
  max: number;
} {
  const scores = analyses.map(a => a.leadScore);
  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  const variance = calculateVariance(scores);
  const stdDev = Math.sqrt(variance);
  
  return {
    mean,
    stdDev,
    min: Math.min(...scores),
    max: Math.max(...scores)
  };
}

// ============================================================================
// Chunk 2: Business Intelligence Analysis Functions
// ============================================================================

// Chunk 2.2: Business Type Detection
function determineBusinessType(
  intents: string[],
  productInterests: string[],
  conversionProbs: number[],
  messageCounts: number[]
): BusinessContext['businessType'] {
  // E-commerce indicators
  const immediatePurchaseSignals = intents.filter(i => 
    i === 'READY_TO_BUY' || i === 'PRICE_INQUIRY'
  ).length;
  const avgMessageCount = messageCounts.reduce((a, b) => a + b, 0) / messageCounts.length;
  const highConversionRate = conversionProbs.filter(p => p > 70).length / conversionProbs.length;
  
  if (immediatePurchaseSignals > intents.length * 0.4 && avgMessageCount < 5 && highConversionRate > 0.3) {
    return 'E_COMMERCE';
  }
  
  // B2B indicators
  const negotiationSignals = intents.filter(i => 
    i === 'ASKING_INFO' || i === 'PRICE_INQUIRY'
  ).length;
  const longConversations = messageCounts.filter(m => m > 10).length;
  
  if (longConversations > messageCounts.length * 0.3 && negotiationSignals > intents.length * 0.5) {
    return 'B2B_SALES';
  }
  
  // Service-based indicators
  const serviceKeywords = ['service', 'consultation', 'support', 'help', 'assistance'];
  const hasServiceKeywords = productInterests.some(p => 
    serviceKeywords.some(k => p.toLowerCase().includes(k))
  );
  const mediumMessageCount = avgMessageCount >= 5 && avgMessageCount <= 15;
  
  if (hasServiceKeywords && mediumMessageCount) {
    return 'SERVICE_BASED';
  }
  
  // Subscription indicators
  const recurringSignals = intents.filter(i => i === 'ASKING_INFO').length;
  const subscriptionKeywords = ['subscription', 'monthly', 'recurring', 'plan'];
  const hasSubscriptionKeywords = productInterests.some(p => 
    subscriptionKeywords.some(k => p.toLowerCase().includes(k))
  );
  
  if (hasSubscriptionKeywords && recurringSignals > intents.length * 0.3) {
    return 'SUBSCRIPTION';
  }
  
  // Lead generation indicators
  const lowConversionRate = conversionProbs.filter(p => p < 30).length / conversionProbs.length;
  const highLeadVolume = intents.length > 100;
  
  if (lowConversionRate > 0.5 && highLeadVolume) {
    return 'LEAD_GENERATION';
  }
  
  // Mixed or unknown
  if (immediatePurchaseSignals > 0 && longConversations > 0) {
    return 'MIXED';
  }
  
  return 'UNKNOWN';
}

// Chunk 2.3: Sales Cycle Analysis
function determineSalesCycleLength(
  messageCounts: number[],
  conversionProbs: number[],
  analyses: ContactAnalysis[]
): BusinessContext['salesCycleLength'] {
  const avgMessageCount = messageCounts.reduce((a, b) => a + b, 0) / messageCounts.length;
  const avgConversionTime = calculateAverageConversionTime(analyses);
  
  if (avgMessageCount < 3 && avgConversionTime < 1) {
    return 'SHORT'; // < 1 day
  } else if (avgMessageCount < 8 && avgConversionTime < 7) {
    return 'MEDIUM'; // 1-7 days
  } else if (avgMessageCount >= 8 || avgConversionTime >= 7) {
    return 'LONG'; // > 7 days
  }
  
  return 'VARIABLE';
}

// Chunk 2.4: Conversion Pattern Analysis
function determineConversionPattern(
  conversionProbs: number[],
  intents: string[]
): BusinessContext['conversionPattern'] {
  const highImmediate = conversionProbs.filter(p => p > 80).length;
  const gradualIncrease = analyzeGradualConversion(conversionProbs);
  const negotiationSignals = intents.filter(i => 
    i === 'PRICE_INQUIRY' || i === 'ASKING_INFO'
  ).length;
  
  if (highImmediate > conversionProbs.length * 0.4) {
    return 'IMMEDIATE';
  } else if (gradualIncrease && negotiationSignals > intents.length * 0.3) {
    return 'NEGOTIATION';
  } else if (gradualIncrease) {
    return 'GRADUAL';
  }
  
  return 'MIXED';
}

// Chunk 2.5: Contact Volume and Engagement Analysis
function determineContactVolume(contactCount: number): BusinessContext['contactVolume'] {
  if (contactCount < 50) return 'LOW';
  if (contactCount < 200) return 'MEDIUM';
  return 'HIGH';
}

function determineEngagementStyle(
  messageCounts: number[],
  engagementLevels: string[]
): BusinessContext['engagementStyle'] {
  const avgMessages = messageCounts.reduce((a, b) => a + b, 0) / messageCounts.length;
  const highEngagement = engagementLevels.filter(e => e === 'HIGH' || e === 'VERY_HIGH').length;
  
  if (avgMessages > 10 && highEngagement > engagementLevels.length * 0.4) {
    return 'HIGH_TOUCH';
  } else if (avgMessages < 5 && highEngagement < engagementLevels.length * 0.2) {
    return 'AUTOMATED';
  }
  
  return 'MIXED';
}

// Chunk 2.6: Industry and Stage Requirements
function extractIndustryIndicators(
  productInterests: string[]
): string[] {
  const indicators: string[] = [];
  const uniqueProductsSet = new Set(productInterests);
  const uniqueProducts = Array.from(uniqueProductsSet);
  
  // Common industry keywords
  const industryKeywords: Record<string, string[]> = {
    'Retail': ['product', 'item', 'buy', 'purchase'],
    'Technology': ['software', 'app', 'system', 'platform'],
    'Healthcare': ['health', 'medical', 'treatment', 'doctor'],
    'Real Estate': ['property', 'house', 'apartment', 'rent'],
    'Education': ['course', 'training', 'learn', 'education'],
    'Finance': ['loan', 'credit', 'investment', 'financial']
  };
  
  for (const [industry, keywords] of Object.entries(industryKeywords)) {
    if (uniqueProducts.some(p => keywords.some(k => p.toLowerCase().includes(k)))) {
      indicators.push(industry);
    }
  }
  
  return indicators;
}

function determineRequiredStages(
  businessType: BusinessContext['businessType'],
  salesCycleLength: BusinessContext['salesCycleLength'],
  conversionPattern: BusinessContext['conversionPattern'],
  engagementStyle: BusinessContext['engagementStyle']
): { requiredStages: string[]; optionalStages: string[] } {
  const required: string[] = [];
  const optional: string[] = [];
  
  // Base stages (always required)
  required.push('New Lead', 'Qualified', 'Closed Won');
  
  // Business-type specific stages
  switch (businessType) {
    case 'E_COMMERCE':
      required.push('Cart Abandonment', 'Payment Processing');
      optional.push('Product Inquiry', 'Shipping Confirmation');
      break;
    
    case 'B2B_SALES':
      required.push('Discovery Call', 'Proposal Sent', 'Negotiation');
      optional.push('Demo Scheduled', 'Contract Review', 'Onboarding');
      break;
    
    case 'SERVICE_BASED':
      required.push('Consultation', 'Service Delivery');
      optional.push('Follow-up', 'Referral');
      break;
    
    case 'SUBSCRIPTION':
      required.push('Trial', 'Active Subscription');
      optional.push('Upgrade', 'Renewal');
      break;
    
    case 'LEAD_GENERATION':
      required.push('Nurturing', 'Qualified');
      optional.push('Re-engagement', 'Conversion');
      break;
  }
  
  // Sales cycle specific stages
  if (salesCycleLength === 'LONG') {
    required.push('Nurturing', 'Follow-up');
    optional.push('Re-engagement', 'Long-term Nurture');
  } else if (salesCycleLength === 'SHORT') {
    optional.push('Quick Win', 'Immediate Follow-up');
  }
  
  // Conversion pattern specific stages
  if (conversionPattern === 'NEGOTIATION') {
    required.push('Negotiation', 'Proposal Review');
  } else if (conversionPattern === 'GRADUAL') {
    required.push('Nurturing', 'Progressive Engagement');
  }
  
  // Engagement style specific stages
  if (engagementStyle === 'HIGH_TOUCH') {
    required.push('Personal Outreach', 'Relationship Building');
    optional.push('VIP Treatment', 'Custom Solution');
  } else if (engagementStyle === 'AUTOMATED') {
    optional.push('Automated Nurture', 'Self-Service');
  }
  
  return { requiredStages: required, optionalStages: optional };
}

// Chunk 2.7: Confidence Calculation
function calculateBusinessContextConfidence(
  businessType: BusinessContext['businessType'],
  salesCycleLength: BusinessContext['salesCycleLength'],
  conversionPattern: BusinessContext['conversionPattern'],
  contactCount: number
): number {
  let confidence = 50; // Base confidence
  
  if (businessType !== 'UNKNOWN') confidence += 20;
  if (salesCycleLength !== 'VARIABLE') confidence += 10;
  if (conversionPattern !== 'MIXED') confidence += 10;
  if (contactCount >= 50) confidence += 10;
  
  return Math.min(95, confidence);
}

// Chunk 2.1: Main Business Context Analysis
async function analyzeBusinessContext(
  analyses: ContactAnalysis[],
  _organizationId: string,
  _facebookPageId?: string
): Promise<BusinessContext> {
  // Analyze patterns to determine business type
  const intents = analyses.map(a => a.buyerIntent);
  const productInterests = analyses.flatMap(a => a.productInterests || []);
  const conversionProbs = analyses.map(a => a.conversionProbability);
  const engagementLevels = analyses.map(a => a.engagementLevel || 'LOW');
  const messageCounts = analyses.map(a => a.messageCount);
  
  // Determine business type
  const businessType = determineBusinessType(intents, productInterests, conversionProbs, messageCounts);
  
  // Determine sales cycle length
  const salesCycleLength = determineSalesCycleLength(messageCounts, conversionProbs, analyses);
  
  // Determine conversion pattern
  const conversionPattern = determineConversionPattern(conversionProbs, intents);
  
  // Determine contact volume
  const contactVolume = determineContactVolume(analyses.length);
  
  // Determine engagement style
  const engagementStyle = determineEngagementStyle(messageCounts, engagementLevels);
  
  // Extract industry indicators
  const industryIndicators = extractIndustryIndicators(productInterests);
  
  // AI determines required and optional stages based on business needs
  const { requiredStages, optionalStages } = determineRequiredStages(
    businessType,
    salesCycleLength,
    conversionPattern,
    engagementStyle
  );
  
  // Calculate confidence
  const confidence = calculateBusinessContextConfidence(
    businessType,
    salesCycleLength,
    conversionPattern,
    analyses.length
  );
  
  return {
    businessType,
    salesCycleLength,
    conversionPattern,
    contactVolume,
    engagementStyle,
    industryIndicators,
    requiredStages,
    optionalStages,
    confidence
  };
}

// ============================================================================
// Chunk 4: Individual Logic Strategy Functions
// ============================================================================

// Helper function to create stage from range
function createStageFromRange(
  range: ScoreRange,
  contactsInRange: ContactAnalysis[],
  index: number,
  totalStages: number,
  usedNames: Set<string>
): SuggestedStage | null {
  if (contactsInRange.length === 0) return null;

  // Extract data from contacts
  const intents = contactsInRange.map(a => a.buyerIntent);
  const sentiments = contactsInRange.map(a => a.sentiment);
  const productInterests = contactsInRange.flatMap(a => a.productInterests || []);
  const avgConversion = contactsInRange.length > 0
    ? contactsInRange.reduce((sum, a) => sum + a.conversionProbability, 0) / contactsInRange.length
    : 0;

  // Determine stage type
  let stageType: SuggestedStage['type'] = 'IN_PROGRESS';
  if (range.max >= 80) {
    stageType = 'WON';
  } else if (range.min < 20) {
    stageType = 'LEAD';
  }

  // Generate stage name
  const stageName = generateUniqueStageName(
    range,
    intents,
    sentiments,
    productInterests,
    avgConversion,
    index,
    totalStages,
    contactsInRange,
    usedNames
  );

  usedNames.add(stageName);

  return {
    name: stageName,
    description: generateStageDescription(range, intents, sentiments, avgConversion, productInterests),
    color: getStageColor(index, totalStages, stageType),
    type: stageType,
    leadScoreMin: range.min,
    leadScoreMax: range.max,
    expectedContacts: contactsInRange.length,
    characteristics: getStageCharacteristics(intents, sentiments, contactsInRange, productInterests)
  };
}

function generateFallbackStages(analyses: ContactAnalysis[], count: number): SuggestedStage[] {
  const ranges = calculateOptimalScoreRanges(analyses, count);
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();

  for (let i = 0; i < ranges.length; i++) {
    const range = ranges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    const stage = createStageFromRange(range, contactsInRange, i, ranges.length, usedNames);
    if (stage) {
      stages.push(stage);
    }
  }

  return stages;
}

function calculateQuantileRanges(analyses: ContactAnalysis[], stageCount: number): ScoreRange[] {
  const ranges: ScoreRange[] = [];
  const step = 100 / stageCount;

  for (let i = 0; i < stageCount; i++) {
    const min = Math.round(i * step);
    const max = i === stageCount - 1 ? 100 : Math.round((i + 1) * step) - 1;
    ranges.push({ min, max });
  }

  return ranges;
}

function calculateGranularRanges(analyses: ContactAnalysis[], stageCount: number): ScoreRange[] {
  return calculateQuantileRanges(analyses, stageCount);
}

function calculateEqualRanges(analyses: ContactAnalysis[], stageCount: number): ScoreRange[] {
  return calculateQuantileRanges(analyses, stageCount);
}

function calculateAdaptiveRanges(
  analyses: ContactAnalysis[],
  stageCount: number
): ScoreRange[] {
  // Use quantile-based ranges, but adjust based on distribution
  return calculateQuantileRanges(analyses, stageCount);
}

// Chunk 4.1: Conservative Strategy
function generateConservativeStages(
  analyses: ContactAnalysis[],
  options: { requestedStageCount?: number; minContactsPerStage: number; detailLevel: number }
): SuggestedStage[] {
  const { requestedStageCount, minContactsPerStage } = options;
  
  // Determine stage count: 3-8 stages
  let stageCount = requestedStageCount || 4;
  stageCount = Math.max(3, Math.min(8, stageCount));
  
  // Use quantile-based ranges for clear separation
  const scoreRanges = calculateQuantileRanges(analyses, stageCount);
  
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < scoreRanges.length; i++) {
    const range = scoreRanges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    // Skip stage if not enough contacts (conservative approach)
    if (contactsInRange.length < minContactsPerStage) {
      continue;
    }
    
    // Only create stage if there's meaningful differentiation
    const differentiation = calculateDifferentiation(contactsInRange);
    if (differentiation < 0.3) { // Low differentiation threshold
      continue;
    }
    
    const stage = createStageFromRange(
      range,
      contactsInRange,
      i,
      scoreRanges.length,
      usedNames
    );
    
    if (stage) {
      stages.push(stage);
    }
  }
  
  // Ensure minimum 3 stages
  if (stages.length < 3) {
    return generateFallbackStages(analyses, 3);
  }
  
  return stages;
}

// Chunk 4.2: Balanced Strategy
function generateBalancedStages(
  analyses: ContactAnalysis[],
  options: { requestedStageCount?: number; minContactsPerStage: number; detailLevel: number }
): SuggestedStage[] {
  const { requestedStageCount, minContactsPerStage, detailLevel } = options;
  
  // Determine stage count: 4-12 stages based on data diversity
  let stageCount = requestedStageCount;
  if (!stageCount) {
    const diversity = calculateDataDiversity(analyses);
    stageCount = Math.floor(4 + (diversity * 8)); // 4-12 range
    stageCount = Math.max(4, Math.min(12, stageCount));
  }
  
  // Apply detail level adjustment
  const adjustedCount = Math.round(stageCount * (0.8 + (detailLevel / 50))); // 0.8x to 1.0x
  stageCount = Math.max(4, Math.min(12, adjustedCount));
  
  const scoreRanges = calculateOptimalScoreRanges(analyses, stageCount, detailLevel);
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < scoreRanges.length; i++) {
    const range = scoreRanges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    // More lenient: allow stages with fewer contacts
    if (contactsInRange.length < Math.max(1, minContactsPerStage - 1)) {
      continue;
    }
    
    // Moderate differentiation threshold
    const differentiation = calculateDifferentiation(contactsInRange);
    if (differentiation < 0.2) {
      continue;
    }
    
    const stage = createStageFromRange(
      range,
      contactsInRange,
      i,
      scoreRanges.length,
      usedNames
    );
    
    if (stage) {
      stages.push(stage);
    }
  }
  
  return stages.length >= 3 ? stages : generateFallbackStages(analyses, 4);
}

// Chunk 4.3: Detailed Strategy
function generateDetailedStages(
  analyses: ContactAnalysis[],
  options: { requestedStageCount?: number; minContactsPerStage: number; detailLevel: number }
): SuggestedStage[] {
  const { requestedStageCount, minContactsPerStage, detailLevel } = options;
  
  // Determine stage count: 6-15 stages
  let stageCount = requestedStageCount;
  if (!stageCount) {
    const diversity = calculateDataDiversity(analyses);
    const scoreRange = Math.max(...analyses.map(a => a.leadScore)) - 
                      Math.min(...analyses.map(a => a.leadScore));
    
    stageCount = Math.floor(6 + (diversity * 6) + (scoreRange / 20));
    stageCount = Math.max(6, Math.min(15, stageCount));
  }
  
  // Apply detail level: 1.0x to 1.5x multiplier
  const adjustedCount = Math.round(stageCount * (1.0 + (detailLevel / 20)));
  stageCount = Math.max(6, Math.min(20, adjustedCount));
  
  // Use smaller score ranges for granularity
  const scoreRanges = calculateGranularRanges(analyses, stageCount);
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < scoreRanges.length; i++) {
    const range = scoreRanges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    // Very lenient: allow stages with 1+ contacts
    if (contactsInRange.length < 1) {
      continue;
    }
    
    // Lower differentiation threshold for more stages
    const differentiation = calculateDifferentiation(contactsInRange);
    if (differentiation < 0.15) {
      // Still create stage but mark as low differentiation
      const stage = createStageFromRange(
        range,
        contactsInRange,
        i,
        scoreRanges.length,
        usedNames
      );
      
      if (stage) {
        stages.push(stage);
      }
    } else {
      const stage = createStageFromRange(
        range,
        contactsInRange,
        i,
        scoreRanges.length,
        usedNames
      );
      
      if (stage) {
        stages.push(stage);
      }
    }
  }
  
  return stages.length >= 3 ? stages : generateFallbackStages(analyses, 6);
}

// Chunk 4.4: Adaptive Strategy
function generateAdaptiveStages(
  analyses: ContactAnalysis[],
  options: { requestedStageCount?: number; minContactsPerStage: number; detailLevel: number }
): SuggestedStage[] {
  const { requestedStageCount, minContactsPerStage, detailLevel } = options;
  
  // Analyze data characteristics
  const diversity = calculateDataDiversity(analyses);
  const scoreDistribution = analyzeScoreDistribution(analyses);
  const intentVariety = new Set(analyses.map(a => a.buyerIntent)).size;
  const sentimentVariety = new Set(analyses.map(a => a.sentiment)).size;
  
  // Determine optimal stage count
  let stageCount = requestedStageCount;
  if (!stageCount) {
    // Base count on multiple factors
    let baseCount = 4;
    
    // Increase for diverse data
    if (diversity > 0.7) baseCount += 3;
    else if (diversity > 0.5) baseCount += 2;
    else if (diversity > 0.3) baseCount += 1;
    
    // Increase for varied intents/sentiments
    if (intentVariety >= 4) baseCount += 2;
    else if (intentVariety >= 3) baseCount += 1;
    
    if (sentimentVariety >= 3) baseCount += 1;
    
    // Increase for wide score distribution
    if (scoreDistribution.stdDev > 25) baseCount += 2;
    else if (scoreDistribution.stdDev > 15) baseCount += 1;
    
    // Apply detail level
    baseCount = Math.round(baseCount * (0.9 + (detailLevel / 50)));
    
    stageCount = Math.max(3, Math.min(20, baseCount));
  }
  
  // Use adaptive range calculation
  const scoreRanges = calculateAdaptiveRanges(analyses, stageCount);
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < scoreRanges.length; i++) {
    const range = scoreRanges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    // Adaptive threshold based on total contacts
    const adaptiveMinContacts = Math.max(1, Math.floor(minContactsPerStage * (analyses.length / 100)));
    if (contactsInRange.length < adaptiveMinContacts) {
      continue;
    }
    
    // Adaptive differentiation threshold
    const adaptiveThreshold = 0.1 + (diversity * 0.2); // 0.1 to 0.3
    const differentiation = calculateDifferentiation(contactsInRange);
    
    if (differentiation >= adaptiveThreshold || contactsInRange.length >= 5) {
      const stage = createStageFromRange(
        range,
        contactsInRange,
        i,
        scoreRanges.length,
        usedNames
      );
      
      if (stage) {
        stages.push(stage);
      }
    }
  }
  
  return stages.length >= 3 ? stages : generateFallbackStages(analyses, 4);
}

// Chunk 4.5: Business-Focused Strategy
function generateBusinessFocusedStages(
  analyses: ContactAnalysis[],
  options: { requestedStageCount?: number; minContactsPerStage: number; detailLevel: number }
): SuggestedStage[] {
  const { requestedStageCount, minContactsPerStage } = options;
  
  // Define standard funnel stages
  const funnelStages = [
    { name: 'Awareness', scoreRange: [0, 20], type: 'LEAD' as const },
    { name: 'Interest', scoreRange: [21, 40], type: 'IN_PROGRESS' as const },
    { name: 'Consideration', scoreRange: [41, 60], type: 'IN_PROGRESS' as const },
    { name: 'Intent', scoreRange: [61, 80], type: 'IN_PROGRESS' as const },
    { name: 'Purchase', scoreRange: [81, 100], type: 'WON' as const },
  ];
  
  // Allow customization: 5-10 stages
  let stageCount = requestedStageCount || 5;
  stageCount = Math.max(5, Math.min(10, stageCount));
  
  // Create score ranges based on funnel
  const scoreRanges: ScoreRange[] = [];
  const step = 100 / stageCount;
  
  for (let i = 0; i < stageCount; i++) {
    const min = Math.round(i * step);
    const max = i === stageCount - 1 ? 100 : Math.round((i + 1) * step) - 1;
    scoreRanges.push({ min, max });
  }
  
  // Map to business funnel stages
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < scoreRanges.length; i++) {
    const range = scoreRanges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    if (contactsInRange.length < minContactsPerStage) {
      continue;
    }
    
    // Find matching funnel stage
    const funnelStage = funnelStages.find(fs => 
      range.min >= fs.scoreRange[0] && range.max <= fs.scoreRange[1]
    ) || funnelStages[Math.floor((i / scoreRanges.length) * funnelStages.length)];
    
    // Generate business-focused stage name
    let stageName = funnelStage.name;
    if (usedNames.has(stageName)) {
      stageName = `${stageName} ${i + 1}`;
    }
    usedNames.add(stageName);
    
    const intents = contactsInRange.map(a => a.buyerIntent);
    const sentiments = contactsInRange.map(a => a.sentiment);
    const productInterests = contactsInRange.flatMap(a => a.productInterests || []);
    const avgConversion = contactsInRange.length > 0
      ? contactsInRange.reduce((sum, a) => sum + a.conversionProbability, 0) / contactsInRange.length
      : 0;

    const stage: SuggestedStage = {
      name: stageName,
      description: `Business funnel stage: ${funnelStage.name} (scores ${range.min}-${range.max})`,
      color: getStageColor(i, scoreRanges.length, funnelStage.type),
      type: funnelStage.type,
      leadScoreMin: range.min,
      leadScoreMax: range.max,
      expectedContacts: contactsInRange.length,
      characteristics: getStageCharacteristics(intents, sentiments, contactsInRange, productInterests)
    };
    
    stages.push(stage);
  }
  
  return stages.length >= 3 ? stages : generateFallbackStages(analyses, 5);
}

// Chunk 4.6: Custom Strategy
function generateCustomStages(
  analyses: ContactAnalysis[],
  options: { requestedStageCount?: number; minContactsPerStage: number; detailLevel: number }
): SuggestedStage[] {
  const { requestedStageCount = 5, minContactsPerStage } = options;
  
  // User-specified count: 3-30 stages
  const stageCount = Math.max(3, Math.min(30, requestedStageCount));
  
  // Equal distribution across score range
  const scoreRanges = calculateEqualRanges(analyses, stageCount);
  const stages: SuggestedStage[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < scoreRanges.length; i++) {
    const range = scoreRanges[i];
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= range.min && a.leadScore <= range.max
    );
    
    // Still respect minimum contacts per stage
    if (contactsInRange.length < minContactsPerStage && contactsInRange.length > 0) {
      // Allow but mark as sparse
      const stage = createStageFromRange(
        range,
        contactsInRange,
        i,
        scoreRanges.length,
        usedNames
      );
      
      if (stage) {
        stage.description += ' (Sparse - consider merging with adjacent stage)';
        stages.push(stage);
      }
    } else if (contactsInRange.length >= minContactsPerStage) {
      const stage = createStageFromRange(
        range,
        contactsInRange,
        i,
        scoreRanges.length,
        usedNames
      );
      
      if (stage) {
        stages.push(stage);
      }
    }
  }
  
  return stages.length >= 3 ? stages : generateFallbackStages(analyses, stageCount);
}

// Chunk 4.7: Strategy Router
async function generateStagesWithLogic(
  analyses: ContactAnalysis[],
  logic: PipelineGenerationLogic,
  options: {
    requestedStageCount?: number;
    minContactsPerStage: number;
    detailLevel: number;
  }
): Promise<SuggestedStage[]> {
  switch (logic) {
    case 'CONSERVATIVE':
      return generateConservativeStages(analyses, options);
    
    case 'BALANCED':
      return generateBalancedStages(analyses, options);
    
    case 'DETAILED':
      return generateDetailedStages(analyses, options);
    
    case 'ADAPTIVE':
      return generateAdaptiveStages(analyses, options);
    
    case 'BUSINESS_FOCUSED':
      return generateBusinessFocusedStages(analyses, options);
    
    case 'CUSTOM':
      return generateCustomStages(analyses, options);
    
    default:
      return generateAdaptiveStages(analyses, options);
  }
}

// ============================================================================
// Chunk 5: Hybrid Logic Implementation
// ============================================================================

// Chunk 5.1: Determine Strategy Weights
function determineStrategyWeights(
  dataProfile: ReturnType<typeof analyzeDataProfile>,
  businessContext: BusinessContext | null,
  detailLevel: number
): {
  conservative: number;
  balanced: number;
  detailed: number;
  businessFocused: number;
  adaptive: number;
} {
  const baseWeights = {
    conservative: 0.2,
    balanced: 0.3,
    detailed: 0.2,
    businessFocused: 0.2,
    adaptive: 0.1
  };
  
  // Adjust based on business context
  if (businessContext) {
    if (businessContext.businessType === 'E_COMMERCE' || businessContext.businessType === 'LEAD_GENERATION') {
      baseWeights.businessFocused += 0.2;
      baseWeights.conservative += 0.1;
    } else if (businessContext.businessType === 'B2B_SALES') {
      baseWeights.businessFocused += 0.3;
      baseWeights.detailed += 0.1;
    } else if (businessContext.businessType === 'SERVICE_BASED') {
      baseWeights.balanced += 0.2;
      baseWeights.adaptive += 0.1;
    }
    
    if (businessContext.salesCycleLength === 'LONG') {
      baseWeights.detailed += 0.2;
      baseWeights.businessFocused += 0.1;
    } else if (businessContext.salesCycleLength === 'SHORT') {
      baseWeights.conservative += 0.2;
      baseWeights.balanced += 0.1;
    }
  }
  
  // Adjust based on detail level
  if (detailLevel >= 7) {
    baseWeights.detailed += 0.2;
    baseWeights.adaptive += 0.1;
  } else if (detailLevel <= 3) {
    baseWeights.conservative += 0.2;
    baseWeights.balanced -= 0.1;
  }
  
  // Normalize weights
  const total = Object.values(baseWeights).reduce((a, b) => a + b, 0);
  const normalizedWeights = {
    conservative: baseWeights.conservative / total,
    balanced: baseWeights.balanced / total,
    detailed: baseWeights.detailed / total,
    businessFocused: baseWeights.businessFocused / total,
    adaptive: baseWeights.adaptive / total
  };
  
  return normalizedWeights;
}

// Chunk 5.2: Merge Strategy Stages
function mergeStrategyStages(
  strategyResults: Array<{ strategy: string; stages: SuggestedStage[]; score: number }>
): SuggestedStage[] {
  // Collect all stages with their strategy scores
  const stageMap = new Map<string, {
    stage: SuggestedStage;
    strategies: string[];
    totalScore: number;
    count: number;
  }>();
  
  for (const result of strategyResults) {
    for (const stage of result.stages) {
      const key = `${stage.leadScoreMin}-${stage.leadScoreMax}`;
      const existing = stageMap.get(key);
      
      if (existing) {
        existing.strategies.push(result.strategy);
        existing.totalScore += result.score;
        existing.count += 1;
      } else {
        stageMap.set(key, {
          stage,
          strategies: [result.strategy],
          totalScore: result.score,
          count: 1
        });
      }
    }
  }
  
  // Convert to array and sort by score
  const merged = Array.from(stageMap.values())
    .sort((a, b) => b.totalScore - a.totalScore)
    .map(item => {
      // Enhance stage name if multiple strategies agree
      if (item.count > 1) {
        item.stage.description += ` (Validated by ${item.count} strategies)`;
      }
      return item.stage;
    });
  
  return merged;
}

// Chunk 5.3: Optimize Stage Distribution
function optimizeStageDistribution(
  stages: SuggestedStage[],
  analyses: ContactAnalysis[],
  minContactsPerStage: number,
  requestedStageCount?: number
): SuggestedStage[] {
  // Sort by score ranges
  const sorted = [...stages].sort((a, b) => a.leadScoreMin - b.leadScoreMin);
  
  // Remove stages with too few contacts (unless required)
  const filtered = sorted.filter(stage => {
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= stage.leadScoreMin && a.leadScore <= stage.leadScoreMax
    );
    return contactsInRange.length >= minContactsPerStage || stage.type === 'WON';
  });
  
  // Ensure we have at least 3 stages
  if (filtered.length < 3 && sorted.length >= 3) {
    return sorted.slice(0, 3);
  }
  
  return filtered.length >= 3 ? filtered : sorted;
}

// Chunk 5.4: Find Score Range Gaps
function findScoreRangeGaps(stages: SuggestedStage[]): Array<{ min: number; max: number }> {
  const sorted = [...stages].sort((a, b) => a.leadScoreMin - b.leadScoreMin);
  const gaps: Array<{ min: number; max: number }> = [];
  
  for (let i = 0; i < sorted.length - 1; i++) {
    const currentMax = sorted[i].leadScoreMax;
    const nextMin = sorted[i + 1].leadScoreMin;
    
    if (nextMin - currentMax > 5) {
      gaps.push({ min: currentMax + 1, max: nextMin - 1 });
    }
  }
  
  return gaps;
}

// Chunk 5.5: Generate Hybrid Stages
async function generateHybridStages(
  analyses: ContactAnalysis[],
  businessContext: BusinessContext | null,
  options: {
    requestedStageCount?: number;
    minContactsPerStage: number;
    detailLevel: number;
    allowAIStageDecision: boolean;
  }
): Promise<SuggestedStage[]> {
  const { requestedStageCount, minContactsPerStage, detailLevel, allowAIStageDecision } = options;

  // Step 1: Analyze data characteristics
  const dataProfile = analyzeDataProfile(analyses);
  
  // Step 2: Determine which strategies to combine
  const strategyWeights = determineStrategyWeights(dataProfile, businessContext, detailLevel);
  
  // Step 3: Generate stages using each relevant strategy
  const strategyResults: Array<{ strategy: string; stages: SuggestedStage[]; score: number }> = [];
  
  if (strategyWeights.conservative > 0.2) {
    const stages = generateConservativeStages(analyses, { requestedStageCount, minContactsPerStage, detailLevel });
    strategyResults.push({ strategy: 'CONSERVATIVE', stages, score: strategyWeights.conservative });
  }
  
  if (strategyWeights.balanced > 0.2) {
    const stages = generateBalancedStages(analyses, { requestedStageCount, minContactsPerStage, detailLevel });
    strategyResults.push({ strategy: 'BALANCED', stages, score: strategyWeights.balanced });
  }
  
  if (strategyWeights.detailed > 0.2) {
    const stages = generateDetailedStages(analyses, { requestedStageCount, minContactsPerStage, detailLevel });
    strategyResults.push({ strategy: 'DETAILED', stages, score: strategyWeights.detailed });
  }
  
  if (strategyWeights.businessFocused > 0.2) {
    const stages = generateBusinessFocusedStages(analyses, { requestedStageCount, minContactsPerStage, detailLevel });
    strategyResults.push({ strategy: 'BUSINESS_FOCUSED', stages, score: strategyWeights.businessFocused });
  }
  
  if (strategyWeights.adaptive > 0.2) {
    const stages = generateAdaptiveStages(analyses, { requestedStageCount, minContactsPerStage, detailLevel });
    strategyResults.push({ strategy: 'ADAPTIVE', stages, score: strategyWeights.adaptive });
  }

  // Step 4: Merge and optimize stages from all strategies
  const mergedStages = mergeStrategyStages(strategyResults);
  
  // Step 5: Apply business intelligence requirements
  const businessOptimizedStages = allowAIStageDecision && businessContext
    ? applyBusinessStageRequirements(mergedStages, businessContext, analyses)
    : mergedStages;

  // Step 6: Final optimization
  return optimizeStageDistribution(businessOptimizedStages, analyses, minContactsPerStage, requestedStageCount);
}

// ============================================================================
// Chunk 6: Business Intelligence Filtering and Validation
// ============================================================================

// Chunk 6.1: Apply Business Intelligence Filtering
function applyBusinessIntelligenceFiltering(
  stages: SuggestedStage[],
  businessContext: BusinessContext,
  analyses: ContactAnalysis[],
  allowAIStageDecision: boolean
): SuggestedStage[] {
  if (!allowAIStageDecision) {
    return stages; // User override - don't filter
  }
  
  const filtered: SuggestedStage[] = [];
  const requiredStageNames = businessContext.requiredStages.map(s => s.toLowerCase());
  const optionalStageNames = businessContext.optionalStages.map(s => s.toLowerCase());
  
  for (const stage of stages) {
    const stageNameLower = stage.name.toLowerCase();
    
    // Always include required stages
    const isRequired = requiredStageNames.some(req => 
      stageNameLower.includes(req) || req.includes(stageNameLower.split(' ')[0])
    );
    
    if (isRequired) {
      filtered.push(stage);
      continue;
    }
    
    // Include optional stages if they have contacts
    const isOptional = optionalStageNames.some(opt => 
      stageNameLower.includes(opt) || opt.includes(stageNameLower.split(' ')[0])
    );
    
    if (isOptional) {
      const contactsInRange = analyses.filter(a => 
        a.leadScore >= stage.leadScoreMin && a.leadScore <= stage.leadScoreMax
      );
      
      // Include optional stage if it has meaningful contacts
      if (contactsInRange.length >= 2) {
        filtered.push(stage);
      }
    } else {
      // For other stages, check if they're necessary based on business needs
      const contactsInRange = analyses.filter(a => 
        a.leadScore >= stage.leadScoreMin && a.leadScore <= stage.leadScoreMax
      );
      
      // Include if it serves a clear purpose and has contacts
      if (contactsInRange.length >= 3 && stage.characteristics.length > 0) {
        filtered.push(stage);
      }
    }
  }
  
  // Ensure we have at least the required stages
  if (filtered.length < 3) {
    return stages; // Fallback to original if filtering too aggressive
  }
  
  return filtered;
}

// Chunk 6.2: Apply Business Stage Requirements
function applyBusinessStageRequirements(
  stages: SuggestedStage[],
  businessContext: BusinessContext,
  analyses: ContactAnalysis[]
): SuggestedStage[] {
  const result = [...stages];
  const existingStageNames = stages.map(s => s.name.toLowerCase());
  
  // Check for missing required stages
  for (const requiredStage of businessContext.requiredStages) {
    const exists = existingStageNames.some(name => 
      name.includes(requiredStage.toLowerCase()) || requiredStage.toLowerCase().includes(name.split(' ')[0])
    );
    
    if (!exists) {
      // Create the required stage
      const newStage = createBusinessRequiredStage(requiredStage, businessContext, analyses, stages);
      if (newStage) {
        result.push(newStage);
      }
    }
  }
  
  // Sort by score ranges
  return result.sort((a, b) => a.leadScoreMin - b.leadScoreMin);
}

// Chunk 6.3: Create Business Required Stage
function createBusinessRequiredStage(
  stageName: string,
  businessContext: BusinessContext,
  analyses: ContactAnalysis[],
  existingStages: SuggestedStage[]
): SuggestedStage | null {
  // Determine appropriate score range based on stage name and business context
  let scoreRange: { min: number; max: number };
  let stageType: SuggestedStage['type'] = 'IN_PROGRESS';
  
  if (stageName.toLowerCase().includes('new') || stageName.toLowerCase().includes('lead')) {
    scoreRange = { min: 0, max: 25 };
    stageType = 'LEAD';
  } else if (stageName.toLowerCase().includes('won') || stageName.toLowerCase().includes('closed')) {
    scoreRange = { min: 81, max: 100 };
    stageType = 'WON';
  } else if (stageName.toLowerCase().includes('qualified')) {
    scoreRange = { min: 41, max: 60 };
  } else if (stageName.toLowerCase().includes('negotiation') || stageName.toLowerCase().includes('proposal')) {
    scoreRange = { min: 61, max: 80 };
  } else {
    // Find a gap in existing stages
    const gaps = findScoreRangeGaps(existingStages);
    if (gaps.length > 0) {
      scoreRange = gaps[0];
    } else {
      scoreRange = { min: 26, max: 40 }; // Default mid-range
    }
  }
  
  const contactsInRange = analyses.filter(a => 
    a.leadScore >= scoreRange.min && a.leadScore <= scoreRange.max
  );
  
  const intents = contactsInRange.map(a => a.buyerIntent);
  const sentiments = contactsInRange.map(a => a.sentiment);
  const productInterests = contactsInRange.flatMap(a => a.productInterests || []);
  
  return {
    name: stageName,
    description: generateBusinessStageDescription(stageName, scoreRange, contactsInRange, businessContext),
    color: getBusinessStageColor(stageType, existingStages.length),
    type: stageType,
    leadScoreMin: scoreRange.min,
    leadScoreMax: scoreRange.max,
    expectedContacts: contactsInRange.length,
    characteristics: getBusinessStageCharacteristics(contactsInRange, stageName, businessContext)
  };
}

// Chunk 6.4: Validate Stages
function validateStages(
  stages: SuggestedStage[],
  analyses: ContactAnalysis[],
  minContactsPerStage: number
): SuggestedStage[] {
  return stages.filter((stage, index) => {
    // 1. Must have purpose (description and characteristics)
    if (!stage.description || stage.characteristics.length === 0) {
      return false;
    }
    
    // 2. Must have unique criteria (different from adjacent stages)
    if (index > 0) {
      const prevStage = stages[index - 1];
      const isDuplicate = 
        stage.leadScoreMin === prevStage.leadScoreMin &&
        stage.leadScoreMax === prevStage.leadScoreMax &&
        stage.characteristics.every(c => prevStage.characteristics.includes(c));
      
      if (isDuplicate) {
        return false; // Remove duplicate
      }
    }
    
    // 3. Must have minimum contacts (unless it's a required stage like "Won")
    const contactsInRange = analyses.filter(a => 
      a.leadScore >= stage.leadScoreMin && a.leadScore <= stage.leadScoreMax
    );
    
    if (stage.type !== 'WON' && contactsInRange.length < minContactsPerStage) {
      return false; // Remove unnecessary stage
    }
    
    return true;
  });
}

// Chunk 6.5: Generate Business Stage Description
function generateBusinessStageDescription(
  stageName: string,
  range: { min: number; max: number },
  contacts: ContactAnalysis[],
  businessContext?: BusinessContext
): string {
  let desc = `${stageName} stage for leads with scores ${range.min}-${range.max}`;
  
  if (businessContext) {
    desc += `. Optimized for ${businessContext.businessType.replace('_', ' ').toLowerCase()} businesses`;
  }
  
  if (contacts.length > 0) {
    const avgConversion = contacts.reduce((sum, c) => sum + c.conversionProbability, 0) / contacts.length;
    desc += `. Average conversion probability: ${Math.round(avgConversion)}%`;
  }
  
  return desc;
}

// Chunk 6.6: Get Business Stage Characteristics
function getBusinessStageCharacteristics(
  contacts: ContactAnalysis[],
  stageName: string,
  businessContext?: BusinessContext
): string[] {
  const characteristics: string[] = [];
  
  if (businessContext) {
    characteristics.push(`Business Type: ${businessContext.businessType.replace('_', ' ')}`);
  }
  
  const intents = contacts.map(c => c.buyerIntent);
  const mostCommonIntent = getMostCommon(intents);
  if (mostCommonIntent) {
    characteristics.push(`Primary Intent: ${mostCommonIntent}`);
  }
  
  const avgConversion = contacts.length > 0
    ? contacts.reduce((sum, c) => sum + c.conversionProbability, 0) / contacts.length
    : 0;
  
  if (avgConversion > 0) {
    characteristics.push(`Conversion: ${Math.round(avgConversion)}%`);
  }
  
  return characteristics;
}

// Chunk 6.7: Get Business Stage Color
function getBusinessStageColor(type: SuggestedStage['type'], index: number): string {
  if (type === 'WON') {
    return '#10b981';
  } else if (type === 'LEAD') {
    return '#64748b';
  }
  
  const colors = [
    '#3b82f6', // Blue
    '#8b5cf6', // Purple
    '#f59e0b', // Amber
    '#ef4444', // Red
  ];
  
  return colors[index % colors.length];
}

// ============================================================================
// Chunk 7: Helper Functions for Main Function
// ============================================================================

async function fetchAnalyzedContacts(
  organizationId: string,
  facebookPageId?: string
) {
  // If facebookPageId is provided, it's the Facebook page ID (pageId), not the database ID
  // We need to find the FacebookPage record first to get the database ID
  let pageDatabaseId: string | undefined;
  if (facebookPageId) {
    const page = await prisma.facebookPage.findFirst({
      where: {
        organizationId,
        pageId: facebookPageId, // facebookPageId parameter is the Facebook pageId, not database id
      },
      select: { id: true },
    });
    if (page) {
      pageDatabaseId = page.id;
    } else {
      console.warn(`[Pipeline Generator] Facebook page with pageId ${facebookPageId} not found in organization ${organizationId}`);
    }
  }

  // Build where clause - look for contacts that have been analyzed
  // A contact is considered analyzed if it has any of these fields populated
  const whereClause: any = {
    organizationId,
    ...(pageDatabaseId ? { facebookPageId: pageDatabaseId } : {}),
    // Require at least one analysis field to be present
    OR: [
      { aiContext: { not: null } },
      { aiSummary: { not: null } },
      { buyerIntent: { not: null } },
      { sentiment: { not: null } },
      { conversionProbability: { not: null } },
      { leadScore: { gt: 0 } }, // Also include contacts with leadScore > 0
    ],
    // Must have at least one message to be meaningful
    messages: { some: {} },
  };

  console.log(`[Pipeline Generator] Fetching analyzed contacts for org ${organizationId}${pageDatabaseId ? `, page ${pageDatabaseId}` : ' (all pages)'}`);

  const contactsWithScores = await prisma.contact.findMany({
    where: whereClause,
    select: {
      id: true,
      leadScore: true,
      buyerIntent: true,
      sentiment: true,
      productInterests: true,
      conversionProbability: true,
      aiContext: true,
      aiSummary: true,
      intentSignals: true,
      nextBestAction: true,
      messages: {
        take: 50,
        orderBy: { createdAt: 'desc' },
        select: {
          content: true,
          isFromBusiness: true,
          createdAt: true,
        },
      },
    },
    take: 1000,
  });

  console.log(`[Pipeline Generator] Found ${contactsWithScores.length} contacts with analysis data`);

  // Filter to ensure we only return contacts with meaningful analysis data
  const analyzedContacts = contactsWithScores.filter(contact => 
    contact.aiContext !== null ||
    contact.aiSummary !== null ||
    contact.buyerIntent !== null ||
    contact.sentiment !== null ||
    contact.conversionProbability !== null ||
    (contact.leadScore !== null && contact.leadScore > 0)
  );

  console.log(`[Pipeline Generator] Filtered to ${analyzedContacts.length} contacts with valid analysis data`);

  return analyzedContacts;
}

interface ContactFromDB {
  id: string;
  leadScore: number | null;
  buyerIntent: string | null;
  sentiment: string | null;
  productInterests: string[];
  conversionProbability: number | null;
  aiContext: string | null;
  aiSummary: string | null;
  intentSignals: Prisma.JsonValue;
  nextBestAction: string | null;
  messages: Array<{ content: string | null; isFromBusiness: boolean; createdAt: Date }>;
}

function convertToContactAnalysis(analyzedContacts: ContactFromDB[]): ContactAnalysis[] {
  return analyzedContacts
    .map(contact => {
      // Calculate leadScore - use existing if available, otherwise derive from analysis data
      let leadScore = contact.leadScore ?? 0;
      
      // If leadScore is 0 or null, try to derive it from other analysis fields
      if (leadScore === 0 || leadScore === null) {
        // Base score from conversion probability
        if (contact.conversionProbability !== null) {
          leadScore = Math.round(contact.conversionProbability);
        } else {
          // Derive from buyer intent
          const intent = contact.buyerIntent?.toUpperCase();
          if (intent === 'READY_TO_BUY' || intent === 'PURCHASING') {
            leadScore = 75;
          } else if (intent === 'EVALUATING' || intent === 'PRICE_INQUIRY') {
            leadScore = 50;
          } else if (intent === 'INQUIRING') {
            leadScore = 30;
          } else {
            leadScore = 20; // Default for BROWSING or unknown
          }
        }
      }

      const totalLength = contact.messages.reduce((sum: number, msg) => sum + (msg.content?.length || 0), 0);
      const avgMessageLength = contact.messages.length > 0 ? totalLength / contact.messages.length : 0;
      
      let engagementLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH' = 'LOW';
      const messageCount = contact.messages.length;
      const conversionProb = contact.conversionProbability || 0;
      const intentSignals = (contact.intentSignals as ContactAnalysis['intentSignals']) || undefined;
      
      if (messageCount >= 10 && conversionProb >= 60 && intentSignals?.rapidReplies) {
        engagementLevel = 'VERY_HIGH';
      } else if (messageCount >= 5 && conversionProb >= 40) {
        engagementLevel = 'HIGH';
      } else if (messageCount >= 3 || conversionProb >= 20) {
        engagementLevel = 'MEDIUM';
      }
      
      return {
        contactId: contact.id,
        buyerIntent: contact.buyerIntent || 'BROWSING',
        sentiment: contact.sentiment || 'NEUTRAL',
        leadScore: Math.max(0, Math.min(100, leadScore)), // Ensure score is 0-100
        messageCount: contact.messages.length,
        productInterests: contact.productInterests || [],
        conversionProbability: contact.conversionProbability || 0,
        intentSignals,
        nextBestAction: contact.nextBestAction || undefined,
        avgMessageLength,
        engagementLevel
      };
    })
    .filter(contact => contact.leadScore > 0 || contact.conversionProbability > 0 || contact.buyerIntent !== 'BROWSING'); // Only include contacts with meaningful data
}

async function getEmptyPipelineResponse(
  organizationId: string,
  facebookPageId?: string
): Promise<PipelineSuggestion> {
  const totalContacts = await prisma.contact.count({
    where: {
      organizationId,
      ...(facebookPageId ? { facebookPageId } : {}),
    }
  });

  if (totalContacts === 0) {
      return {
        name: 'Sales Pipeline',
      description: 'No contacts found. Please sync contacts first before generating a pipeline.',
        stages: [],
      totalContacts: 0,
      confidence: 0
    };
  } else {
    return {
      name: 'Sales Pipeline',
      description: `Found ${totalContacts} contact(s), but they haven't been analyzed yet. Please run pipeline analysis first to analyze contacts before generating a pipeline.`,
      stages: [],
      totalContacts,
        confidence: 0
      };
  }
}

function getErrorResponse(error: unknown): PipelineSuggestion {
  const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
  return {
    name: 'Sales Pipeline',
    description: `Error generating pipeline: ${errorMessage}. Please ensure contacts have been analyzed first.`,
    stages: [],
    totalContacts: 0,
    confidence: 0
  };
}

function generatePipelineDescription(
  logic: PipelineGenerationLogic,
  businessContext: BusinessContext | null,
  stageCount: number,
  contactCount: number,
  usesGPT: boolean = false
): string {
  let desc = usesGPT
    ? `AI-generated pipeline using GPT-OSS-120B with custom instructions`
    : `AI-generated pipeline using ${logic} logic`;
  
  if (businessContext) {
    desc += ` for ${businessContext.businessType.replace('_', ' ').toLowerCase()} business`;
    if (businessContext.industryIndicators.length > 0) {
      desc += ` (${businessContext.industryIndicators.join(', ')})`;
    }
  }
  
  desc += `. ${stageCount} stages based on ${contactCount} contact analyses`;
  
  return desc;
}

function calculateConfidence(
  stages: SuggestedStage[],
  analyses: ContactAnalysis[],
  businessContext: BusinessContext | null
): number {
  let confidence = 50; // Base
  
  // More stages = more confidence (up to a point)
  if (stages.length >= 5 && stages.length <= 12) confidence += 10;
  
  // More contacts = more confidence
  if (analyses.length >= 50) confidence += 15;
  else if (analyses.length >= 20) confidence += 10;
  
  // Business context confidence
  if (businessContext && businessContext.confidence > 70) confidence += 10;
  
  // Stage validation
  const validStages = stages.filter(s => s.expectedContacts > 0 && s.characteristics.length > 0);
  if (validStages.length === stages.length) confidence += 15;
  
  return Math.min(95, confidence);
}

// ============================================================================
// Chunk 7: GPT-Based Pipeline Generation (for custom instructions)
// ============================================================================

/**
 * Get API key for GPT generation
 */
async function getApiKeyForGPT(): Promise<string | null> {
  try {
    const dbKey = await apiKeyManager.getNextKey({ operation: 'pipeline-generation' });
    if (dbKey) {
      return dbKey;
    }
    
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    return envKey;
  } catch (error) {
    console.error('[Pipeline GPT] Error retrieving API key:', error);
    const envKey = process.env.NVIDIA_API_KEY || process.env.GOOGLE_AI_API_KEY || null;
    return envKey;
  }
}

/**
 * Create NVIDIA OpenAI client
 */
function createNvidiaClient(apiKey: string): OpenAI {
  return new OpenAI({
    baseURL: 'https://integrate.api.nvidia.com/v1',
    apiKey: apiKey,
  });
}

/**
 * Generate pipeline stages using GPT-OSS-120B based on custom instructions
 */
async function generateStagesWithGPT(
  analyses: ContactAnalysis[],
  customInstructions: string,
  options: {
    requestedStageCount?: number;
    minContactsPerStage: number;
    detailLevel: number;
    businessContext: BusinessContext | null;
  }
): Promise<SuggestedStage[]> {
  const apiKey = await getApiKeyForGPT();
  if (!apiKey) {
    console.warn('[Pipeline GPT] No API key available, falling back to algorithmic generation');
    return generateFallbackStages(analyses, options.requestedStageCount || 5);
  }

  try {
    const client = createNvidiaClient(apiKey);
    const MODEL = 'openai/gpt-oss-120b';

    // Prepare contact data summary for GPT
    const contactSummary = {
      totalContacts: analyses.length,
      scoreRange: {
        min: Math.min(...analyses.map(a => a.leadScore)),
        max: Math.max(...analyses.map(a => a.leadScore)),
        mean: analyses.reduce((sum, a) => sum + a.leadScore, 0) / analyses.length
      },
      buyerIntents: [...new Set(analyses.map(a => a.buyerIntent))],
      sentiments: [...new Set(analyses.map(a => a.sentiment))],
      productInterests: [...new Set(analyses.flatMap(a => a.productInterests || []))],
      engagementLevels: [...new Set(analyses.map(a => a.engagementLevel || 'LOW'))],
      avgConversionProbability: analyses.reduce((sum, a) => sum + a.conversionProbability, 0) / analyses.length
    };

    const businessContextInfo = options.businessContext
      ? `Business Type: ${options.businessContext.businessType}, Sales Cycle: ${options.businessContext.salesCycleLength}, Conversion Pattern: ${options.businessContext.conversionPattern}`
      : 'No specific business context detected';

    const stageCountHint = options.requestedStageCount
      ? `Generate approximately ${options.requestedStageCount} stages.`
      : `Generate an appropriate number of stages (typically 3-15) based on the data and requirements.`;

    const prompt = `You are an expert sales pipeline architect. Generate a custom sales pipeline structure based on the following requirements and contact data.

CUSTOM INSTRUCTIONS:
${customInstructions}

CONTACT DATA SUMMARY:
- Total Contacts: ${contactSummary.totalContacts}
- Lead Score Range: ${contactSummary.scoreRange.min}-${contactSummary.scoreRange.max} (mean: ${contactSummary.scoreRange.mean.toFixed(1)})
- Buyer Intents: ${contactSummary.buyerIntents.join(', ')}
- Sentiments: ${contactSummary.sentiments.join(', ')}
- Product Interests: ${contactSummary.productInterests.slice(0, 10).join(', ')}${contactSummary.productInterests.length > 10 ? '...' : ''}
- Engagement Levels: ${contactSummary.engagementLevels.join(', ')}
- Average Conversion Probability: ${contactSummary.avgConversionProbability.toFixed(1)}%

BUSINESS CONTEXT:
${businessContextInfo}

REQUIREMENTS:
${stageCountHint}
- Each stage must have a unique lead score range that covers the full 0-100 range without gaps
- Minimum contacts per stage: ${options.minContactsPerStage}
- Detail level: ${options.detailLevel}/10

Return ONLY a valid JSON array of stages with this exact structure (no markdown, no explanations):
[
  {
    "name": "Stage name (e.g., 'New Lead', 'Qualified', 'Proposal Sent')",
    "description": "Brief description of what this stage represents",
    "color": "Hex color code (e.g., '#3b82f6')",
    "type": "LEAD|IN_PROGRESS|WON|LOST|ARCHIVED",
    "leadScoreMin": 0-100,
    "leadScoreMax": 0-100,
    "expectedContacts": number,
    "characteristics": ["characteristic 1", "characteristic 2"]
  }
]

IMPORTANT:
- Stages must be ordered from lowest to highest score (leadScoreMin ascending)
- Score ranges must cover 0-100 without gaps or overlaps
- Stage names should be clear and professional
- Colors should be distinct and visually appealing
- Types: LEAD (0-30), IN_PROGRESS (31-80), WON (81-100), LOST (0-20), ARCHIVED (any)
- Ensure expectedContacts reflects realistic distribution based on the score ranges`;

    console.log('[Pipeline GPT] Generating stages with GPT-OSS-120B...');

    const completion = await client.chat.completions.create({
      model: MODEL,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.7,
      max_tokens: 3000,
    });

    const responseText = completion.choices[0]?.message?.content?.trim();
    if (!responseText) {
      throw new Error('No response from GPT');
    }

    // Parse JSON response (handle markdown code blocks if present)
    let jsonText = responseText;
    const jsonMatch = responseText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    if (jsonMatch) {
      jsonText = jsonMatch[1];
    }

    const parsedStages = JSON.parse(jsonText) as Array<{
      name: string;
      description: string;
      color: string;
      type: 'LEAD' | 'IN_PROGRESS' | 'WON' | 'LOST' | 'ARCHIVED';
      leadScoreMin: number;
      leadScoreMax: number;
      expectedContacts: number;
      characteristics: string[];
    }>;

    // Convert to SuggestedStage format and validate
    const stages: SuggestedStage[] = parsedStages.map((stage, index) => {
      // Calculate actual expected contacts based on score range
      const contactsInRange = analyses.filter(a =>
        a.leadScore >= stage.leadScoreMin && a.leadScore <= stage.leadScoreMax
      );

      return {
        name: stage.name,
        description: stage.description,
        color: stage.color || getStageColor(index, parsedStages.length, stage.type),
        type: stage.type,
        leadScoreMin: Math.max(0, Math.min(100, stage.leadScoreMin)),
        leadScoreMax: Math.max(0, Math.min(100, stage.leadScoreMax)),
        expectedContacts: contactsInRange.length || stage.expectedContacts || 0,
        characteristics: stage.characteristics || []
      };
    });

    // Sort by score range
    stages.sort((a, b) => a.leadScoreMin - b.leadScoreMin);

    // Validate and fix gaps/overlaps
    const validatedStages = validateAndFixScoreRanges(stages, analyses, options.minContactsPerStage);

    console.log(`[Pipeline GPT] Generated ${validatedStages.length} stages using GPT-OSS-120B`);

    return validatedStages.length >= 3 ? validatedStages : generateFallbackStages(analyses, options.requestedStageCount || 5);
  } catch (error) {
    console.error('[Pipeline GPT] Error generating with GPT, falling back to algorithmic:', error);
    return generateFallbackStages(analyses, options.requestedStageCount || 5);
  }
}

/**
 * Validate and fix score ranges to ensure no gaps or overlaps
 */
function validateAndFixScoreRanges(
  stages: SuggestedStage[],
  analyses: ContactAnalysis[],
  minContactsPerStage: number
): SuggestedStage[] {
  if (stages.length === 0) return stages;

  // Sort by score min
  const sorted = [...stages].sort((a, b) => a.leadScoreMin - b.leadScoreMin);

  // Fix overlaps and gaps
  const fixed: SuggestedStage[] = [];
  let currentMin = 0;

  for (let i = 0; i < sorted.length; i++) {
    const stage = sorted[i];
    const isLast = i === sorted.length - 1;

    // Adjust min to avoid overlap with previous stage
    const adjustedMin = Math.max(currentMin, stage.leadScoreMin);

    // Adjust max - if last stage, extend to 100; otherwise, ensure no gap with next stage
    let adjustedMax = stage.leadScoreMax;
    if (isLast) {
      adjustedMax = 100;
    } else {
      const nextMin = sorted[i + 1].leadScoreMin;
      adjustedMax = Math.min(adjustedMax, nextMin - 1);
    }

    // Ensure min < max
    if (adjustedMin >= adjustedMax) {
      adjustedMax = adjustedMin + 1;
    }

    // Check if stage has enough contacts
    const contactsInRange = analyses.filter(a =>
      a.leadScore >= adjustedMin && a.leadScore <= adjustedMax
    );

    if (contactsInRange.length >= minContactsPerStage || isLast) {
      fixed.push({
        ...stage,
        leadScoreMin: adjustedMin,
        leadScoreMax: adjustedMax,
        expectedContacts: contactsInRange.length
      });
      currentMin = adjustedMax + 1;
    }
  }

  // Ensure we cover 0-100
  if (fixed.length > 0) {
    fixed[0].leadScoreMin = 0;
    fixed[fixed.length - 1].leadScoreMax = 100;
  }

  return fixed;
}

/**
 * Analyze contacts to suggest optimal pipeline structure
 * Supports both old signature (backward compatible) and new options-based signature
 */
export async function generatePipelineFromContacts(
  organizationId: string,
  facebookPageIdOrOptions?: string | GenerationOptions,
  requestedStageCountOrOptions?: number | GenerationOptions,
  detailLevel?: number
): Promise<PipelineSuggestion> {
  // Handle backward compatibility - detect if second param is options object
  let options: GenerationOptions;
  let actualFacebookPageId: string | undefined;
  
  if (typeof facebookPageIdOrOptions === 'object' && facebookPageIdOrOptions !== null && 'logic' in facebookPageIdOrOptions) {
    // New signature: (organizationId, options) - options may contain facebookPageId
    options = facebookPageIdOrOptions;
    actualFacebookPageId = (options as GenerationOptions & { facebookPageId?: string }).facebookPageId;
  } else if (typeof requestedStageCountOrOptions === 'object' && requestedStageCountOrOptions !== null && 'logic' in requestedStageCountOrOptions) {
    // New signature: (organizationId, facebookPageId, options)
    actualFacebookPageId = facebookPageIdOrOptions as string | undefined;
    options = requestedStageCountOrOptions;
          } else {
    // Old signature: (organizationId, facebookPageId?, requestedStageCount?, detailLevel?)
    actualFacebookPageId = facebookPageIdOrOptions as string | undefined;
    options = {
      requestedStageCount: requestedStageCountOrOptions as number | undefined,
      detailLevel: detailLevel,
      logic: 'ADAPTIVE',
      minContactsPerStage: 2,
      enableAutoGeneration: true,
      enableBusinessIntelligence: false,
      allowAIStageDecision: false
    };
  }

  const {
    logic = 'HYBRID',
    requestedStageCount,
    minContactsPerStage = 2,
    enableBusinessIntelligence = true,
    detailLevel: optDetailLevel = 5,
    allowAIStageDecision = true,
    customInstructions
  } = options;

  try {
    // Step 1: Analyze contacts first (required)
    const analyzedContacts = await fetchAnalyzedContacts(organizationId, actualFacebookPageId);
    
    if (analyzedContacts.length === 0) {
      return await getEmptyPipelineResponse(organizationId, actualFacebookPageId);
    }

    // Step 2: Convert to ContactAnalysis format
    const analyses = convertToContactAnalysis(analyzedContacts);

    if (analyses.length === 0) {
      return {
        name: 'Sales Pipeline',
        description: 'Contacts found but no lead scores available. Please run pipeline analysis first.',
        stages: [],
        totalContacts: analyzedContacts.length,
        confidence: 0
      };
    }

    // Step 3: Analyze business context (if enabled)
    let businessContext: BusinessContext | null = null;
    if (enableBusinessIntelligence) {
      businessContext = await analyzeBusinessContext(analyses, organizationId, actualFacebookPageId);
    }

    // Step 4: Generate stages - use GPT if custom instructions provided, otherwise use algorithmic approach
    let stages: SuggestedStage[];
    if (customInstructions && customInstructions.trim().length > 0) {
      // Use GPT-OSS-120B for custom pipeline generation
      stages = await generateStagesWithGPT(
        analyses,
        customInstructions,
        {
          requestedStageCount,
          minContactsPerStage,
          detailLevel: optDetailLevel,
          businessContext
        }
      );
    } else {
      // Use algorithmic approach
      stages = logic === 'HYBRID'
        ? await generateHybridStages(analyses, businessContext, {
            requestedStageCount,
            minContactsPerStage,
            detailLevel: optDetailLevel,
            allowAIStageDecision
          })
        : await generateStagesWithLogic(analyses, logic, {
            requestedStageCount,
            minContactsPerStage,
            detailLevel: optDetailLevel
          });
    }

    // Step 5: Apply business intelligence filtering (if enabled)
    const finalStages = enableBusinessIntelligence && businessContext
      ? applyBusinessIntelligenceFiltering(stages, businessContext, analyses, allowAIStageDecision)
      : stages;

    // Step 6: Validate stages
    const validatedStages = validateStages(finalStages, analyses, minContactsPerStage);

    // Step 7: Generate pipeline metadata
    const pipelineName = generatePipelineName(analyses, actualFacebookPageId, logic, businessContext);
    const description = customInstructions && customInstructions.trim().length > 0
      ? generatePipelineDescription(logic, businessContext, validatedStages.length, analyses.length, true)
      : generatePipelineDescription(logic, businessContext, validatedStages.length, analyses.length, false);

    return {
        name: pipelineName,
      description,
      stages: validatedStages,
        totalContacts: analyzedContacts.length,
      confidence: calculateConfidence(validatedStages, analyses, businessContext)
      };
  } catch (error) {
    console.error('[Pipeline Generator] Error:', error);
    return getErrorResponse(error);
  }
}

// Old code removed

interface ScoreRange {
  min: number;
  max: number;
}

function calculateOptimalScoreRanges(
  analyses: ContactAnalysis[],
  requestedCount?: number,
  detailLevel?: number // 1-10 scale: 1-3 = simple, 4-6 = moderate, 7-8 = detailed, 9-10 = very detailed
): ScoreRange[] {
  const scores = analyses.map(a => a.leadScore).sort((a, b) => a - b);
  const minScore = Math.min(...scores);
  const maxScore = Math.max(...scores);
  
  // Determine optimal number of stages
  let stageCount = requestedCount;
  if (!stageCount) {
    // AI decides: 3-15+ stages based on data distribution, diversity, and detail level
    const scoreRange = maxScore - minScore;
    
    // Calculate data diversity
    const uniqueIntents = new Set(analyses.map(a => a.buyerIntent)).size;
    const uniqueSentiments = new Set(analyses.map(a => a.sentiment)).size;
    const uniqueProducts = new Set(analyses.flatMap(a => a.productInterests || [])).size;
    const diversityScore = uniqueIntents + uniqueSentiments + (uniqueProducts > 0 ? Math.min(uniqueProducts, 5) : 0);
    
    // Base stage count on score range
    let baseCount = 3;
    if (scoreRange < 30) {
      baseCount = 3;
    } else if (scoreRange < 50) {
      baseCount = 4;
    } else if (scoreRange < 70) {
      baseCount = 5;
    } else {
      baseCount = 6;
    }
    
    // Apply detail level multiplier (1-10 scale)
    let detailMultiplier = 1;
    if (detailLevel !== undefined) {
      // Map detail level to multiplier:
      // 1-3: 0.8-1.0x (simpler, fewer stages)
      // 4-6: 1.0-1.3x (moderate)
      // 7-8: 1.3-1.6x (detailed)
      // 9-10: 1.6-2.0x (very detailed, more stages)
      if (detailLevel <= 3) {
        detailMultiplier = 0.8 + (detailLevel - 1) * 0.1; // 0.8, 0.9, 1.0
      } else if (detailLevel <= 6) {
        detailMultiplier = 1.0 + (detailLevel - 3) * 0.1; // 1.0, 1.1, 1.2, 1.3
      } else if (detailLevel <= 8) {
        detailMultiplier = 1.3 + (detailLevel - 6) * 0.15; // 1.3, 1.45, 1.6
      } else {
        detailMultiplier = 1.6 + (detailLevel - 8) * 0.2; // 1.6, 1.8, 2.0
      }
    }
    
    // Increase stages for diverse data (more unique characteristics = more stages)
    let diversityBonus = 0;
    if (diversityScore >= 10) {
      diversityBonus = 4; // Up to 4 extra stages for very diverse data
    } else if (diversityScore >= 7) {
      diversityBonus = 3; // Up to 3 extra stages for diverse data
    } else if (diversityScore >= 5) {
      diversityBonus = 2; // Up to 2 extra stages for moderate diversity
    }
    
    // Calculate final stage count
    stageCount = Math.round(baseCount * detailMultiplier) + diversityBonus;
    
    // Apply bounds: minimum 3, maximum 20 stages
    stageCount = Math.max(3, Math.min(20, stageCount));
  }

  // Ensure minimum of 3 stages, but allow unlimited maximum for special/unique pipelines
  stageCount = Math.max(3, stageCount);

  // Calculate ranges using quantiles for better distribution
  const ranges: ScoreRange[] = [];
  const step = 100 / stageCount;

  for (let i = 0; i < stageCount; i++) {
    const min = Math.round(i * step);
    const max = i === stageCount - 1 ? 100 : Math.round((i + 1) * step) - 1;
    ranges.push({ min, max });
  }

  return ranges;
}

function generateUniqueStageName(
  range: ScoreRange,
  intents: string[],
  sentiments: string[],
  productInterests: string[],
  avgConversion: number,
  index: number,
  totalStages: number,
  contactsInRange: ContactAnalysis[],
  usedNames: Set<string> = new Set(),
  detailedMetrics?: {
    rapidRepliesCount: number;
    multipleQuestionsCount: number;
    askingForProofCount: number;
    offHoursCount: number;
    avgResponseTime: number;
    avgMessageLength: number;
    mostCommonEngagement: string;
    mostCommonAction?: string;
    topProductInterest?: string;
  }
): string {
  const mostCommonIntent = getMostCommon(intents);
  const scorePosition = (range.min + range.max) / 2;
  const metrics = detailedMetrics || {
    rapidRepliesCount: 0,
    multipleQuestionsCount: 0,
    askingForProofCount: 0,
    offHoursCount: 0,
    avgResponseTime: 0,
    avgMessageLength: 0,
    mostCommonEngagement: 'LOW',
    mostCommonAction: undefined,
    topProductInterest: undefined
  };
  
  // Determine stage position
  const isFirstStage = index === 0;
  const isLastStage = index === totalStages - 1;
  const isEarlyStage = scorePosition < 25;
  const isMidEarlyStage = scorePosition >= 25 && scorePosition < 45;
  const isMidStage = scorePosition >= 45 && scorePosition < 70;
  const isMidLateStage = scorePosition >= 70 && scorePosition < 85;
  const isLateStage = scorePosition >= 85;
  
  // Build unique stage name using multiple differentiating factors
  let baseName = '';
  let modifier = '';
  
  // Last stage - "Closed Won" or variations
  if (isLastStage) {
    if (avgConversion >= 85 || mostCommonIntent === 'READY_TO_BUY') {
      baseName = 'Closed Won';
      if (metrics.askingForProofCount > 0) {
        modifier = ' - Verified';
      } else if (metrics.rapidRepliesCount > contactsInRange.length * 0.5) {
        modifier = ' - High Engagement';
      }
    } else if (avgConversion >= 70) {
      baseName = 'Negotiating';
      if (metrics.multipleQuestionsCount > 0) {
        modifier = ' - Active Discussion';
      }
    } else {
      baseName = 'Qualified';
      if (metrics.topProductInterest) {
        modifier = ` - ${metrics.topProductInterest}`;
      }
    }
  }
  // First stage - "New Lead" with variations
  else if (isFirstStage || isEarlyStage) {
    baseName = 'New Lead';
    if (metrics.mostCommonEngagement === 'HIGH' || metrics.mostCommonEngagement === 'VERY_HIGH') {
      modifier = ' - Engaged';
    } else if (metrics.offHoursCount > 0) {
      modifier = ' - Urgent';
    } else if (metrics.topProductInterest) {
      modifier = ` - ${metrics.topProductInterest}`;
    }
  }
  // Mid-early stages - "Contacted" with variations
  else if (isMidEarlyStage) {
    if (mostCommonIntent === 'PRICE_INQUIRY' && avgConversion >= 40) {
      baseName = 'Qualified';
      modifier = ' - Price Inquiry';
    } else if (mostCommonIntent === 'ASKING_INFO' && metrics.multipleQuestionsCount > 0) {
      baseName = 'Contacted';
      modifier = ' - Information Gathering';
    } else if (metrics.rapidRepliesCount > contactsInRange.length * 0.3) {
      baseName = 'Contacted';
      modifier = ' - Responsive';
    } else {
      baseName = 'Contacted';
      if (metrics.topProductInterest) {
        modifier = ` - ${metrics.topProductInterest}`;
      } else if (metrics.mostCommonEngagement === 'HIGH') {
        modifier = ' - Engaged';
      }
    }
  }
  // Mid stages - "Qualified" or "Proposal Sent"
  else if (isMidStage) {
    if (mostCommonIntent === 'PRICE_INQUIRY' && avgConversion >= 50) {
      baseName = 'Proposal Sent';
      if (metrics.askingForProofCount > 0) {
        modifier = ' - With Proof';
      } else if (metrics.avgResponseTime < 60) {
        modifier = ' - Quick Response';
      }
    } else if (mostCommonIntent === 'READY_TO_BUY' && avgConversion >= 60) {
      baseName = 'Negotiating';
      if (metrics.rapidRepliesCount > contactsInRange.length * 0.4) {
        modifier = ' - Active';
      }
    } else if (avgConversion >= 50) {
      baseName = 'Qualified';
      if (metrics.multipleQuestionsCount > 0) {
        modifier = ' - In Discussion';
      } else if (metrics.topProductInterest) {
        modifier = ` - ${metrics.topProductInterest}`;
      } else if (metrics.mostCommonEngagement === 'VERY_HIGH') {
        modifier = ' - High Engagement';
      }
    } else {
      baseName = 'Contacted';
      if (metrics.mostCommonEngagement === 'HIGH') {
        modifier = ' - Engaged';
      } else if (metrics.avgMessageLength > 100) {
        modifier = ' - Detailed';
      }
    }
  }
  // Mid-late stages - "Proposal Sent" or "Negotiating"
  else if (isMidLateStage) {
    if (mostCommonIntent === 'READY_TO_BUY' || avgConversion >= 70) {
      baseName = 'Negotiating';
      if (metrics.askingForProofCount > 0) {
        modifier = ' - Verification';
      } else if (metrics.rapidRepliesCount > contactsInRange.length * 0.5) {
        modifier = ' - Active';
      } else if (metrics.avgResponseTime < 30) {
        modifier = ' - Quick Response';
      }
    } else if (mostCommonIntent === 'PRICE_INQUIRY') {
      baseName = 'Proposal Sent';
      if (metrics.multipleQuestionsCount > 0) {
        modifier = ' - Reviewing';
      } else if (metrics.topProductInterest) {
        modifier = ` - ${metrics.topProductInterest}`;
      }
    } else {
      baseName = 'Qualified';
      if (metrics.mostCommonEngagement === 'VERY_HIGH') {
        modifier = ' - High Engagement';
      } else if (metrics.topProductInterest) {
        modifier = ` - ${metrics.topProductInterest}`;
      }
    }
  }
  // Late stages (but not last)
  else if (isLateStage && !isLastStage) {
    if (avgConversion >= 75) {
      baseName = 'Negotiating';
      if (metrics.askingForProofCount > 0) {
        modifier = ' - Finalizing';
      } else if (metrics.rapidRepliesCount > contactsInRange.length * 0.6) {
        modifier = ' - Very Active';
      }
    } else {
      baseName = 'Qualified';
      if (metrics.mostCommonEngagement === 'VERY_HIGH') {
        modifier = ' - High Potential';
      } else if (metrics.topProductInterest) {
        modifier = ` - ${metrics.topProductInterest}`;
      }
    }
  }
  // Fallback
  else {
    if (avgConversion >= 70) {
      baseName = 'Negotiating';
    } else if (avgConversion >= 50) {
      baseName = 'Qualified';
    } else if (avgConversion >= 30) {
      baseName = 'Contacted';
    } else {
      baseName = 'New Lead';
    }
    
    if (metrics.topProductInterest) {
      modifier = ` - ${metrics.topProductInterest}`;
    }
  }
  
  // Combine base name with modifier
  let finalName = baseName + modifier;
  
  // Ensure uniqueness - if duplicate, add more specific differentiators
  if (usedNames.has(finalName)) {
    // Add score range
    finalName = `${baseName}${modifier} (${range.min}-${range.max})`;
    
    // If still duplicate, add intent or engagement level
    if (usedNames.has(finalName)) {
      if (mostCommonIntent && mostCommonIntent !== 'BROWSING') {
        const intentLabel = mostCommonIntent.replace('_', ' ').toLowerCase();
        finalName = `${baseName}${modifier} - ${intentLabel} (${range.min}-${range.max})`;
      } else if (metrics.mostCommonEngagement !== 'LOW') {
        finalName = `${baseName}${modifier} - ${metrics.mostCommonEngagement.toLowerCase()} (${range.min}-${range.max})`;
      } else {
        finalName = `${baseName}${modifier} - Stage ${index + 1} (${range.min}-${range.max})`;
      }
    }
  }
  
  return finalName;
}

function generateStageDescription(
  range: ScoreRange,
  intents: string[],
  sentiments: string[],
  avgConversion: number,
  productInterests: string[] = []
): string {
  const mostCommonIntent = getMostCommon(intents);
  const mostCommonSentiment = getMostCommon(sentiments);
  const topProductInterest = getMostCommon(productInterests);
  
  let description = `Leads with scores ${range.min}-${range.max}`;
  
  if (topProductInterest && productInterests.length >= 2) {
    description += `. Primary interest: ${topProductInterest}`;
  }
  
  if (mostCommonIntent) {
    description += `. Intent: ${mostCommonIntent.toLowerCase().replace('_', ' ')}`;
  }
  
  if (mostCommonSentiment && mostCommonSentiment !== 'NEUTRAL') {
    description += `. Sentiment: ${mostCommonSentiment.toLowerCase()}`;
  }
  
  if (avgConversion >= 70) {
    description += `. High conversion potential (${Math.round(avgConversion)}%)`;
  } else if (avgConversion >= 50) {
    description += `. Moderate conversion potential (${Math.round(avgConversion)}%)`;
  } else if (avgConversion > 0) {
    description += `. Conversion probability: ${Math.round(avgConversion)}%`;
  }
  
  return description;
}

function getStageColor(index: number, total: number, type: SuggestedStage['type']): string {
  const colors = [
    '#64748b', // Gray - New
    '#3b82f6', // Blue - Contacted
    '#8b5cf6', // Purple - Qualified
    '#f59e0b', // Amber - Warm
    '#ef4444', // Red - Hot
    '#10b981', // Green - Won
  ];

  if (type === 'WON') {
    return '#10b981';
  } else if (type === 'LEAD') {
    return '#64748b';
  }

  return colors[Math.min(index, colors.length - 1)];
}

function getStageCharacteristics(
  intents: string[],
  sentiments: string[],
  contacts: ContactAnalysis[],
  productInterests: string[] = []
): string[] {
  const characteristics: string[] = [];
  
  const mostCommonIntent = getMostCommon(intents);
  if (mostCommonIntent) {
    characteristics.push(`Intent: ${mostCommonIntent.replace('_', ' ')}`);
  }
  
  const mostCommonSentiment = getMostCommon(sentiments);
  if (mostCommonSentiment && mostCommonSentiment !== 'NEUTRAL') {
    characteristics.push(`Sentiment: ${mostCommonSentiment}`);
  }
  
  // Add top product interests
  if (productInterests.length > 0) {
    const uniqueInterestsSet = new Set(productInterests);
    const uniqueInterests = Array.from(uniqueInterestsSet).slice(0, 3);
    if (uniqueInterests.length > 0) {
      characteristics.push(`Products: ${uniqueInterests.join(', ')}`);
    }
  }
  
  const avgMessageCount = contacts.length > 0
    ? contacts.reduce((sum, c) => sum + c.messageCount, 0) / contacts.length
    : 0;
  
  if (avgMessageCount >= 10) {
    characteristics.push('High engagement');
  } else if (avgMessageCount >= 5) {
    characteristics.push('Moderate engagement');
  }
  
  const avgConversion = contacts.length > 0
    ? contacts.reduce((sum, c) => sum + c.conversionProbability, 0) / contacts.length
    : 0;
  
  if (avgConversion >= 70) {
    characteristics.push(`High conversion (${Math.round(avgConversion)}%)`);
  } else if (avgConversion >= 50) {
    characteristics.push(`Moderate conversion (${Math.round(avgConversion)}%)`);
  }
  
  return characteristics;
}

function generatePipelineName(
  analyses: ContactAnalysis[], 
  facebookPageId?: string,
  logic?: PipelineGenerationLogic,
  businessContext?: BusinessContext | null
): string {
  // Analyze most common intents and product interests
  const intents = analyses.map(a => a.buyerIntent);
  const mostCommonIntent = getMostCommon(intents);
  
  if (businessContext && businessContext.businessType !== 'UNKNOWN') {
    const businessTypeName = businessContext.businessType.replace('_', ' ');
    return `${businessTypeName} Pipeline`;
  }
  
  if (mostCommonIntent === 'READY_TO_BUY') {
    return 'Sales Pipeline - High Intent';
  } else if (mostCommonIntent === 'PRICE_INQUIRY') {
    return 'Sales Pipeline - Price Focused';
  } else if (mostCommonIntent === 'ASKING_INFO') {
    return 'Sales Pipeline - Information Seekers';
  }
  
  if (logic === 'HYBRID') {
    return 'Hybrid AI-Generated Pipeline';
  }
  
  return 'AI-Generated Sales Pipeline';
}

function getMostCommon<T>(items: T[]): T | null {
  if (items.length === 0) return null;
  
  const counts = new Map<T, number>();
  items.forEach(item => {
    counts.set(item, (counts.get(item) || 0) + 1);
  });
  
  let maxCount = 0;
  let mostCommon: T | null = null;
  
  counts.forEach((count, item) => {
    if (count > maxCount) {
      maxCount = count;
      mostCommon = item;
    }
  });
  
  return mostCommon;
}

