import { prisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { FacebookClient } from './client';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';
import { analyzeConversation, type AnalyzeConversationResult } from '@/lib/ai/google-ai-service';
import { autoAssignContactToPipeline } from '@/lib/pipelines/auto-assign';
import { analyzeReplyTimes } from '@/lib/ai/reply-time-analyzer';

/**
 * Validates and fills missing analysis fields to prevent UNKNOWN values
 * This ensures all fields are populated based on conversation content
 */
function validateAndFillAnalysisFields(
  analysis: any,
  messages: Array<{ from: string; text: string; timestamp?: Date }> | null | undefined,
  fallbackAnalysis?: { summary?: string; leadScore?: number; confidence?: number; recommendedStage?: string; leadStatus?: string }
): any {
  const validated = { ...analysis };
  
  // Handle case where messages might be null/undefined or empty
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    // Return validated analysis with defaults if no messages available
    console.warn('[Validate Analysis] No messages provided for validation, using defaults');
    return validated;
  }
  
  // Helper to infer from conversation text
  const conversationText = messages.map(m => (m.text || '').toLowerCase()).join(' ');
  const hasPriceMention = /price|cost|budget|afford|payment|pay|expensive|cheap|discount/.test(conversationText);
  const hasTimeMention = /when|deadline|urgent|soon|asap|time|schedule|date/.test(conversationText);
  const hasQuestion = messages.some(m => (m.text || '').includes('?'));
  const messageCount = messages.length;
  const avgMessageLength = messages.length > 0 
    ? messages.reduce((sum, m) => sum + (m.text || '').length, 0) / messages.length 
    : 0;
  
  // Validate customerInsights
  if (!validated.customerInsights) validated.customerInsights = {};
  if (!validated.customerInsights.customerIntent || validated.customerInsights.customerIntent === 'UNKNOWN') {
    if (hasPriceMention && hasTimeMention) {
      validated.customerInsights.customerIntent = 'READY_TO_BUY';
    } else if (hasPriceMention || hasQuestion) {
      validated.customerInsights.customerIntent = 'EVALUATING';
    } else if (hasQuestion) {
      validated.customerInsights.customerIntent = 'INQUIRING';
    } else {
      validated.customerInsights.customerIntent = 'BROWSING';
    }
  }
  if (validated.customerInsights.budgetIndicated === undefined || validated.customerInsights.budgetIndicated === null) {
    validated.customerInsights.budgetIndicated = hasPriceMention;
  }
  if (validated.customerInsights.timelineIndicated === undefined || validated.customerInsights.timelineIndicated === null) {
    validated.customerInsights.timelineIndicated = hasTimeMention;
  }
  if (!validated.customerInsights.authorityLevel || validated.customerInsights.authorityLevel === 'UNKNOWN') {
    // Infer from decision-making language
    const hasDecisionLanguage = /decide|approve|authorize|final|confirm|agree/.test(conversationText);
    validated.customerInsights.authorityLevel = hasDecisionLanguage ? 'DECISION_MAKER' : 'END_USER';
  }
  
  // Validate engagementMetrics
  if (!validated.engagementMetrics) validated.engagementMetrics = {};
  if (!validated.engagementMetrics.engagementLevel || validated.engagementMetrics.engagementLevel === 'UNKNOWN') {
    if (messageCount > 20) validated.engagementMetrics.engagementLevel = 'VERY_HIGH';
    else if (messageCount > 10) validated.engagementMetrics.engagementLevel = 'HIGH';
    else if (messageCount > 5) validated.engagementMetrics.engagementLevel = 'MEDIUM';
    else validated.engagementMetrics.engagementLevel = 'LOW';
  }
  if (!validated.engagementMetrics.responseTime || validated.engagementMetrics.responseTime === 'UNKNOWN') {
    validated.engagementMetrics.responseTime = 'NORMAL';
  }
  if (!validated.engagementMetrics.messageFrequency || validated.engagementMetrics.messageFrequency === 'UNKNOWN') {
    if (messageCount > 15) validated.engagementMetrics.messageFrequency = 'HIGH';
    else if (messageCount > 5) validated.engagementMetrics.messageFrequency = 'MEDIUM';
    else validated.engagementMetrics.messageFrequency = 'LOW';
  }
  if (!validated.engagementMetrics.conversationDepth || validated.engagementMetrics.conversationDepth === 'UNKNOWN') {
    if (avgMessageLength > 100) validated.engagementMetrics.conversationDepth = 'DEEP';
    else if (avgMessageLength > 50) validated.engagementMetrics.conversationDepth = 'MODERATE';
    else validated.engagementMetrics.conversationDepth = 'SURFACE';
  }
  if (!validated.engagementMetrics.sentiment || validated.engagementMetrics.sentiment === 'UNKNOWN') {
    const positiveWords = /thank|great|good|excellent|love|happy|satisfied|perfect/.test(conversationText);
    const negativeWords = /bad|terrible|disappointed|angry|frustrated|hate|wrong/.test(conversationText);
    if (positiveWords && !negativeWords) validated.engagementMetrics.sentiment = 'POSITIVE';
    else if (negativeWords) validated.engagementMetrics.sentiment = 'NEGATIVE';
    else validated.engagementMetrics.sentiment = 'NEUTRAL';
  }
  if (!validated.engagementMetrics.tone || validated.engagementMetrics.tone === 'UNKNOWN') {
    validated.engagementMetrics.tone = 'FRIENDLY';
  }
  
  // Validate businessIntelligence
  if (!validated.businessIntelligence) validated.businessIntelligence = {};
  if (!validated.businessIntelligence.priceSensitivity || validated.businessIntelligence.priceSensitivity === 'UNKNOWN') {
    const priceConcern = /expensive|costly|afford|budget|cheap|discount/.test(conversationText);
    validated.businessIntelligence.priceSensitivity = priceConcern ? 'HIGH' : 'MEDIUM';
  }
  if (!validated.businessIntelligence.opportunitySize || validated.businessIntelligence.opportunitySize === 'UNKNOWN') {
    validated.businessIntelligence.opportunitySize = 'SMALL';
  }
  if (validated.businessIntelligence.conversionProbability === undefined || validated.businessIntelligence.conversionProbability === null) {
    validated.businessIntelligence.conversionProbability = fallbackAnalysis?.leadScore || 0;
  }
  
  // Validate scoring
  if (!validated.scoring) validated.scoring = {};
  if (!validated.scoring.leadScore || validated.scoring.leadScore === 0) {
    validated.scoring.leadScore = fallbackAnalysis?.leadScore || 0;
  }
  if (!validated.scoring.confidence || validated.scoring.confidence === 0) {
    validated.scoring.confidence = fallbackAnalysis?.confidence || 50;
  }
  if (!validated.scoring.fitScore) validated.scoring.fitScore = validated.scoring.leadScore || 0;
  if (!validated.scoring.engagementScore) validated.scoring.engagementScore = validated.scoring.leadScore || 0;
  if (!validated.scoring.urgencyScore) validated.scoring.urgencyScore = hasTimeMention ? 50 : 25;
  
  // Extract actual questions from messages
  if (!validated.conversationAnalysis) validated.conversationAnalysis = {};
  if (!Array.isArray(validated.conversationAnalysis.questionsAsked) || validated.conversationAnalysis.questionsAsked.length === 0) {
    validated.conversationAnalysis.questionsAsked = [];
    // Extract actual questions from messages (lines ending with ?)
    const questions = messages
      .map(m => m.text?.trim())
      .filter(text => text && text.endsWith('?') && text.length > 5)
      .slice(0, 10);
    if (questions.length > 0) {
      validated.conversationAnalysis.questionsAsked = questions;
    }
  }
  
  // Extract key topics from message content
  if (!Array.isArray(validated.conversationAnalysis.keyTopics) || validated.conversationAnalysis.keyTopics.length === 0) {
    validated.conversationAnalysis.keyTopics = [];
    // Extract topics by looking for capitalized words (likely names/products) and common topic keywords
    const topicKeywords = /(?:about|regarding|concerning|topic|subject|discuss|talk|regarding)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/gi;
    const topicMatches = [...conversationText.matchAll(topicKeywords)];
    const extractedTopics = topicMatches.map(m => m[1]).filter((v, i, a) => a.indexOf(v) === i).slice(0, 5);
    if (extractedTopics.length > 0) {
      validated.conversationAnalysis.keyTopics = extractedTopics;
    }
  }
  
  // Extract key points from longer messages
  if (!Array.isArray(validated.conversationAnalysis.keyPoints) || validated.conversationAnalysis.keyPoints.length === 0) {
    validated.conversationAnalysis.keyPoints = [];
    // Extract longer messages (likely contain key information)
    const keyPoints = messages
      .map(m => m.text?.trim())
      .filter(text => text && text.length > 30 && text.length < 200)
      .slice(0, 5);
    if (keyPoints.length > 0) {
      validated.conversationAnalysis.keyPoints = keyPoints;
    }
  }
  
  // Extract information provided (messages from business/page)
  if (!Array.isArray(validated.conversationAnalysis.informationProvided) || validated.conversationAnalysis.informationProvided.length === 0) {
    validated.conversationAnalysis.informationProvided = [];
    // Extract messages that contain information (numbers, URLs, specific details)
    const infoPattern = /(\d+|[A-Z][a-z]+\s+[A-Z][a-z]+|https?:\/\/[^\s]+|[A-Z]{2,})/;
    const infoMessages = messages
      .map(m => m.text?.trim())
      .filter(text => text && infoPattern.test(text) && text.length > 20)
      .slice(0, 5);
    if (infoMessages.length > 0) {
      validated.conversationAnalysis.informationProvided = infoMessages;
    }
  }
  
  // Ensure arrays exist and extract actual data from conversation if arrays are empty
  if (!Array.isArray(validated.customerInsights.customerNeeds) || validated.customerInsights.customerNeeds.length === 0) {
    validated.customerInsights.customerNeeds = [];
    // Extract needs from conversation - look for specific need statements
    const needPatterns = /(?:need|want|require|looking for|interested in|seeking)\s+([^.!?]+)/gi;
    const needMatches = [...conversationText.matchAll(needPatterns)];
    if (needMatches.length > 0) {
      validated.customerInsights.customerNeeds = needMatches
        .map(m => m[1].trim())
        .filter(s => s.length > 5 && s.length < 100)
        .slice(0, 5);
    }
  }
  
  if (!Array.isArray(validated.customerInsights.customerGoals) || validated.customerInsights.customerGoals.length === 0) {
    validated.customerInsights.customerGoals = [];
    // Extract goals - look for goal statements
    const goalPatterns = /(?:goal|objective|aim|target|plan|purpose|trying to|want to)\s+([^.!?]+)/gi;
    const goalMatches = [...conversationText.matchAll(goalPatterns)];
    if (goalMatches.length > 0) {
      validated.customerInsights.customerGoals = goalMatches
        .map(m => m[1].trim())
        .filter(s => s.length > 5 && s.length < 100)
        .slice(0, 5);
    }
  }
  
  if (!Array.isArray(validated.customerInsights.painPoints) || validated.customerInsights.painPoints.length === 0) {
    validated.customerInsights.painPoints = [];
    const painPatterns = /problem|issue|challenge|difficulty|struggle|frustrated|concern|worry/gi;
    const painMatches = conversationText.match(painPatterns);
    if (painMatches && painMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /problem|issue|challenge|difficulty|struggle|frustrated|concern|worry/i.test(s));
      validated.customerInsights.painPoints = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.customerInsights.preferences) || validated.customerInsights.preferences.length === 0) {
    validated.customerInsights.preferences = [];
    const prefPatterns = /prefer|like|favorite|choose|option|style|type/gi;
    const prefMatches = conversationText.match(prefPatterns);
    if (prefMatches && prefMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /prefer|like|favorite|choose|option|style|type/i.test(s));
      validated.customerInsights.preferences = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.businessIntelligence.buyingSignals) || validated.businessIntelligence.buyingSignals.length === 0) {
    validated.businessIntelligence.buyingSignals = [];
    // Extract buying signals - look for specific buying statements
    const signalPatterns = /(?:ready|buy|purchase|order|interested|decide|proceed|move forward|bili|gusto|kukunin)\s*([^.!?]*)/gi;
    const signalMatches = [...conversationText.matchAll(signalPatterns)];
    if (signalMatches.length > 0) {
      validated.businessIntelligence.buyingSignals = signalMatches
        .map(m => m[0].trim())
        .filter(s => s.length > 5 && s.length < 150)
        .slice(0, 5);
    }
  }
  
  if (!Array.isArray(validated.businessIntelligence.objections) || validated.businessIntelligence.objections.length === 0) {
    validated.businessIntelligence.objections = [];
    const objectionPatterns = /but|however|concern|worry|expensive|cost|price|hesitate|not sure|doubt/gi;
    const objectionMatches = conversationText.match(objectionPatterns);
    if (objectionMatches && objectionMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /but|however|concern|worry|expensive|cost|price|hesitate|not sure|doubt/i.test(s));
      validated.businessIntelligence.objections = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.businessIntelligence.competitorsMentioned) || validated.businessIntelligence.competitorsMentioned.length === 0) {
    validated.businessIntelligence.competitorsMentioned = [];
    // Extract competitor names (common patterns)
    const competitorPatterns = /(?:compared to|vs|versus|instead of|other|competitor|alternative)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/gi;
    const competitorMatches = [...conversationText.matchAll(competitorPatterns)];
    if (competitorMatches.length > 0) {
      validated.businessIntelligence.competitorsMentioned = competitorMatches.map(m => m[1]).filter((v, i, a) => a.indexOf(v) === i).slice(0, 5);
    }
  }
  
  if (!Array.isArray(validated.businessIntelligence.productInterest) || validated.businessIntelligence.productInterest.length === 0) {
    validated.businessIntelligence.productInterest = [];
    const productPatterns = /product|service|package|plan|option|feature|solution/gi;
    const productMatches = conversationText.match(productPatterns);
    if (productMatches && productMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /product|service|package|plan|option|feature|solution/i.test(s));
      validated.businessIntelligence.productInterest = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.businessIntelligence.riskFactors) || validated.businessIntelligence.riskFactors.length === 0) {
    validated.businessIntelligence.riskFactors = [];
    const riskPatterns = /risk|concern|worry|issue|problem|challenge|difficulty/gi;
    const riskMatches = conversationText.match(riskPatterns);
    if (riskMatches && riskMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /risk|concern|worry|issue|problem|challenge|difficulty/i.test(s));
      validated.businessIntelligence.riskFactors = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.greenFlags) || validated.greenFlags.length === 0) {
    validated.greenFlags = [];
    const greenPatterns = /yes|agree|interested|ready|excited|great|perfect|love|excellent/gi;
    const greenMatches = conversationText.match(greenPatterns);
    if (greenMatches && greenMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /yes|agree|interested|ready|excited|great|perfect|love|excellent/i.test(s));
      validated.greenFlags = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.redFlags) || validated.redFlags.length === 0) {
    validated.redFlags = [];
    const redPatterns = /no|not interested|too expensive|cannot afford|maybe later|not now|hesitate/gi;
    const redMatches = conversationText.match(redPatterns);
    if (redMatches && redMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /no|not interested|too expensive|cannot afford|maybe later|not now|hesitate/i.test(s));
      validated.redFlags = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  if (!Array.isArray(validated.upsellOpportunities) || validated.upsellOpportunities.length === 0) {
    validated.upsellOpportunities = [];
    const upsellPatterns = /also|additionally|more|another|extra|upgrade|premium|add/gi;
    const upsellMatches = conversationText.match(upsellPatterns);
    if (upsellMatches && upsellMatches.length > 0) {
      const sentences = conversationText.split(/[.!?]/).filter(s => /also|additionally|more|another|extra|upgrade|premium|add/i.test(s));
      validated.upsellOpportunities = sentences.slice(0, 5).map(s => s.trim()).filter(s => s.length > 10);
    }
  }
  
  // Validate pipelineRecommendation
  if (!validated.pipelineRecommendation) validated.pipelineRecommendation = {};
  if (!validated.pipelineRecommendation.recommendedStage) {
    validated.pipelineRecommendation.recommendedStage = fallbackAnalysis?.recommendedStage || 'New Lead';
  }
  if (!validated.pipelineRecommendation.leadStatus || validated.pipelineRecommendation.leadStatus === 'UNKNOWN') {
    validated.pipelineRecommendation.leadStatus = fallbackAnalysis?.leadStatus || 'NEW';
  }
  
  // Validate actionItems
  if (!validated.actionItems) validated.actionItems = {};
  if (!validated.actionItems.nextBestAction) {
    validated.actionItems.nextBestAction = hasQuestion ? 'Answer customer questions' : 'Follow up with contact';
  }
  
  return validated;
}

/**
 * Concurrency limiter utility for parallel operations
 */
class ConcurrencyLimiter {
  private queue: Array<{ 
    fn: () => Promise<unknown>; 
    resolve: (value: unknown) => void; 
    reject: (error: unknown) => void 
  }> = [];
  private running = 0;

  constructor(private limit: number) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push({ 
        fn: fn as () => Promise<unknown>, 
        resolve: resolve as (value: unknown) => void, 
        reject: reject as (error: unknown) => void 
      });
      this.process();
    });
  }

  private async process() {
    while (this.running < this.limit && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;

      this.running++;
      
      task.fn()
        .then((result) => {
          task.resolve(result);
        })
        .catch((error) => {
          task.reject(error);
        })
        .finally(() => {
          this.running--;
          this.process();
        });
    }
  }
}

interface AnalyzeSelectedContactsResult {
  successCount: number;
  failedCount: number;
  errors: Array<{ contactId: string; error: string }>;
}

/**
 * Analyzes selected contacts by fetching their conversations and assigning to pipeline
 */
export async function analyzeSelectedContacts(
  contactIds: string[],
  organizationId: string,
  onProgress?: (analyzed: number, failed: number, total: number) => void
): Promise<AnalyzeSelectedContactsResult> {
  // Pre-check API key health before starting analysis
  try {
    const { checkApiKeyHealth, logApiKeyHealth } = await import('@/lib/ai/api-key-health-check');
    const healthStatus = await checkApiKeyHealth();
    logApiKeyHealth(healthStatus);
    
    if (!healthStatus.hasWorkingKeys) {
      console.error(`[Analyze Selected] ❌ No working API keys available. Health check failed.`);
      console.error(`[Analyze Selected] Recommendations:`, healthStatus.recommendations);
    }
  } catch (healthCheckError) {
    console.warn(`[Analyze Selected] ⚠️ API key health check failed (non-critical):`, healthCheckError instanceof Error ? healthCheckError.message : String(healthCheckError));
    // Continue anyway - health check is informational
  }
  // Use atomic counters to avoid race conditions
  let successCount = 0;
  let failedCount = 0;
  const errors: Array<{ contactId: string; error: string }> = [];
  const overallStartTime = Date.now();
  let batchStartTime: number | undefined;
  
  // Helper to safely increment and call progress callback
  const incrementSuccess = () => {
    successCount++;
    if (onProgress) {
      onProgress(successCount, failedCount, contactIds.length);
    }
  };
  
  const incrementFailed = (error: string, contactId: string) => {
    failedCount++;
    errors.push({ contactId, error });
    if (onProgress) {
      onProgress(successCount, failedCount, contactIds.length);
    }
  };

  console.log(`[Analyze Selected] 🚀 Starting analysis for ${contactIds.length} contacts at ${new Date().toISOString()}`);
  console.log(`[Analyze Selected] Contact IDs received:`, contactIds);

  // CRITICAL VALIDATION: Ensure we're not accidentally analyzing all contacts
  if (contactIds.length > 50) {
    console.error(`[Analyze Selected] 🚨 WARNING: Received ${contactIds.length} contacts! This might be an error.`);
    console.error(`[Analyze Selected] Contact IDs:`, contactIds);
    console.error(`[Analyze Selected] If user only selected 1 contact, this is a BUG!`);
  }
  
  // ADDITIONAL VALIDATION: Log the exact count to help debug
  if (contactIds.length === 1) {
    console.log(`[Analyze Selected] ✅ Processing exactly 1 contact - this is correct for single selection`);
    console.log(`[Analyze Selected] Contact ID: ${contactIds[0]}`);
  } else {
    console.log(`[Analyze Selected] ⚠️ Processing ${contactIds.length} contacts - ensure this matches user's selection`);
  }

  // CRITICAL: Validate contactIds array before querying
  if (!Array.isArray(contactIds) || contactIds.length === 0) {
    console.error('[Analyze Selected] 🚨 CRITICAL: Invalid contactIds array!', contactIds);
    return { successCount: 0, failedCount: 0, errors: [] };
  }
  
  // CRITICAL: If only 1 contact ID provided, ensure we only fetch 1 contact
  if (contactIds.length === 1) {
    console.log(`[Analyze Selected] 🔒 SINGLE CONTACT MODE: Fetching exactly 1 contact from database`);
    console.log(`[Analyze Selected] Contact ID to fetch: ${contactIds[0]}`);
  }

  // Fetch contacts with their Facebook page info
  // IMPORTANT: Search across all databases if multi-DB is enabled (contacts might be in different org's database)
  const prisma = getPrismaForOrg(organizationId);
  let contacts = await prisma.contact.findMany({
    where: {
      id: { in: contactIds },
      organizationId,
    },
    select: {
      id: true,
      messengerPSID: true,
      instagramSID: true,
      firstName: true,
      lastName: true,
      lastInteraction: true,
      aiContext: true,
      aiContextUpdatedAt: true,
      facebookPageId: true,
      organizationId: true,
      facebookPage: {
        include: {
          autoPipeline: {
            include: {
              stages: { orderBy: { order: 'asc' } }
            }
          }
        }
      }
    },
  });

  // If not all contacts found and multi-DB is enabled, search ALL databases (like bulk API)
  if (contacts.length !== contactIds.length && process.env.ENABLE_MULTI_DB === 'true') {
    const foundContactIds = new Set(contacts.map(c => c.id));
    const missingContactIds = contactIds.filter(id => !foundContactIds.has(id));
    
    console.warn(`[Analyze Selected] Some contacts not found in routed database, checking all databases:`, {
      found: contacts.length,
      requested: contactIds.length,
      missing: missingContactIds.length,
    });
    
    try {
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const allDbConfigs = router.getAllDatabaseConfigs();
      
      // Search all databases for missing contacts (by ID only, no organizationId filter)
      const allContactsPromises = allDbConfigs.map(async (dbConfig, index) => {
        try {
          const dbContacts = await dbConfig.client.contact.findMany({
            where: {
              id: { in: missingContactIds },
              // Remove organizationId filter to find contacts across organizations
            },
            select: {
              id: true,
              messengerPSID: true,
              instagramSID: true,
              firstName: true,
              lastName: true,
              lastInteraction: true,
              aiContext: true,
              aiContextUpdatedAt: true,
              facebookPageId: true,
              organizationId: true,
              facebookPage: {
                include: {
                  autoPipeline: {
                    include: {
                      stages: { orderBy: { order: 'asc' } }
                    }
                  }
                }
              }
            },
          });
          
          console.log(`[Analyze Selected] Database ${index} (${dbConfig.index}): Found ${dbContacts.length} missing contacts`);
          return dbContacts;
        } catch (error) {
          console.error(`[Analyze Selected] Error querying database ${index} for contacts:`, error);
          return [];
        }
      });

      const allContactsResults = await Promise.all(allContactsPromises);
      const allFoundContacts = allContactsResults.flat();
      
      // Remove duplicates
      const uniqueContacts = Array.from(
        new Map(allFoundContacts.map(c => [c.id, c])).values()
      );
      
      // Check for cross-organization contacts
      const crossOrgContacts = uniqueContacts.filter(
        c => c.organizationId !== organizationId
      );
      
      if (crossOrgContacts.length > 0) {
        console.warn(`[Analyze Selected] Some contacts belong to different organization (allowing access):`, {
          crossOrgCount: crossOrgContacts.length,
          contactOrgIds: [...new Set(crossOrgContacts.map(c => c.organizationId))],
          userOrgId: organizationId,
        });
      }
      
      // Add all found contacts (allow cross-organization access like contact detail page)
      contacts = [...contacts, ...uniqueContacts];
      
      console.log(`[Analyze Selected] After checking all databases:`, {
        totalFound: contacts.length,
        fromRouted: contacts.length - uniqueContacts.length,
        fromAllDbs: uniqueContacts.length,
        requested: contactIds.length,
      });
    } catch (fallbackError) {
      console.error(`[Analyze Selected] Error checking all databases:`, fallbackError);
    }
  }

  // CRITICAL VALIDATION: Verify we fetched the correct number of contacts
  if (contactIds.length === 1 && contacts.length !== 1) {
    console.error(`[Analyze Selected] 🚨 CRITICAL BUG: Requested 1 contact but fetched ${contacts.length}!`);
    console.error(`[Analyze Selected] Requested ID: ${contactIds[0]}`);
    console.error(`[Analyze Selected] Fetched contacts:`, contacts.map(c => c.id));
    if (contacts.length > 1) {
      console.error(`[Analyze Selected] 🚨 This is a database query bug - returning only the requested contact`);
      // Filter to only the requested contact
      const requestedContact = contacts.find(c => c.id === contactIds[0]);
      if (requestedContact) {
        return await analyzeSelectedContacts([requestedContact.id], organizationId, onProgress);
      }
    }
  }

  if (contacts.length === 0) {
    console.warn(`[Analyze Selected] No contacts found for provided IDs:`, contactIds);
    return { successCount: 0, failedCount: 0, errors: [] };
  }
  
  // CRITICAL: If we requested N contacts but got more, something is wrong
  if (contacts.length > contactIds.length) {
    console.error(`[Analyze Selected] 🚨 CRITICAL: Requested ${contactIds.length} contacts but fetched ${contacts.length}!`);
    console.error(`[Analyze Selected] Requested IDs:`, contactIds);
    console.error(`[Analyze Selected] Fetched contact IDs:`, contacts.map(c => c.id));
    console.error(`[Analyze Selected] Filtering to only requested contacts`);
    // Filter to only the requested contacts
    const requestedContacts = contacts.filter(c => contactIds.includes(c.id));
    if (requestedContacts.length !== contactIds.length) {
      console.error(`[Analyze Selected] 🚨 Still have mismatch after filtering!`);
      console.error(`[Analyze Selected] Requested: ${contactIds.length}, Filtered: ${requestedContacts.length}`);
    }
    // Continue with filtered contacts
    const filteredContactIds = requestedContacts.map(c => c.id);
    return await analyzeSelectedContacts(filteredContactIds, organizationId, onProgress);
  }
  
  console.log(`[Analyze Selected] ✅ Fetched ${contacts.length} contact(s) matching ${contactIds.length} requested ID(s)`);

  // Group contacts by Facebook page (to reuse client and conversations)
  const contactsByPage = new Map<string, typeof contacts>();
  for (const contact of contacts) {
    const pageId = contact.facebookPageId;
    if (!contactsByPage.has(pageId)) {
      contactsByPage.set(pageId, []);
    }
    contactsByPage.get(pageId)!.push(contact);
  }

  // Process each page's contacts
  for (const [, pageContacts] of contactsByPage) {
    const page = pageContacts[0].facebookPage;
    
    const hasAutoPipeline = page.autoPipelineId && page.autoPipeline;
    
    if (!hasAutoPipeline) {
      console.log(`[Analyze Selected] Page ${page.pageName} has no auto-pipeline configured (autoPipelineId: ${page.autoPipelineId || 'null'}), will analyze without pipeline assignment`);
      console.log(`[Analyze Selected] To enable pipeline assignment, go to Settings → Facebook Pages → ${page.pageName} → Configure Auto-Pipeline`);
    } else {
      console.log(`[Analyze Selected] Page ${page.pageName} has auto-pipeline configured: ${page.autoPipeline?.name || 'Unknown'} (ID: ${page.autoPipelineId})`);
    }

    const client = new FacebookClient(page.pageAccessToken);

    // Build list of participant IDs we need to find
    const neededParticipantIds = new Set<string>();
    for (const contact of pageContacts) {
      if (contact.messengerPSID) neededParticipantIds.add(contact.messengerPSID);
      if (contact.instagramSID) neededParticipantIds.add(contact.instagramSID);
    }

    // Fetch conversations incrementally, stopping when we find all needed participants
    console.log(`[Analyze Selected] Fetching conversations for page ${page.pageName} (looking for ${neededParticipantIds.size} participants)...`);
    const messengerConvos = await client.getMessengerConversationsUntilFound(
      page.pageId,
      neededParticipantIds
    );
    console.log(`[Analyze Selected] Fetched ${messengerConvos.length} Messenger conversations (stopped early when all participants found)`);
    
    // Create conversation maps - only for participants we need
    const messengerConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    let foundCount = 0;
    for (const convo of messengerConvos) {
      // Early exit if we've found all needed participants
      if (foundCount >= neededParticipantIds.size) {
        console.log(`[Analyze Selected] Found all ${foundCount} participants, skipping remaining conversations`);
        break;
      }

      for (const participant of convo.participants.data) {
        if (participant.id !== page.pageId && neededParticipantIds.has(participant.id)) {
          const existing = messengerConversationMap.get(participant.id);
          if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
            messengerConversationMap.set(participant.id, {
              conversationId: convo.id,
              updatedTime: convo.updated_time,
            });
            if (!existing) foundCount++;
          }
        }
      }
    }
    console.log(`[Analyze Selected] Found conversations for ${messengerConversationMap.size} Messenger participants`);

    // Fetch Instagram conversations if connected - only for needed participants
    const instagramConversationMap = new Map<string, { conversationId: string; updatedTime: string }>();
    if (page.instagramAccountId) {
      try {
        const igConvos = await client.getInstagramConversationsUntilFound(
          page.instagramAccountId,
          neededParticipantIds
        );
        console.log(`[Analyze Selected] Fetched ${igConvos.length} Instagram conversations (stopped early when all participants found)`);
        let igFoundCount = 0;
        for (const convo of igConvos) {
          // Early exit if we've found all needed participants
          if (igFoundCount >= neededParticipantIds.size) {
            console.log(`[Analyze Selected] Found all ${igFoundCount} IG participants, skipping remaining conversations`);
            break;
          }

          for (const participant of convo.participants.data) {
            if (participant.id !== page.instagramAccountId && neededParticipantIds.has(participant.id)) {
              const existing = instagramConversationMap.get(participant.id);
              if (!existing || new Date(convo.updated_time) > new Date(existing.updatedTime)) {
                instagramConversationMap.set(participant.id, {
                  conversationId: convo.id,
                  updatedTime: convo.updated_time,
                });
                if (!existing) igFoundCount++;
              }
            }
          }
        }
        console.log(`[Analyze Selected] Found conversations for ${instagramConversationMap.size} Instagram participants`);
      } catch (error) {
        console.error(`[Analyze Selected] Failed to fetch Instagram conversations:`, error);
      }
    }

    // Process all contacts continuously - each contact completes independently
    // Use dynamic concurrency limits that respect database pool capacity
    const { getCachedConcurrencyLimits } = await import('@/lib/ai/dynamic-concurrency');
    const concurrencyLimits = await getCachedConcurrencyLimits();
    
    const conversationFetchLimiter = new ConcurrencyLimiter(concurrencyLimits.conversationFetchConcurrency); // Pool-aware limit
    const analysisLimiter = new ConcurrencyLimiter(concurrencyLimits.analysisConcurrency); // Pool-aware limit (typically 1 to prevent pool exhaustion)
    
    console.log(`[Analyze Selected] Using dynamic concurrency: Analysis=${concurrencyLimits.analysisConcurrency}, Fetch=${concurrencyLimits.conversationFetchConcurrency}`);

    console.log(`[Analyze Selected] Processing ${pageContacts.length} contacts continuously...`);
    batchStartTime = Date.now();

    // Process all contacts in one continuous flow
    await Promise.all(
      pageContacts.map(async (contact) => {
        const contactStartTime = Date.now();
        try {
          // Step 1: Find conversation ID
          let conversationInfo = contact.messengerPSID 
            ? messengerConversationMap.get(contact.messengerPSID)
            : null;

          if (!conversationInfo && contact.instagramSID) {
            conversationInfo = instagramConversationMap.get(contact.instagramSID);
          }

          if (!conversationInfo) {
            const psid = contact.messengerPSID || contact.instagramSID || 'N/A';
            const platform = contact.messengerPSID ? 'Messenger' : contact.instagramSID ? 'Instagram' : 'Unknown';
            incrementFailed(`Conversation not found: ${platform} PSID ${psid} not found in conversation list`, contact.id);
            console.warn(`[Analyze Selected] Contact ${contact.id} (${platform} PSID: ${psid}) has no conversation`);
            return;
          }

          // Step 2: Fetch messages (concurrency limited)
          const messages = await conversationFetchLimiter.execute(async () => {
            try {
              // IMPORTANT: Fetch more messages (100) to provide better context for AI analysis
              // This ensures the AI has enough conversation history to extract all required fields
              // Previous limit of 20 was too low and caused many fields to show as UNKNOWN
              return await client.getRecentMessagesForConversation(conversationInfo!.conversationId, 100);
            } catch (error) {
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              // Include more context in error message
              const errorCode = (error as any)?.code || (error as any)?.statusCode || 'N/A';
              const enhancedError = `API Error [${errorCode}]: ${errorMessage}`;
              console.error(`[Analyze Selected] Failed to fetch messages for contact ${contact.id}, conversation ${conversationInfo!.conversationId}:`, enhancedError);
              throw enhancedError;
            }
          });

          if (!messages || messages.length === 0) {
            incrementFailed('No messages found', contact.id);
            return;
          }

          // Step 3: Filter out system messages and prepare messages for analysis
          const { filterSystemMessages, hasUserMessages } = await import('./message-filtering');
          
          // Handle conversations with no messages
          if (!messages || messages.length === 0) {
            incrementFailed('No messages found in conversation', contact.id);
            return;
          }

          // Handle conversations with only system messages
          if (!hasUserMessages(messages, page.pageId)) {
            incrementFailed('No user messages found (only system messages)', contact.id);
            return;
          }

          const messagesToAnalyze = filterSystemMessages(messages, page.pageId)
            .map((msg, index) => {
              // Find original message to get timestamp if available
              const originalMsg = messages.find(m => 
                (m.message || '').trim() === msg.text.trim() ||
                (m.from?.id === msg.from) ||
                (m.from?.name === msg.from)
              );
              
              // Validate message structure
              if (!msg.text || typeof msg.text !== 'string' || msg.text.trim().length === 0) {
                console.warn(`[Analyze Selected] ⚠️ Skipping invalid message for contact ${contact.id} (empty or invalid text)`);
                return null;
              }
              
              if (!msg.from || typeof msg.from !== 'string') {
                console.warn(`[Analyze Selected] ⚠️ Skipping invalid message for contact ${contact.id} (missing or invalid from field)`);
                return null;
              }
              
              return {
                from: msg.from,
                text: msg.text.trim(),
                timestamp: originalMsg?.created_time ? new Date(originalMsg.created_time) : undefined,
                isFromBusiness: false,
              };
            })
            .filter((msg): msg is NonNullable<typeof msg> => msg !== null) // Remove nulls
            .reverse();

          // Enhanced validation with detailed logging
          if (!messagesToAnalyze || messagesToAnalyze.length === 0) {
            const errorMsg = `No valid messages to analyze after filtering (original: ${messages.length} messages)`;
            console.error(`[Analyze Selected] ❌ ${errorMsg} for contact ${contact.id}`);
            console.error(`[Analyze Selected] Contact context: firstName=${contact.firstName}, lastName=${contact.lastName}, lastInteraction=${contact.lastInteraction?.toISOString() || 'none'}`);
            incrementFailed(errorMsg, contact.id);
            return;
          }
          
          // Log message validation success
          console.log(`[Analyze Selected] ✅ Validated ${messagesToAnalyze.length} messages for contact ${contact.id} (filtered from ${messages.length} total)`);
          
          // Additional validation: ensure messages have required structure
          const invalidMessages = messagesToAnalyze.filter(msg => 
            !msg.text || !msg.from || msg.text.trim().length === 0
          );
          
          if (invalidMessages.length > 0) {
            console.warn(`[Analyze Selected] ⚠️ Found ${invalidMessages.length} invalid messages in validated set for contact ${contact.id}, removing...`);
            // Filter out invalid messages
            const validMessages = messagesToAnalyze.filter(msg => 
              msg.text && msg.from && msg.text.trim().length > 0
            );
            
            if (validMessages.length === 0) {
              const errorMsg = 'All messages were invalid after structure validation';
              console.error(`[Analyze Selected] ❌ ${errorMsg} for contact ${contact.id}`);
              incrementFailed(errorMsg, contact.id);
              return;
            }
            
            // Replace with valid messages
            messagesToAnalyze.splice(0, messagesToAnalyze.length, ...validMessages);
            console.log(`[Analyze Selected] ✅ Using ${validMessages.length} valid messages after structure validation`);
          }

          // Step 3.5: Analyze reply times for best contact times (synchronous, no API calls)
          const replyTimeAnalysis = (() => {
            try {
              const analysis = analyzeReplyTimes(messagesToAnalyze, page.pageId);
              if (analysis) {
                console.log(`[Analyze Selected] Successfully analyzed reply times for ${contact.id}`);
              }
              return analysis;
            } catch (error) {
              const errorMessage = error instanceof Error ? error.message : String(error);
              console.warn(`[Analyze Selected] Failed to analyze reply times for ${contact.id}:`, errorMessage);
              // Don't fail the entire analysis if reply time analysis fails
              return null;
            }
          })();

          // Step 4: Analyze with AI (concurrency limited)
          // OPTIMIZATION: Skip AI analysis if contact already has recent analysis (saves 5-10s per contact)
          // BUT: Always re-analyze if the previous analysis was a fallback (indicated by fallback message pattern)
          const hasRecentAnalysis = contact.aiContext && contact.aiContextUpdatedAt && 
            (Date.now() - new Date(contact.aiContextUpdatedAt).getTime()) <= 7 * 24 * 60 * 60 * 1000; // 7 days
          
          // Detect fallback analyses by checking for common fallback message patterns
          const aiContextStr = typeof contact.aiContext === 'string' ? contact.aiContext : '';
          const isFallbackAnalysis = 
            aiContextStr.toLowerCase().includes('analysis failed but assigned score') || 
            aiContextStr.toLowerCase().includes('emergency fallback') ||
            aiContextStr.toLowerCase().includes('used fallback scoring') ||
            aiContextStr.toLowerCase().includes('fallback scoring') ||
            (aiContextStr.toLowerCase().includes('moderate conversation') && aiContextStr.toLowerCase().includes('averaging')) || // Fallback pattern
            aiContextStr.toLowerCase().includes('assigned score based on'); // Another fallback pattern
          
          // Also detect old format (3-5 sentence summary) to force re-analysis with new comprehensive format
          const isOldFormat = 
            aiContextStr.toLowerCase().includes('analyze this conversation and provide a concise 3-5 sentence') ||
            aiContextStr.toLowerCase().includes('the main topic or purpose of the conversation') ||
            (aiContextStr.length < 500 && !aiContextStr.toLowerCase().includes('executivesummary')); // Short summaries likely old format
          
          // Check if existing analysis is in comprehensive JSON format
          let isComprehensiveFormat = false;
          let hasLongExecutiveSummary = false;
          let hasEmptyArrays = false;
          try {
            if (aiContextStr.trim().startsWith('{')) {
              const parsed = JSON.parse(aiContextStr);
              isComprehensiveFormat = !!(parsed.executiveSummary || parsed.greenFlags || parsed.redFlags || parsed.upsellOpportunities);
              
              // Check if executive summary is too long (old format was 200-400 words, new format should be 50-100 words)
              if (parsed.executiveSummary) {
                const wordCount = parsed.executiveSummary.split(/\s+/).length;
                // If executive summary is over 100 words, it's the old long format - force re-analysis
                hasLongExecutiveSummary = wordCount > 100;
              }
              
              // Check if analysis has empty arrays (missing data) - force re-analysis
              const arrayFields = [
                'keyTopics', 'keyPoints', 'decisionsMade', 'questionsAsked', 'informationProvided',
                'customerNeeds', 'customerGoals', 'painPoints', 'preferences',
                'buyingSignals', 'objections', 'competitorsMentioned', 'productInterest', 'riskFactors',
                'greenFlags', 'redFlags', 'upsellOpportunities', 'conversationTips', 'objectionHandling'
              ];
              
              const emptyCount = arrayFields.reduce((count, field) => {
                const value = parsed.conversationAnalysis?.[field] || 
                             parsed.customerInsights?.[field] || 
                             parsed.businessIntelligence?.[field] ||
                             parsed[field];
                if (Array.isArray(value) && value.length === 0) {
                  return count + 1;
                }
                return count;
              }, 0);
              
              // If more than 5 arrays are empty, force re-analysis
              hasEmptyArrays = emptyCount > 5;
              
              if (hasEmptyArrays) {
                console.log(`[Analyze Selected] 🔄 Previous analysis has ${emptyCount} empty arrays, forcing re-analysis for ${contact.id}`);
              }
            }
          } catch {
            // Not JSON, so not comprehensive format
            isComprehensiveFormat = false;
          }
          
          // Force re-analysis if:
          // 1. No recent analysis
          // 2. Previous was fallback
          // 3. Previous was old format
          // 4. Previous is NOT in comprehensive format (even if recent)
          // 5. Previous has long executive summary (old format - over 100 words)
          // 6. Previous has too many empty arrays (missing data)
          const shouldAnalyze = !hasRecentAnalysis || isFallbackAnalysis || isOldFormat || !isComprehensiveFormat || hasLongExecutiveSummary || hasEmptyArrays;
          
          if (hasRecentAnalysis) {
            console.log(`[Analyze Selected] 📋 Contact ${contact.id} has recent analysis from ${contact.aiContextUpdatedAt}`);
            console.log(`[Analyze Selected] Analysis preview: ${aiContextStr.substring(0, 150)}...`);
            if (isFallbackAnalysis) {
              console.log(`[Analyze Selected] 🔄 ✅ DETECTED FALLBACK ANALYSIS - Forcing re-analysis for contact ${contact.id}`);
            } else if (isOldFormat) {
              console.log(`[Analyze Selected] 🔄 ✅ DETECTED OLD FORMAT - Forcing re-analysis with new comprehensive format for contact ${contact.id}`);
            } else if (!isComprehensiveFormat) {
              console.log(`[Analyze Selected] 🔄 ✅ DETECTED NON-COMPREHENSIVE FORMAT - Forcing re-analysis with comprehensive format for contact ${contact.id}`);
            } else if (hasLongExecutiveSummary) {
              console.log(`[Analyze Selected] 🔄 ✅ DETECTED LONG EXECUTIVE SUMMARY (old format) - Forcing re-analysis with new brief format for contact ${contact.id}`);
            } else {
              console.log(`[Analyze Selected] ✅ Analysis appears valid (comprehensive format detected)`);
            }
          }
          
          let analysis: { summary: string; leadScore?: number; recommendedStage?: string; leadStatus?: string; confidence?: number; reasoning?: string } | null = null;
          
          try {
            if (shouldAnalyze) {
              // Pre-analysis validation
              if (!messagesToAnalyze || messagesToAnalyze.length === 0) {
                console.warn(`[Analyze Selected] ⚠️ No messages to analyze for contact ${contact.id}`);
                const { calculateFallbackScore } = await import('@/lib/ai/fallback-scoring');
                const fallback = calculateFallbackScore([], contact.lastInteraction || undefined);
                analysis = {
                  summary: `No messages available for analysis. ${fallback.reasoning}`,
                  leadScore: fallback.leadScore,
                  leadStatus: fallback.leadStatus,
                  confidence: fallback.confidence,
                  reasoning: fallback.reasoning,
                };
              } else {
                // Retry logic for transient errors
                const MAX_RETRIES = 3;
                let retryCount = 0;
                let lastError: Error | null = null;
                
                while (retryCount < MAX_RETRIES) {
                  try {
                    // Log analysis start
                    if (retryCount === 0) {
                      console.log(`[Analyze Selected] 🔍 Starting analysis for contact ${contact.id}: ${messagesToAnalyze.length} messages, pipeline=${hasAutoPipeline && page.autoPipeline ? 'yes' : 'no'}`);
                    } else {
                      console.log(`[Analyze Selected] 🔄 Retry ${retryCount}/${MAX_RETRIES} for contact ${contact.id}`);
                    }
                    
                    if (hasAutoPipeline && page.autoPipeline) {
                      // Use pipeline-based analysis with stage recommendation
                      const result = await analysisLimiter.execute(async () => {
                        return await analyzeWithFallback(
                          messagesToAnalyze,
                          page.autoPipeline!.stages,
                          contact.lastInteraction || undefined,
                          MAX_RETRIES - retryCount // Pass remaining retries
                        );
                      });
                      
                      // Validate result
                      if (result && result.analysis) {
                        analysis = result.analysis;
                        if (result.usedFallback) {
                          console.warn(`[Analyze Selected] ⚠️ Analysis used fallback for contact ${contact.id}: score=${analysis.leadScore}, retries=${retryCount}`);
                          console.warn(`[Analyze Selected] This means AI analysis failed - check API key, network, or model availability`);
                        } else {
                          console.log(`[Analyze Selected] ✅ AI analysis successful for contact ${contact.id}: score=${analysis.leadScore}, retries=${retryCount}`);
                        }
                        break; // Success, exit retry loop
                      } else {
                        console.warn(`[Analyze Selected] ⚠️ Analysis returned null for contact ${contact.id}, retry ${retryCount + 1}/${MAX_RETRIES}`);
                        if (retryCount < MAX_RETRIES - 1) {
                          retryCount++;
                          const backoffDelay = Math.min(Math.pow(2, retryCount) * 500, 2000); // Exponential backoff, max 2s
                          console.log(`[Analyze Selected] ⏳ Retrying in ${backoffDelay}ms...`);
                          await new Promise(resolve => setTimeout(resolve, backoffDelay));
                          continue;
                        } else {
                          analysis = null;
                          break; // Max retries reached
                        }
                      }
                    } else {
                      // Use simple analysis without pipeline
                      if (retryCount === 0) {
                        console.log(`[Analyze Selected] 🔍 Starting simple analysis for contact ${contact.id}: ${messagesToAnalyze.length} messages`);
                      }
                      const result = await analysisLimiter.execute(async () => {
                        return await analyzeConversation(messagesToAnalyze, MAX_RETRIES - retryCount, { contactId: contact.id }, true); // Request comprehensive format
                      });
                      
                      // Handle both string (backward compat) and comprehensive format
                      const summary = typeof result === 'string' ? result : result?.summary;
                      let comprehensiveAnalysis = typeof result === 'object' && result !== null && 'comprehensiveAnalysis' in result ? result.comprehensiveAnalysis : null;
                      
                      if (!summary) {
                        console.warn(`[Analyze Selected] ⚠️ AI analysis returned no summary for contact ${contact.id}, retry ${retryCount + 1}/${MAX_RETRIES}`);
                        if (retryCount < MAX_RETRIES - 1) {
                          retryCount++;
                          const backoffDelay = Math.min(Math.pow(2, retryCount) * 500, 2000);
                          console.log(`[Analyze Selected] ⏳ Retrying in ${backoffDelay}ms...`);
                          await new Promise(resolve => setTimeout(resolve, backoffDelay));
                          continue;
                        } else {
                          // Max retries reached, use fallback
                          console.warn(`[Analyze Selected] ⚠️ Max retries reached for contact ${contact.id}, using fallback`);
                          try {
                            const { calculateFallbackScore } = await import('@/lib/ai/fallback-scoring');
                            const fallback = calculateFallbackScore(messagesToAnalyze, contact.lastInteraction || undefined);
                            analysis = {
                              summary: `Analyzed ${messagesToAnalyze.length} messages. ${fallback.reasoning}`,
                              leadScore: fallback.leadScore,
                              leadStatus: fallback.leadStatus,
                              confidence: fallback.confidence,
                              reasoning: fallback.reasoning,
                            };
                            console.log(`[Analyze Selected] ✅ Used fallback scoring for contact ${contact.id} (score: ${fallback.leadScore})`);
                          } catch (fallbackError) {
                            console.error(`[Analyze Selected] ❌ Fallback scoring failed for contact ${contact.id}:`, fallbackError);
                            // Absolute minimum
                            analysis = {
                              summary: `Analysis failed. Contact has ${messagesToAnalyze.length} messages.`,
                              leadScore: 15,
                              leadStatus: 'NEW',
                              confidence: 10,
                              reasoning: 'Analysis and fallback both failed',
                            };
                          }
                          break;
                        }
                      } else {
                        console.log(`[Analyze Selected] ✅ Simple analysis complete for contact ${contact.id} (summary length: ${summary.length} chars, retries=${retryCount})`);
                        
                        // Use comprehensive format if available, otherwise create basic analysis
                        if (comprehensiveAnalysis) {
                          console.log(`[Analyze Selected] ✅ Using comprehensive format for contact ${contact.id}`);
                          
                          // Clean and validate comprehensiveAnalysis data before using it
                          // Fix any malformed strings, especially in executiveSummary
                          let cleanExecutiveSummary = comprehensiveAnalysis.executiveSummary || summary;
                          if (typeof cleanExecutiveSummary === 'string') {
                            // Check if it's malformed JSON (starts with { but isn't valid)
                            if (cleanExecutiveSummary.trim().startsWith('{')) {
                              try {
                                // Try to parse it - if it fails, it's malformed
                                const parsed = JSON.parse(cleanExecutiveSummary);
                                // If it parses, extract text from it
                                if (parsed && typeof parsed === 'object') {
                                  cleanExecutiveSummary = parsed.executiveSummary || parsed.summary || summary;
                                  console.warn(`[Analyze Selected] ⚠️ Fixed malformed executiveSummary JSON for contact ${contact.id}`);
                                }
                              } catch {
                                // It's not valid JSON - check if it's an unterminated string
                                const quoteCount = (cleanExecutiveSummary.match(/"/g) || []).length;
                                if (quoteCount % 2 !== 0) {
                                  // Unterminated string - try to fix it
                                  const lastQuoteIndex = cleanExecutiveSummary.lastIndexOf('"');
                                  if (lastQuoteIndex > 0) {
                                    cleanExecutiveSummary = cleanExecutiveSummary.substring(0, lastQuoteIndex + 1);
                                    console.warn(`[Analyze Selected] ⚠️ Fixed unterminated string in executiveSummary for contact ${contact.id}`);
                                  } else {
                                    // Can't fix it, use summary fallback
                                    cleanExecutiveSummary = summary;
                                    console.warn(`[Analyze Selected] ⚠️ Could not fix executiveSummary, using summary for contact ${contact.id}`);
                                  }
                                } else {
                                  // It's not JSON and quotes are balanced - might be valid text, but starts with {
                                  // This is suspicious - use summary instead
                                  cleanExecutiveSummary = summary;
                                  console.warn(`[Analyze Selected] ⚠️ executiveSummary looks suspicious (starts with { but not valid JSON), using summary for contact ${contact.id}`);
                                }
                              }
                            }
                          }
                          
                          analysis = {
                            summary: cleanExecutiveSummary,
                            leadScore: comprehensiveAnalysis.scoring?.leadScore ?? 50,
                            recommendedStage: comprehensiveAnalysis.pipelineRecommendation?.recommendedStage,
                            leadStatus: comprehensiveAnalysis.pipelineRecommendation?.leadStatus || 'NEW',
                            confidence: comprehensiveAnalysis.scoring?.confidence ?? 80,
                            reasoning: comprehensiveAnalysis.reasoning || '',
                            // Include all comprehensive fields (cast to any to allow extra fields)
                            executiveSummary: cleanExecutiveSummary,
                            conversationAnalysis: comprehensiveAnalysis.conversationAnalysis,
                            customerInsights: comprehensiveAnalysis.customerInsights,
                            engagementMetrics: comprehensiveAnalysis.engagementMetrics,
                            businessIntelligence: comprehensiveAnalysis.businessIntelligence,
                            actionItems: comprehensiveAnalysis.actionItems,
                            greenFlags: comprehensiveAnalysis.greenFlags,
                            redFlags: comprehensiveAnalysis.redFlags,
                            upsellOpportunities: comprehensiveAnalysis.upsellOpportunities,
                            conversationTips: comprehensiveAnalysis.conversationTips,
                            objectionHandling: comprehensiveAnalysis.objectionHandling,
                          } as any;
                        } else {
                          // Fallback to basic analysis
                          analysis = {
                            summary,
                            leadScore: 50, // Default score when no pipeline
                            recommendedStage: undefined,
                            leadStatus: undefined,
                            confidence: undefined,
                            reasoning: undefined,
                          };
                        }
                        break; // Success, exit retry loop
                      }
                    }
                  } catch (retryError) {
                    lastError = retryError instanceof Error ? retryError : new Error(String(retryError));
                    const errorMsg = lastError.message;
                    
                    // Check if error is transient (retryable)
                    const isTransientError = 
                      errorMsg.includes('timeout') ||
                      errorMsg.includes('network') ||
                      errorMsg.includes('429') || // Rate limit
                      errorMsg.includes('503') || // Service unavailable
                      errorMsg.includes('ECONNRESET') ||
                      errorMsg.includes('ETIMEDOUT');
                    
                    if (isTransientError && retryCount < MAX_RETRIES - 1) {
                      retryCount++;
                      const backoffDelay = Math.min(Math.pow(2, retryCount) * 500, 2000);
                      console.warn(`[Analyze Selected] ⚠️ Transient error for contact ${contact.id} (attempt ${retryCount}/${MAX_RETRIES}): ${errorMsg}`);
                      console.log(`[Analyze Selected] ⏳ Retrying in ${backoffDelay}ms...`);
                      await new Promise(resolve => setTimeout(resolve, backoffDelay));
                      continue;
                    } else {
                      // Non-transient error or max retries reached
                      console.error(`[Analyze Selected] ❌ Error for contact ${contact.id} (attempt ${retryCount + 1}/${MAX_RETRIES}): ${errorMsg}`);
                      throw retryError; // Will be caught by outer catch block
                    }
                  }
                }
                
                // If we exited retry loop without success and no analysis
                if (!analysis && retryCount >= MAX_RETRIES) {
                  console.error(`[Analyze Selected] ❌ Max retries (${MAX_RETRIES}) reached for contact ${contact.id}, last error: ${lastError?.message || 'Unknown'}`);
                  // Will fall through to outer catch block for fallback
                }
              }
            } else {
              // Use existing AI context (skip slow AI API call)
              if (isFallbackAnalysis) {
                console.log(`[Analyze Selected] 🔄 Previous analysis was fallback, forcing re-analysis for ${contact.id}`);
                // Force re-analysis by setting shouldAnalyze to true
                // This will be handled in the shouldAnalyze check above
              } else {
                console.log(`[Analyze Selected] ⚡ Skipping AI analysis for ${contact.id} - has recent valid analysis (${contact.aiContextUpdatedAt})`);
                if (contact.aiContext) {
                  // Parse existing context or create minimal analysis
                  // Note: leadScore and leadStatus may not exist on Contact type yet
                  analysis = {
                    summary: typeof contact.aiContext === 'string' ? contact.aiContext : 'Existing analysis',
                    leadScore: (contact as any).leadScore || 50,
                    recommendedStage: undefined,
                    leadStatus: (contact as any).leadStatus || 'NEW',
                    confidence: 80,
                    reasoning: 'Using existing AI context',
                  };
                }
              }
            }
          } catch (analysisError) {
            // Enhanced error logging
            const errorMsg = analysisError instanceof Error ? analysisError.message : String(analysisError);
            const errorType = analysisError instanceof Error ? analysisError.constructor.name : typeof analysisError;
            const errorStack = analysisError instanceof Error ? analysisError.stack : undefined;
            
            console.error(`[Analyze Selected] ❌ Analysis error for contact ${contact.id}:`);
            console.error(`[Analyze Selected] Error message: ${errorMsg}`);
            console.error(`[Analyze Selected] Error type: ${errorType}`);
            if (errorStack) {
              console.error(`[Analyze Selected] Stack trace (first 10 lines):`, errorStack.split('\n').slice(0, 10).join('\n'));
            }
            console.error(`[Analyze Selected] Context: messages=${messagesToAnalyze?.length || 0}, pipeline=${hasAutoPipeline && page.autoPipeline ? 'yes' : 'no'}`);
            console.error(`[Analyze Selected] 🔍 DEBUG: This error should NOT happen if analyzeWithFallback is working correctly.`);
            console.error(`[Analyze Selected] 🔍 DEBUG: Check if analyzeWithFallback is throwing or if analysisLimiter.execute is failing.`);
            
            // Use fallback scoring as last resort - ensure it never throws
            try {
              const { calculateFallbackScore } = await import('@/lib/ai/fallback-scoring');
              const fallback = calculateFallbackScore(messagesToAnalyze || [], contact.lastInteraction || undefined);
              analysis = {
                summary: `Analysis failed but assigned score based on ${messagesToAnalyze?.length || 0} messages. ${fallback.reasoning}`,
                leadScore: fallback.leadScore,
                leadStatus: fallback.leadStatus,
                confidence: Math.max(fallback.confidence - 20, 30), // Lower confidence due to failure
                reasoning: `Emergency fallback: ${fallback.reasoning}`,
              };
              console.log(`[Analyze Selected] ✅ Used emergency fallback scoring for contact ${contact.id} (score: ${fallback.leadScore})`);
            } catch (fallbackError) {
              // Even fallback failed - use absolute minimum
              console.error(`[Analyze Selected] ❌ Even fallback scoring failed for contact ${contact.id}:`, fallbackError);
              console.error(`[Analyze Selected] Fallback error:`, fallbackError instanceof Error ? fallbackError.message : String(fallbackError));
              
              // Absolute last resort - never throw
              analysis = {
                summary: `Analysis encountered critical errors. Contact has ${messagesToAnalyze?.length || 0} messages.`,
                leadScore: 15,
                leadStatus: 'NEW',
                confidence: 10,
                reasoning: `Multiple critical errors prevented analysis: ${errorMsg}`,
              };
              console.error(`[Analyze Selected] ⚠️ Used absolute minimum fallback for contact ${contact.id}`);
            }
          }
          
          // Comprehensive analysis result validation
          if (!analysis) {
            const errorMsg = 'AI analysis returned null - all analysis methods failed (fast, enhanced, and edge function)';
            console.error(`[Analyze Selected] ❌ ${errorMsg} for contact ${contact.id}`);
            console.error(`[Analyze Selected] Context: messages=${messagesToAnalyze?.length || 0}, pipeline=${hasAutoPipeline && page.autoPipeline ? 'yes' : 'no'}`);
            
            // Use emergency fallback instead of throwing
            try {
              const { calculateFallbackScore } = await import('@/lib/ai/fallback-scoring');
              const fallback = calculateFallbackScore(messagesToAnalyze || [], contact.lastInteraction || undefined);
              analysis = {
                summary: `Analysis returned null. Contact has ${messagesToAnalyze?.length || 0} messages. ${fallback.reasoning}`,
                leadScore: fallback.leadScore,
                leadStatus: fallback.leadStatus,
                confidence: Math.max(fallback.confidence - 30, 20),
                reasoning: `Emergency fallback: All analysis methods returned null. ${fallback.reasoning}`,
              };
              console.log(`[Analyze Selected] ✅ Used emergency fallback for null analysis (contact ${contact.id}, score: ${fallback.leadScore})`);
            } catch (fallbackError) {
              console.error(`[Analyze Selected] ❌ Emergency fallback failed for contact ${contact.id}:`, fallbackError);
              // Absolute minimum
              analysis = {
                summary: `Analysis failed. Contact has ${messagesToAnalyze?.length || 0} messages.`,
                leadScore: 15,
                leadStatus: 'NEW',
                confidence: 10,
                reasoning: 'All analysis methods and fallback failed',
              };
            }
          }
          
          // Validate analysis structure before using
          if (analysis) {
            // Ensure required fields exist
            if (!analysis.summary || typeof analysis.summary !== 'string') {
              console.warn(`[Analyze Selected] ⚠️ Invalid analysis.summary for contact ${contact.id}, fixing...`);
              analysis.summary = analysis.summary || `Contact analysis. ${messagesToAnalyze?.length || 0} messages.`;
            }
            
            if (typeof analysis.leadScore !== 'number' || isNaN(analysis.leadScore)) {
              console.warn(`[Analyze Selected] ⚠️ Invalid analysis.leadScore for contact ${contact.id}, using fallback...`);
              try {
                const { calculateFallbackScore } = await import('@/lib/ai/fallback-scoring');
                const fallback = calculateFallbackScore(messagesToAnalyze || [], contact.lastInteraction || undefined);
                analysis.leadScore = fallback.leadScore;
                analysis.leadStatus = fallback.leadStatus;
                analysis.confidence = Math.max((analysis.confidence || 50) - 20, 20);
              } catch (fallbackError) {
                analysis.leadScore = 20;
                analysis.leadStatus = 'NEW';
                analysis.confidence = 10;
              }
            }
            
            // Ensure leadScore is in valid range
            if (analysis.leadScore < 0 || analysis.leadScore > 100) {
              console.warn(`[Analyze Selected] ⚠️ leadScore out of range (${analysis.leadScore}) for contact ${contact.id}, clamping...`);
              analysis.leadScore = Math.max(0, Math.min(100, analysis.leadScore));
            }
            
            // Validate leadStatus
            if (!analysis.leadStatus || !['NEW', 'CONTACTED', 'QUALIFIED'].includes(analysis.leadStatus)) {
              console.warn(`[Analyze Selected] ⚠️ Invalid leadStatus (${analysis.leadStatus}) for contact ${contact.id}, fixing...`);
              if (analysis.leadScore >= 60) {
                analysis.leadStatus = 'QUALIFIED';
              } else if (analysis.leadScore >= 40) {
                analysis.leadStatus = 'CONTACTED';
              } else {
                analysis.leadStatus = 'NEW';
              }
            }
          }

          // Step 5: Update contact with AI context and best contact times
          // Validate analysis before database update
          if (!analysis || !analysis.summary) {
            const errorMsg = 'Cannot update contact: analysis is null or missing summary';
            console.error(`[Analyze Selected] ❌ ${errorMsg} for contact ${contact.id}`);
            incrementFailed(errorMsg, contact.id);
            return;
          }
          
          try {
            // Build update data - only include new fields if they exist in database
            const hasBestContactTimes = !!replyTimeAnalysis;
            
            // ALWAYS build comprehensive format with all required fields and defaults
            // This ensures no section is null and the JSON is always valid
            
            // CRITICAL: Ensure executiveSummary is always a plain string, not a JSON string
            let cleanExecutiveSummary = (analysis as any).executiveSummary || analysis.summary || 'Analysis completed.';
            
            // If executiveSummary is a JSON string (double-encoded), extract the actual text
            if (typeof cleanExecutiveSummary === 'string' && cleanExecutiveSummary.trim().startsWith('{')) {
              try {
                const parsed = JSON.parse(cleanExecutiveSummary);
                // If it parsed and has an executiveSummary field, use that
                if (parsed && typeof parsed === 'object' && parsed.executiveSummary) {
                  cleanExecutiveSummary = typeof parsed.executiveSummary === 'string' 
                    ? parsed.executiveSummary 
                    : JSON.stringify(parsed.executiveSummary);
                  console.log(`[Analyze Selected] ✅ Fixed double-encoded executiveSummary for contact ${contact.id}`);
                } else if (parsed && typeof parsed === 'string') {
                  // If the parsed result is a string, use it
                  cleanExecutiveSummary = parsed;
                }
              } catch {
                // If parsing fails, it's not JSON - use as-is
                // But check if it looks like it was cut off (unterminated JSON)
                if (cleanExecutiveSummary.includes('"executiveSummary"')) {
                  // Try to extract the text value
                  const match = cleanExecutiveSummary.match(/"executiveSummary"\s*:\s*"((?:[^"\\]|\\.)*)"/);
                  if (match && match[1]) {
                    cleanExecutiveSummary = match[1].replace(/\\"/g, '"').replace(/\\n/g, '\n');
                    console.log(`[Analyze Selected] ✅ Extracted executiveSummary from malformed JSON for contact ${contact.id}`);
                  }
                }
              }
            }
            
            let comprehensiveAnalysis = {
              executiveSummary: cleanExecutiveSummary,
              conversationAnalysis: (analysis as any).conversationAnalysis || {
                mainTopic: 'General conversation',
                keyTopics: [],
                keyPoints: [],
                decisionsMade: [],
                questionsAsked: [],
                informationProvided: [],
              },
              customerInsights: (analysis as any).customerInsights || {
                customerIntent: 'UNKNOWN',
                customerNeeds: [],
                customerGoals: [],
                painPoints: [],
                preferences: [],
                budgetIndicated: false,
                timelineIndicated: false,
                authorityLevel: 'UNKNOWN',
              },
              engagementMetrics: (analysis as any).engagementMetrics || {
                engagementLevel: 'UNKNOWN',
                responseTime: 'UNKNOWN',
                messageFrequency: 'UNKNOWN',
                conversationDepth: 'UNKNOWN',
                sentiment: 'NEUTRAL',
                tone: 'NEUTRAL',
              },
              businessIntelligence: (analysis as any).businessIntelligence || {
                buyingSignals: [],
                objections: [],
                competitorsMentioned: [],
                priceSensitivity: 'UNKNOWN',
                productInterest: [],
                conversionProbability: analysis.leadScore || 0,
                riskFactors: [],
                opportunitySize: 'UNKNOWN',
              },
              scoring: (analysis as any).scoring || {
                leadScore: analysis.leadScore || 0,
                confidence: analysis.confidence || 50,
                fitScore: (analysis as any).fitScore || 50,
                engagementScore: (analysis as any).engagementScore || 50,
                urgencyScore: (analysis as any).urgencyScore || 0,
              },
              pipelineRecommendation: (analysis as any).pipelineRecommendation || {
                recommendedStage: analysis.recommendedStage || 'New Lead',
                leadStatus: analysis.leadStatus || 'NEW',
                stageReason: (analysis as any).stageReason || 'Analysis completed',
                nextStage: (analysis as any).nextStage || 'Follow up',
                estimatedCloseDate: (analysis as any).estimatedCloseDate || null,
              },
              actionItems: (analysis as any).actionItems || {
                immediateActions: [],
                followUpActions: [],
                nextBestAction: 'Follow up with contact',
                bestReply: '',
                followUpMessage: '',
                deadline: null,
              },
              greenFlags: Array.isArray((analysis as any).greenFlags) ? (analysis as any).greenFlags : [],
              redFlags: Array.isArray((analysis as any).redFlags) ? (analysis as any).redFlags : [],
              upsellOpportunities: Array.isArray((analysis as any).upsellOpportunities) ? (analysis as any).upsellOpportunities : [],
              conversationTips: Array.isArray((analysis as any).conversationTips) ? (analysis as any).conversationTips : [],
              objectionHandling: Array.isArray((analysis as any).objectionHandling) ? (analysis as any).objectionHandling : [],
              reasoning: analysis.reasoning || (analysis as any).reasoning || 'Analysis completed based on conversation data.',
            };
            
            // Always save as comprehensive format JSON
            let aiContextValue: string;
            // Extract contact information from messages (phone, email, location, etc.)
            // Declare outside try block so it's accessible when updating database
            let extractedContactInfo = null;
            if (messagesToAnalyze && messagesToAnalyze.length > 0) {
              try {
                const { extractContactInfo } = await import('@/lib/ai/contact-info-extraction');
                extractedContactInfo = await extractContactInfo(messagesToAnalyze, 2, { contactId: contact.id });
                if (extractedContactInfo) {
                  console.log(`[Analyze Selected] ✅ Extracted contact info for ${contact.id}:`, {
                    hasPhone: !!(extractedContactInfo.phoneNumbers && extractedContactInfo.phoneNumbers.length > 0),
                    hasEmail: !!(extractedContactInfo.emails && extractedContactInfo.emails.length > 0),
                    hasLocation: !!(extractedContactInfo.locations && extractedContactInfo.locations.length > 0),
                    hasBusiness: !!(extractedContactInfo.businessNames && extractedContactInfo.businessNames.length > 0),
                  });
                }
              } catch (contactInfoError) {
                console.warn(`[Analyze Selected] ⚠️ Failed to extract contact info for ${contact.id}:`, contactInfoError instanceof Error ? contactInfoError.message : String(contactInfoError));
                // Don't fail the whole analysis if contact info extraction fails
              }
            }
            
            try {
              // Validate comprehensiveAnalysis structure before stringifying
              if (!comprehensiveAnalysis || typeof comprehensiveAnalysis !== 'object') {
                throw new Error('comprehensiveAnalysis is not a valid object');
              }
              
              // Validate and fill missing fields to prevent UNKNOWN values
              // Function handles null/undefined messages gracefully
              comprehensiveAnalysis = validateAndFillAnalysisFields(comprehensiveAnalysis, messagesToAnalyze, analysis);
              
              // Ensure executiveSummary is a valid string (not malformed JSON)
              if (comprehensiveAnalysis.executiveSummary && typeof comprehensiveAnalysis.executiveSummary === 'string') {
                // Check if executiveSummary contains malformed JSON (starts with { but isn't valid)
                if (comprehensiveAnalysis.executiveSummary.trim().startsWith('{')) {
                  try {
                    // Try to parse it - if it fails, it's malformed
                    JSON.parse(comprehensiveAnalysis.executiveSummary);
                    // If it parses, it's valid JSON - but we want a string, not JSON
                    // Extract the text content if it's a JSON object
                    const parsed = JSON.parse(comprehensiveAnalysis.executiveSummary);
                    if (parsed && typeof parsed === 'object') {
                      // This is malformed - executiveSummary should be a string, not JSON
                      // Extract text from it or use a fallback
                      comprehensiveAnalysis.executiveSummary = parsed.executiveSummary || parsed.summary || analysis.summary || 'Analysis completed.';
                      console.warn(`[Analyze Selected] ⚠️ Fixed malformed executiveSummary for contact ${contact.id}`);
                    }
                  } catch {
                    // It's not valid JSON, which is fine - it should be a string
                    // But check if it looks like it was cut off (unterminated string)
                    const quoteCount = (comprehensiveAnalysis.executiveSummary.match(/"/g) || []).length;
                    if (quoteCount % 2 !== 0) {
                      // Unterminated string - try to fix it
                      const lastQuoteIndex = comprehensiveAnalysis.executiveSummary.lastIndexOf('"');
                      if (lastQuoteIndex > 0) {
                        // Close the string
                        comprehensiveAnalysis.executiveSummary = comprehensiveAnalysis.executiveSummary.substring(0, lastQuoteIndex + 1);
                        console.warn(`[Analyze Selected] ⚠️ Fixed unterminated string in executiveSummary for contact ${contact.id}`);
                      } else {
                        // Can't fix it, use fallback
                        comprehensiveAnalysis.executiveSummary = analysis.summary || 'Analysis completed.';
                        console.warn(`[Analyze Selected] ⚠️ Could not fix executiveSummary, using summary fallback for contact ${contact.id}`);
                      }
                    }
                  }
                }
              }
              
              aiContextValue = JSON.stringify(comprehensiveAnalysis);
              // Validate JSON is valid and can be parsed back
              const parsed = JSON.parse(aiContextValue);
              if (!parsed || typeof parsed !== 'object') {
                throw new Error('Stringified JSON does not parse to valid object');
              }
              
              // Additional validation: ensure we have at least executiveSummary
              if (!parsed.executiveSummary || typeof parsed.executiveSummary !== 'string') {
                throw new Error('Parsed JSON missing valid executiveSummary');
              }
              
              console.log(`[Analyze Selected] ✅ Saving comprehensive format to aiContext for contact ${contact.id} (${aiContextValue.length} chars)`);
            } catch (jsonError) {
              console.error(`[Analyze Selected] ❌ Failed to stringify/validate comprehensive analysis for contact ${contact.id}:`, jsonError);
              // Fallback: create a minimal valid comprehensive format
              try {
                const fallbackComprehensive = {
                  executiveSummary: analysis.summary || 'Analysis completed.',
                  conversationAnalysis: {},
                  customerInsights: {},
                  engagementMetrics: {},
                  businessIntelligence: {
                    conversionProbability: analysis.leadScore || 0,
                  },
                  scoring: {
                    leadScore: analysis.leadScore || 0,
                    confidence: analysis.confidence || 50,
                  },
                  pipelineRecommendation: {
                    recommendedStage: analysis.recommendedStage || 'New Lead',
                    leadStatus: analysis.leadStatus || 'NEW',
                  },
                  actionItems: {},
                };
                aiContextValue = JSON.stringify(fallbackComprehensive);
                JSON.parse(aiContextValue); // Validate
                console.warn(`[Analyze Selected] ⚠️ Using fallback comprehensive format for contact ${contact.id}`);
              } catch (fallbackError) {
                // Absolute last resort - just use summary
                aiContextValue = analysis.summary || 'Analysis completed.';
                console.error(`[Analyze Selected] ❌ Even fallback comprehensive format failed, using plain summary for contact ${contact.id}`);
              }
            }
            
            const updateData: any = {
              aiContext: aiContextValue,
              aiContextUpdatedAt: new Date(),
              leadScore: analysis.leadScore,
              leadStatus: analysis.leadStatus,
            };

            // Add contact info if extracted (will fail gracefully if column doesn't exist)
            if (extractedContactInfo) {
              updateData.contactInfo = extractedContactInfo;
            }

            // Only add best contact times if available (will fail gracefully if columns don't exist)
            if (replyTimeAnalysis) {
              updateData.bestContactTimes = replyTimeAnalysis;
            }
            
            // Validate update data before database write
            if (!updateData.aiContext || typeof updateData.aiContext !== 'string') {
              throw new Error(`Invalid aiContext: ${typeof updateData.aiContext}`);
            }
            
            if (!updateData.aiContextUpdatedAt || !(updateData.aiContextUpdatedAt instanceof Date)) {
              throw new Error(`Invalid aiContextUpdatedAt: ${typeof updateData.aiContextUpdatedAt}`);
            }

            // CRITICAL: Use the contact's organizationId to get the correct database client
            // Contacts from different organizations need to be updated in their own database
            const contactPrisma = getPrismaForOrg(contact.organizationId);
            await contactPrisma.contact.update({
              where: { id: contact.id },
              data: updateData,
            });
            
            // Log success if bestContactTimes was saved
            if (hasBestContactTimes) {
              console.log(`[Analyze Selected] ✅ Successfully saved best contact times for ${contact.id}`);
            }
            
            console.log(`[Analyze Selected] ✅ Successfully updated contact ${contact.id} with AI context (${analysis.summary.length} chars, score: ${analysis.leadScore || 'N/A'})`);
          } catch (dbError: unknown) {
            // Handle database connection errors
            const dbErrorObj = dbError as { code?: string; message?: string };
            if (dbErrorObj?.code === 'P1001' || dbErrorObj?.message?.includes("Can't reach database")) {
              console.error(`[Analyze Selected] Database connection error for contact ${contact.id}:`, dbErrorObj.message);
              incrementFailed('Database connection failed. Please try again.', contact.id);
              return; // Skip pipeline assignment if DB update failed
            }
            
            // Handle missing column error (P2022) - try update without new fields
            if (dbErrorObj?.code === 'P2022' || dbErrorObj?.message?.includes('does not exist')) {
              console.warn(`[Analyze Selected] ⚠️ New columns not found in database for contact ${contact.id}, updating without them`);
              
              // CRITICAL: Log if we're losing analyzed data
              if (replyTimeAnalysis) {
                console.error(`[Analyze Selected] 🚨 CRITICAL: Best contact times were analyzed but NOT SAVED due to missing database column!`);
                console.error(`[Analyze Selected] Contact ID: ${contact.id}`);
                console.error(`[Analyze Selected] Action required: Run migration (apply-production-migration.sql) to add bestContactTimes column`);
              }
              
              try {
                // Fallback: update only existing fields
                // CRITICAL: Use the contact's organizationId to get the correct database client
                const contactPrisma = getPrismaForOrg(contact.organizationId);
                await contactPrisma.contact.update({
                  where: { id: contact.id },
                  data: {
                    aiContext: analysis.summary,
                    aiContextUpdatedAt: new Date(),
                    leadScore: analysis.leadScore,
                    leadStatus: analysis.leadStatus as 'NEW' | 'CONTACTED' | 'QUALIFIED' | 'PROPOSAL_SENT' | 'NEGOTIATING' | undefined,
                  },
                });
                console.log(`[Analyze Selected] Successfully updated contact ${contact.id} without new fields`);
                console.warn(`[Analyze Selected] ⚠️ WARNING: Contact info and best contact times were NOT saved. Please run database migration.`);
              } catch (fallbackError) {
                console.error(`[Analyze Selected] Fallback update also failed for contact ${contact.id}:`, fallbackError);
                incrementFailed('Database schema mismatch. Please run migration.', contact.id);
                return;
              }
            } else {
            throw dbError; // Re-throw other errors
            }
          }

          // Step 6: Assign to pipeline (only if auto-pipeline is configured and analysis has required fields)
          if (hasAutoPipeline && page.autoPipelineId) {
            // Check if we have the minimum required fields for pipeline assignment
            const hasLeadScore = analysis.leadScore !== undefined && analysis.leadScore !== null;
            const hasRecommendedStage = analysis.recommendedStage && analysis.recommendedStage.trim().length > 0;
            
            if (!hasLeadScore || !hasRecommendedStage) {
              console.warn(`[Analyze Selected] Missing required fields for pipeline assignment for contact ${contact.id}:`, {
                hasLeadScore,
                leadScore: analysis.leadScore,
                hasRecommendedStage,
                recommendedStage: analysis.recommendedStage,
              });
              // Use fallback values if missing
              const fallbackLeadScore = analysis.leadScore ?? 50;
              const fallbackStage = analysis.recommendedStage || page.autoPipeline?.stages[0]?.name || 'New Lead';
              
              console.log(`[Analyze Selected] Using fallback values: score=${fallbackLeadScore}, stage=${fallbackStage}`);
              
              try {
                await autoAssignContactToPipeline({
                  contactId: contact.id,
                  aiAnalysis: {
                    summary: analysis.summary,
                    leadScore: fallbackLeadScore,
                    recommendedStage: fallbackStage,
                    leadStatus: analysis.leadStatus || 'NEW',
                    confidence: analysis.confidence || 50,
                    reasoning: analysis.reasoning || `AI analysis completed but some fields missing. Score: ${fallbackLeadScore}`,
                  },
                  pipelineId: page.autoPipelineId,
                  updateMode: page.autoPipelineMode,
                });
                console.log(`[Analyze Selected] Successfully assigned contact ${contact.id} to pipeline using fallback values`);
              } catch (fallbackError: unknown) {
                const fallbackErrorObj = fallbackError as { code?: string; message?: string };
                console.error(`[Analyze Selected] Failed to assign contact ${contact.id} to pipeline even with fallback values:`, fallbackErrorObj.message);
                incrementFailed(`Pipeline assignment failed: ${fallbackErrorObj.message || 'Unknown error'}`, contact.id);
              }
            } else {
              // All required fields present - normal assignment
              try {
                await autoAssignContactToPipeline({
                  contactId: contact.id,
                  aiAnalysis: {
                    summary: analysis.summary,
                    leadScore: analysis.leadScore!,
                    recommendedStage: analysis.recommendedStage!,
                    leadStatus: analysis.leadStatus || 'NEW',
                    confidence: analysis.confidence || 50,
                    reasoning: analysis.reasoning || 'AI analysis',
                  },
                  pipelineId: page.autoPipelineId,
                  updateMode: page.autoPipelineMode,
                });
                console.log(`[Analyze Selected] Successfully assigned contact ${contact.id} to pipeline`);
              } catch (pipelineError: unknown) {
                // Handle database connection errors during pipeline assignment
                const pipelineErrorObj = pipelineError as { code?: string; message?: string };
                if (pipelineErrorObj?.code === 'P1001' || pipelineErrorObj?.message?.includes("Can't reach database")) {
                  console.error(`[Analyze Selected] Database connection error during pipeline assignment for contact ${contact.id}:`, pipelineErrorObj.message);
                  // Contact was updated but pipeline assignment failed - still count as partial success
                  incrementFailed('Contact analyzed but pipeline assignment failed due to database connection issue.', contact.id);
                  return;
                }
                console.error(`[Analyze Selected] Pipeline assignment error for contact ${contact.id}:`, pipelineErrorObj.message);
                throw pipelineError; // Re-throw other errors
              }
            }
          } else {
            const reason = !hasAutoPipeline 
              ? `no auto-pipeline configured for page ${page.pageName}` 
              : !page.autoPipelineId 
                ? 'missing pipeline ID' 
                : 'unknown reason';
            console.log(`[Analyze Selected] Skipping pipeline assignment for contact ${contact.id} - ${reason}`);
          }

          const contactDuration = Date.now() - contactStartTime;
          console.log(`[Analyze Selected] ✅ Contact ${contact.id} completed in ${contactDuration}ms`);
          incrementSuccess();
        } catch (error) {
          const contactDuration = Date.now() - contactStartTime;
          const errorMessage = error instanceof Error ? error.message : (typeof error === 'string' ? error : 'Unknown error');
          console.error(`[Analyze Selected] ❌ Contact ${contact.id} failed after ${contactDuration}ms:`, errorMessage);
          incrementFailed(errorMessage, contact.id);
        }
      })
    );
    
    const batchDuration = Date.now() - (batchStartTime || Date.now());
    console.log(`[Analyze Selected] Batch completed in ${batchDuration}ms (${pageContacts.length} contacts)`);
  }

  const totalDuration = Date.now() - overallStartTime;
  console.log(`[Analyze Selected] ✅ Completed: ${successCount} analyzed, ${failedCount} failed in ${totalDuration}ms (${Math.round(totalDuration / 1000)}s)`);
  return { successCount, failedCount, errors };
}
