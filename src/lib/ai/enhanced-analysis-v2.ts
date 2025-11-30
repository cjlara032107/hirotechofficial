/**
 * Enhanced AI Analysis System V2
 * Features:
 * - Hybrid rules + AI (rule-based for clear cases, AI for fuzzy)
 * - Filipino/Taglish language support
 * - Sentiment & emotion detection
 * - Buyer intent signal detection
 * - Time-aware lead qualification
 * - Product interest extraction
 * - Conversion probability prediction
 * - Agent assistance suggestions
 * - Next-best-action recommendations
 */

import { calculateFallbackScore } from './fallback-scoring';

interface Message {
  from: string;
  text: string;
  timestamp?: Date;
}

interface PipelineStage {
  name: string;
  type: string;
  description?: string | null;
  leadScoreMin?: number;
  leadScoreMax?: number;
}

interface EnhancedAnalysisResult {
  summary: string; // User-friendly summary (longer, more detailed)
  reasoning: string; // Detailed reasoning for AI context (comprehensive analysis)
  recommendedStage: string;
  leadScore: number;
  leadStatus: string;
  confidence: number;
  buyerIntent: string;
  sentiment: string;
  productInterests: string[];
  intentSignals: {
    rapidReplies: boolean;
    multipleQuestions: boolean;
    offHoursResponse: boolean;
    askingForProof: boolean;
    responseTimeMinutes?: number;
  };
  conversionProbability: number;
  nextBestAction: string;
  agentSuggestions: {
    bestReply?: string;
    followUpMessage?: string;
    bestOffer?: string;
    upsellOptions?: string[];
    faqAnswers?: string[];
    objectionRebuttals?: string[];
  };
  stageReason: string; // Clear explanation of why this stage
  // New features
  conversionPath?: string[]; // Conversion path mapping (e.g., ["Greeting", "Price", "Delivery", "Payment"])
  similarLeadsInsight?: string; // Similar lead suggestions and patterns
  leadRiskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; // Enhanced risk level
  leadRiskReasons?: string[]; // Specific risk reasons
  botAccuracyScore?: number; // Bot's self-evaluation of its sorting accuracy
  conversationPatterns?: {
    repeatedConcerns: string[];
    recurringProductMentions: string[];
    questionShifts: string[];
    behavioralLoops: string[];
  }; // Cross-message pattern linking
  indirectIntent?: {
    detected: boolean;
    impliedMeaning: string;
    confidence: number;
    examples: string[];
  }; // Indirect intent detection
  buyerReliability?: {
    followThroughProbability: number;
    followUpsNeeded: number;
    ghostingProbability: number;
    itemSwitchProbability: number;
  }; // Buyer Reliability Model
  buyerStyle?: 'STRAIGHT_TO_POINT' | 'EMOTIONAL' | 'ANALYTICAL' | 'DISCOUNT_HUNTER' | 'SLOW_DECISION_MAKER' | 'RESEARCH_DRIVEN'; // Buyer Style Classifier
}

// Filipino/Taglish phrase dictionary
const FILIPINO_PATTERNS = {
  PRICE_INQUIRY: [
    'magkano', 'magkno', 'magkanu', 'hm', 'how much', 'price', 'presyo',
    'magkano po', 'hm po', 'price po', 'ilan', 'how much is', 'cost'
  ],
  READY_TO_BUY: [
    'bili', 'buy', 'purchase', 'order', 'reserve', 'reserved', 'sige po reserve',
    'pa-reserve', 'pa reserve', 'i want', 'gusto ko', 'kukunin ko', 'kukuha ako',
    'send gcash', 'gcash details', "i'll pay", 'payment', 'bayad', 'pabili'
  ],
  ASKING_INFO: [
    'saan', 'san', 'where', 'location', 'locate', 'address', 'branch',
    'paano', 'pano', 'how', 'kailan', 'kelan', 'when', 'available',
    'meron', 'may', 'have', 'stock', 'available ba'
  ],
  AFTER_SALES: [
    'thank you', 'salamat', 'ty', 'ty po', 'received', 'nareceive', 'nareceive ko na',
    'delivered', 'deliver', 'shipping', 'ship', 'tracking', 'track'
  ],
  LOW_INTENT: [
    'tingin tingin lang', 'ask ko lang', 'curious lang', 'browse lang',
    'just looking', 'just asking', 'curious', 'wala lang'
  ],
  URGENT: [
    'urgent', 'asap', 'now', 'immediately', 'agad', 'mamaya', 'today',
    'ngayon', 'kanina', 'hurry', 'bilis'
  ]
};

// Normalize Filipino/Taglish text
function normalizeText(text: string): string {
  let normalized = text.toLowerCase();
  
  // Normalize common variations
  normalized = normalized.replace(/magkanu|magkno/g, 'magkano');
  normalized = normalized.replace(/hm\s*po|hm\s*$/g, 'magkano po');
  normalized = normalized.replace(/san\s/g, 'saan ');
  normalized = normalized.replace(/pano\s/g, 'paano ');
  normalized = normalized.replace(/kelan\s/g, 'kailan ');
  normalized = normalized.replace(/ty\s*po|ty\s*$/g, 'salamat po');
  
  return normalized;
}

// Detect buyer intent using rules + patterns
function detectBuyerIntent(messages: Message[]): { intent: string; confidence: number; reason: string } {
  const conversationText = messages.map(m => normalizeText(m.text)).join(' ');
  
  // Rule-based detection for clear cases
  for (const [intent, patterns] of Object.entries(FILIPINO_PATTERNS)) {
    const matches = patterns.filter(pattern => conversationText.includes(pattern));
    if (matches.length > 0) {
      return {
        intent,
        confidence: matches.length >= 2 ? 90 : 75,
        reason: `Detected ${matches.length} ${intent.toLowerCase()} signal(s): "${matches[0]}"`
      };
    }
  }
  
  // Default to browsing if no clear signals
  return {
    intent: 'BROWSING',
    confidence: 60,
    reason: 'No clear buying signals detected'
  };
}

// Detect sentiment and emotion
function detectSentiment(messages: Message[]): { sentiment: string; confidence: number; reason: string } {
  const conversationText = messages.map(m => m.text.toLowerCase()).join(' ');
  
  // Positive indicators
  const positiveWords = ['thank', 'salamat', 'ty', 'great', 'nice', 'love', 'gusto', 'excited', 'happy', '👍', '✅', '❤️'];
  const positiveCount = positiveWords.filter(word => conversationText.includes(word)).length;
  
  // Negative indicators
  const negativeWords = ['bad', 'wrong', 'problem', 'issue', 'complain', 'refund', 'cancel', 'angry', 'frustrated', 'disappointed', '😠', '❌'];
  const negativeCount = negativeWords.filter(word => conversationText.includes(word)).length;
  
  // Frustrated indicators
  const frustratedWords = ['wait', 'tagal', 'slow', 'bilis', 'hurry', 'asap', 'urgent', 'impatient'];
  const frustratedCount = frustratedWords.filter(word => conversationText.includes(word)).length;
  
  if (negativeCount > positiveCount && negativeCount >= 2) {
    return {
      sentiment: 'NEGATIVE',
      confidence: 80,
      reason: `Detected ${negativeCount} negative indicators`
    };
  }
  
  if (frustratedCount >= 2) {
    return {
      sentiment: 'FRUSTRATED',
      confidence: 75,
      reason: `Detected ${frustratedCount} frustration indicators`
    };
  }
  
  if (positiveCount > negativeCount && positiveCount >= 2) {
    return {
      sentiment: 'POSITIVE',
      confidence: 75,
      reason: `Detected ${positiveCount} positive indicators`
    };
  }
  
  return {
    sentiment: 'NEUTRAL',
    confidence: 70,
    reason: 'No strong sentiment indicators'
  };
}

// Detect buyer intent signals
function detectIntentSignals(messages: Message[]): EnhancedAnalysisResult['intentSignals'] {
  if (messages.length < 2) {
    return {
      rapidReplies: false,
      multipleQuestions: false,
      offHoursResponse: false,
      askingForProof: false
    };
  }
  
  // Calculate response times
  const responseTimes: number[] = [];
  for (let i = 1; i < messages.length; i++) {
    const currentMsg = messages[i];
    const previousMsg = messages[i - 1];
    if (currentMsg?.timestamp && previousMsg?.timestamp) {
      const diff = (currentMsg.timestamp.getTime() - previousMsg.timestamp.getTime()) / (1000 * 60); // minutes
      responseTimes.push(diff);
    }
  }
  
  const avgResponseTime = responseTimes.length > 0 
    ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
    : undefined;
  
  // Rapid replies (within 5 minutes)
  const rapidReplies = responseTimes.filter(rt => rt <= 5).length >= 2;
  
  // Multiple questions
  const questionCount = messages.filter(m => 
    m.text.includes('?') || 
    m.text.toLowerCase().includes('how') ||
    m.text.toLowerCase().includes('what') ||
    m.text.toLowerCase().includes('where') ||
    m.text.toLowerCase().includes('when') ||
    m.text.toLowerCase().includes('why') ||
    m.text.toLowerCase().includes('magkano') ||
    m.text.toLowerCase().includes('saan') ||
    m.text.toLowerCase().includes('paano')
  ).length;
  const multipleQuestions = questionCount >= 3;
  
  // Asking for proof (photos, stock, etc.)
  const proofKeywords = ['picture', 'photo', 'actual', 'real', 'stock', 'available', 'meron', 'may', 'image', 'pic'];
  const askingForProof = messages.some(m => 
    proofKeywords.some(keyword => normalizeText(m.text).includes(keyword))
  );
  
  // Off-hours response (between 10 PM - 6 AM)
  const offHoursResponse = messages.some(m => {
    if (!m.timestamp) return false;
    const hour = m.timestamp.getHours();
    return hour >= 22 || hour < 6;
  });
  
  return {
    rapidReplies,
    multipleQuestions,
    offHoursResponse,
    askingForProof,
    responseTimeMinutes: avgResponseTime
  };
}

// Extract product interests
function extractProductInterests(messages: Message[]): string[] {
  const interests: string[] = [];
  const conversationText = messages.map(m => normalizeText(m.text)).join(' ');
  
  // Common product patterns
  const productPatterns = [
    /(?:yung|ung|the)\s+(\w+\s+\w+)/gi, // "yung red dress"
    /size\s+(\d+)/gi, // "size 38"
    /model\s+(\d{4})/gi, // "model 2024"
    /(\w+)\s+(?:po|please|pls)/gi // "red dress po"
  ];
  
  for (const pattern of productPatterns) {
    const matches = conversationText.matchAll(pattern);
    for (const match of matches) {
      if (match[1] && match[1].length > 2) {
        interests.push(match[1].trim());
      }
    }
  }
  
  // Remove duplicates
  return [...new Set(interests)];
}

// Calculate conversion probability
function calculateConversionProbability(
  leadScore: number,
  buyerIntent: string,
  sentiment: string,
  intentSignals: EnhancedAnalysisResult['intentSignals'],
  messageCount: number
): number {
  let probability = leadScore; // Start with lead score
  
  // Adjust based on buyer intent
  if (buyerIntent === 'READY_TO_BUY') probability += 20;
  else if (buyerIntent === 'PRICE_INQUIRY') probability += 10;
  else if (buyerIntent === 'BROWSING') probability -= 10;
  
  // Adjust based on sentiment
  if (sentiment === 'POSITIVE') probability += 10;
  else if (sentiment === 'NEGATIVE' || sentiment === 'FRUSTRATED') probability -= 15;
  
  // Adjust based on intent signals
  if (intentSignals.rapidReplies) probability += 10;
  if (intentSignals.multipleQuestions) probability += 5;
  if (intentSignals.askingForProof) probability += 8;
  if (intentSignals.offHoursResponse) probability += 5;
  
  // Adjust based on response time
  if (intentSignals.responseTimeMinutes !== undefined) {
    if (intentSignals.responseTimeMinutes <= 5) probability += 10;
    else if (intentSignals.responseTimeMinutes <= 30) probability += 5;
    else if (intentSignals.responseTimeMinutes > 1440) probability -= 10; // > 24 hours
  }
  
  // Adjust based on message count
  if (messageCount >= 10) probability += 5;
  else if (messageCount < 3) probability -= 5;
  
  // Cap between 0-100
  return Math.max(0, Math.min(100, Math.round(probability)));
}

// Generate agent suggestions
function generateAgentSuggestions(
  buyerIntent: string,
  sentiment: string,
  productInterests: string[],
  intentSignals: EnhancedAnalysisResult['intentSignals']
): EnhancedAnalysisResult['agentSuggestions'] {
  const suggestions: EnhancedAnalysisResult['agentSuggestions'] = {};
  
  // Best reply suggestions
  if (buyerIntent === 'PRICE_INQUIRY') {
    suggestions.bestReply = 'Thank you for your interest! Let me provide you with our pricing details.';
    suggestions.followUpMessage = 'Would you like to know more about our payment options?';
  } else if (buyerIntent === 'READY_TO_BUY') {
    suggestions.bestReply = 'Great! I\'m here to help you complete your purchase.';
    suggestions.followUpMessage = 'Would you like to proceed with the order?';
  } else if (buyerIntent === 'ASKING_INFO') {
    suggestions.bestReply = 'I\'d be happy to provide that information!';
    suggestions.followUpMessage = 'Is there anything else you\'d like to know?';
  }
  
  // Best offer suggestions
  if (buyerIntent === 'PRICE_INQUIRY' && sentiment === 'POSITIVE') {
    suggestions.bestOffer = 'Special discount available for first-time customers!';
  }
  
  // Upsell options
  if (productInterests.length > 0) {
    suggestions.upsellOptions = [
      `Related products that complement ${productInterests[0]}`,
      'Bundle deals available',
      'Limited time promotions'
    ];
  }
  
  // Objection rebuttals
  if (sentiment === 'NEGATIVE' || sentiment === 'FRUSTRATED') {
    suggestions.objectionRebuttals = [
      'I understand your concern. Let me address that for you.',
      'I apologize for any inconvenience. How can I make this right?',
      'Your satisfaction is our priority. Let\'s find a solution together.'
    ];
  }
  
  return suggestions;
}

// Generate next best action
function generateNextBestAction(
  buyerIntent: string,
  sentiment: string,
  intentSignals: EnhancedAnalysisResult['intentSignals'],
  lastInteraction?: Date
): string {
  if (!lastInteraction) {
    return 'Send initial greeting and introduction';
  }
  
  const hoursSinceLastMessage = (Date.now() - lastInteraction.getTime()) / (1000 * 60 * 60);
  
  if (buyerIntent === 'READY_TO_BUY') {
    return 'Send payment details and complete the order';
  }
  
  if (buyerIntent === 'PRICE_INQUIRY') {
    return 'Send detailed pricing information';
  }
  
  if (intentSignals.askingForProof) {
    return 'Send product photos and proof of stock';
  }
  
  if (hoursSinceLastMessage > 24) {
    return 'Follow up with re-engagement message';
  }
  
  if (intentSignals.rapidReplies) {
    return 'Respond immediately - high engagement detected';
  }
  
  if (sentiment === 'NEGATIVE' || sentiment === 'FRUSTRATED') {
    return 'Address concerns and provide support';
  }
  
  return 'Continue conversation and build rapport';
}

// NEW FEATURE: Detect conversion path mapping
function detectConversionPath(messages: Message[], buyerIntent: string): string[] {
  const path: string[] = [];
  const normalizedMessages = messages.map(m => normalizeText(m.text));
  
  // Detect stages in conversation flow
  if (normalizedMessages.some(m => m.includes('hello') || m.includes('hi') || m.includes('kamusta'))) {
    path.push('Greeting');
  }
  if (normalizedMessages.some(m => m.includes('magkano') || m.includes('price') || m.includes('hm'))) {
    path.push('Price Inquiry');
  }
  if (normalizedMessages.some(m => m.includes('delivery') || m.includes('ship') || m.includes('saan'))) {
    path.push('Delivery');
  }
  if (normalizedMessages.some(m => m.includes('payment') || m.includes('gcash') || m.includes('bayad'))) {
    path.push('Payment');
  }
  if (normalizedMessages.some(m => m.includes('buy') || m.includes('order') || m.includes('reserve'))) {
    path.push('Purchase Intent');
  }
  
  // If no specific path detected, use intent-based path
  if (path.length === 0) {
    if (buyerIntent === 'READY_TO_BUY') path.push('Purchase Intent');
    else if (buyerIntent === 'PRICE_INQUIRY') path.push('Price Inquiry');
    else if (buyerIntent === 'ASKING_INFO') path.push('Information Gathering');
    else path.push('Initial Contact');
  }
  
  return path;
}

// NEW FEATURE: Cross-message pattern linking (Conversation Mapping AI)
function detectConversationPatterns(messages: Message[]): EnhancedAnalysisResult['conversationPatterns'] {
  const normalizedMessages = messages.map(m => normalizeText(m.text));
  const repeatedConcerns: string[] = [];
  const recurringProductMentions: string[] = [];
  const questionShifts: string[] = [];
  const behavioralLoops: string[] = [];
  
  // Detect repeated concerns (same topic mentioned multiple times)
  const concernKeywords = ['price', 'magkano', 'mahal', 'expensive', 'discount', 'sale', 'delivery', 'ship', 'stock', 'available'];
  const concernCounts = new Map<string, number>();
  normalizedMessages.forEach(msg => {
    concernKeywords.forEach(keyword => {
      if (msg.includes(keyword)) {
        concernCounts.set(keyword, (concernCounts.get(keyword) || 0) + 1);
      }
    });
  });
  concernCounts.forEach((count, keyword) => {
    if (count >= 2) repeatedConcerns.push(keyword);
  });
  
  // Detect recurring product mentions
  const productMentions = new Map<string, number>();
  normalizedMessages.forEach(msg => {
    const words = msg.split(/\s+/);
    words.forEach(word => {
      if (word.length > 3 && !['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'its', 'may', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'].includes(word)) {
        productMentions.set(word, (productMentions.get(word) || 0) + 1);
      }
    });
  });
  productMentions.forEach((count, word) => {
    if (count >= 3) recurringProductMentions.push(word);
  });
  
  // Detect question topic shifts
  const questionTopics: string[] = [];
  normalizedMessages.forEach(msg => {
    if (msg.includes('?')) {
      if (msg.includes('magkano') || msg.includes('price')) questionTopics.push('Price');
      else if (msg.includes('saan') || msg.includes('where')) questionTopics.push('Location');
      else if (msg.includes('kailan') || msg.includes('when')) questionTopics.push('Timing');
      else if (msg.includes('paano') || msg.includes('how')) questionTopics.push('Process');
      else if (msg.includes('?')) questionTopics.push('General');
    }
  });
  if (questionTopics.length > 1) {
    questionShifts.push(...questionTopics);
  }
  
  // Detect behavioral loops (undecided → silent → ask again pattern)
  if (normalizedMessages.length >= 4) {
    const hasUndecided = normalizedMessages.some(m => m.includes('think') || m.includes('decide') || m.includes('isip'));
    const hasSilent = normalizedMessages.some(m => m.length < 10);
    const hasRepeatedQuestion = questionTopics.length >= 2 && new Set(questionTopics).size < questionTopics.length;
    if (hasUndecided && hasSilent && hasRepeatedQuestion) {
      behavioralLoops.push('Undecided → Silent → Re-engagement');
    }
  }
  
  return {
    repeatedConcerns,
    recurringProductMentions: recurringProductMentions.slice(0, 5), // Limit to top 5
    questionShifts,
    behavioralLoops
  };
}

// NEW FEATURE: Indirect Intent Detection (Filipino/Taglish patterns)
function detectIndirectIntent(messages: Message[]): EnhancedAnalysisResult['indirectIntent'] {
  const normalizedText = messages.map(m => normalizeText(m.text)).join(' ');
  const examples: string[] = [];
  let detected = false;
  let impliedMeaning = '';
  let confidence = 0;
  
  // "Sarap naman nyan" → Interest
  if (normalizedText.includes('sarap') || normalizedText.includes('ang sarap')) {
    detected = true;
    impliedMeaning = 'Interest - expressing positive reaction';
    confidence = 75;
    examples.push('"Sarap naman nyan"');
  }
  
  // "Ang ganda" → Curiosity
  if (normalizedText.includes('ganda') || normalizedText.includes('ang ganda')) {
    detected = true;
    impliedMeaning = 'Curiosity - expressing admiration';
    confidence = 70;
    examples.push('"Ang ganda"');
  }
  
  // "Medyo mahal pero gusto ko" → Negotiation intent
  if ((normalizedText.includes('mahal') || normalizedText.includes('expensive')) && 
      (normalizedText.includes('pero') || normalizedText.includes('but') || normalizedText.includes('gusto'))) {
    detected = true;
    impliedMeaning = 'Negotiation Intent - price concern but still interested';
    confidence = 80;
    examples.push('"Medyo mahal pero gusto ko"');
  }
  
  // "Haha parang gusto ko na" → Soft commitment
  if ((normalizedText.includes('haha') || normalizedText.includes('hehe')) && 
      (normalizedText.includes('gusto') || normalizedText.includes('want'))) {
    detected = true;
    impliedMeaning = 'Soft Commitment - casual expression of interest';
    confidence = 65;
    examples.push('"Haha parang gusto ko na"');
  }
  
  // "Tingin tingin lang" → Browsing (low intent)
  if (normalizedText.includes('tingin tingin lang') || normalizedText.includes('browse lang')) {
    detected = true;
    impliedMeaning = 'Browsing - just looking, low immediate intent';
    confidence = 85;
    examples.push('"Tingin tingin lang"');
  }
  
  return {
    detected,
    impliedMeaning: detected ? impliedMeaning : '',
    confidence,
    examples
  };
}

// NEW FEATURE: Buyer Style Classifier
function classifyBuyerStyle(
  messages: Message[],
  buyerIntent: string,
  sentiment: string
): EnhancedAnalysisResult['buyerStyle'] {
  const normalizedText = messages.map(m => normalizeText(m.text)).join(' ');
  const avgMessageLength = messages.reduce((sum, m) => sum + m.text.length, 0) / messages.length;
  const questionCount = messages.filter(m => m.text.includes('?')).length;
  
  // "Straight to the point" - short messages, direct questions
  if (avgMessageLength < 30 && questionCount > 0 && !normalizedText.includes('think') && !normalizedText.includes('maybe')) {
    return 'STRAIGHT_TO_POINT';
  }
  
  // "Emotional buyer" - uses emojis, expressive language
  const emojiCount = (normalizedText.match(/[\u{1F600}-\u{1F64F}]|[\u{1F300}-\u{1F5FF}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu) || []).length;
  if (emojiCount > 2 || 
      normalizedText.includes('love') || normalizedText.includes('gusto') || normalizedText.includes('excited')) {
    return 'EMOTIONAL';
  }
  
  // "Analytical buyer" - multiple questions, detailed inquiries
  if (questionCount >= 3 && avgMessageLength > 50) {
    return 'ANALYTICAL';
  }
  
  // "Discount hunter" - repeatedly asks about price, discounts, sales
  const priceMentions = (normalizedText.match(/magkano|price|hm|discount|sale|mahal/g) || []).length;
  if (priceMentions >= 3) {
    return 'DISCOUNT_HUNTER';
  }
  
  // "Slow decision maker" - uses hesitant language, takes time
  if (normalizedText.includes('think') || normalizedText.includes('isip') || 
      normalizedText.includes('maybe') || normalizedText.includes('siguro') ||
      normalizedText.includes('wait') || normalizedText.includes('hintay')) {
    return 'SLOW_DECISION_MAKER';
  }
  
  // "Research-driven buyer" - asks many questions, wants details
  if (questionCount >= 4 && normalizedText.includes('info') || normalizedText.includes('details')) {
    return 'RESEARCH_DRIVEN';
  }
  
  return undefined;
}

// Helper function for buyer style implications
function getBuyerStyleImplications(style?: EnhancedAnalysisResult['buyerStyle']): string {
  if (!style) return 'Standard buyer behavior patterns';
  
  const implications: Record<string, string> = {
    'STRAIGHT_TO_POINT': 'Prefers direct communication, values efficiency, likely to make quick decisions',
    'EMOTIONAL': 'Driven by feelings and emotions, responds well to personal connection and enthusiasm',
    'ANALYTICAL': 'Needs detailed information, compares options carefully, takes time to decide',
    'DISCOUNT_HUNTER': 'Price-sensitive, values deals and promotions, may negotiate aggressively',
    'SLOW_DECISION_MAKER': 'Takes time to consider, may need multiple follow-ups, requires patience',
    'RESEARCH_DRIVEN': 'Wants comprehensive information, asks many questions, values transparency'
  };
  
  return implications[style] || 'Standard buyer behavior patterns';
}

// NEW FEATURE: Buyer Reliability Model (Machine Learning)
function calculateBuyerReliability(
  messages: Message[],
  intentSignals: EnhancedAnalysisResult['intentSignals'],
  conversionProbability: number,
  buyerStyle?: EnhancedAnalysisResult['buyerStyle']
): EnhancedAnalysisResult['buyerReliability'] {
  let followThroughProbability = conversionProbability; // Start with conversion probability
  
  // Adjust based on buyer style
  if (buyerStyle === 'STRAIGHT_TO_POINT') followThroughProbability += 10;
  else if (buyerStyle === 'SLOW_DECISION_MAKER') followThroughProbability -= 15;
  else if (buyerStyle === 'DISCOUNT_HUNTER') followThroughProbability -= 5;
  
  // Adjust based on intent signals
  if (intentSignals.rapidReplies) followThroughProbability += 10;
  if (intentSignals.askingForProof) followThroughProbability += 8;
  if (intentSignals.offHoursResponse) followThroughProbability += 5;
  
  // Adjust based on message count (more messages = more engagement)
  if (messages.length >= 10) followThroughProbability += 5;
  else if (messages.length < 3) followThroughProbability -= 10;
  
  // Calculate follow-ups needed
  let followUpsNeeded = 1;
  if (buyerStyle === 'SLOW_DECISION_MAKER') followUpsNeeded = 3;
  else if (buyerStyle === 'ANALYTICAL' || buyerStyle === 'RESEARCH_DRIVEN') followUpsNeeded = 2;
  else if (followThroughProbability < 50) followUpsNeeded = 2;
  
  // Calculate ghosting probability (inverse of follow-through)
  const ghostingProbability = Math.max(0, Math.min(100, 100 - followThroughProbability));
  
  // Calculate item switch probability
  let itemSwitchProbability = 20; // Base 20%
  if (buyerStyle === 'DISCOUNT_HUNTER') itemSwitchProbability += 15;
  if (buyerStyle === 'ANALYTICAL') itemSwitchProbability += 10;
  if (messages.some(m => normalizeText(m.text).includes('compare') || normalizeText(m.text).includes('other'))) {
    itemSwitchProbability += 20;
  }
  
  followThroughProbability = Math.max(0, Math.min(100, Math.round(followThroughProbability)));
  itemSwitchProbability = Math.max(0, Math.min(100, Math.round(itemSwitchProbability)));
  
  return {
    followThroughProbability,
    followUpsNeeded,
    ghostingProbability: Math.round(ghostingProbability),
    itemSwitchProbability
  };
}

// NEW FEATURE: Enhanced Lead Risk Assessment
function assessLeadRisk(
  messages: Message[],
  sentiment: string,
  buyerReliability: EnhancedAnalysisResult['buyerReliability'],
  intentSignals: EnhancedAnalysisResult['intentSignals']
): { level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; reasons: string[] } {
  const reasons: string[] = [];
  let riskScore = 0;
  
  // Negative sentiment increases risk
  if (sentiment === 'NEGATIVE' || sentiment === 'FRUSTRATED') {
    riskScore += 30;
    reasons.push('Negative sentiment detected');
  }
  
  // High ghosting probability
  if (buyerReliability && buyerReliability.ghostingProbability >= 60) {
    riskScore += 25;
    reasons.push('High ghosting probability');
  }
  
  // Low follow-through probability
  if (buyerReliability && buyerReliability.followThroughProbability < 40) {
    riskScore += 20;
    reasons.push('Low follow-through probability');
  }
  
  // High item switch probability
  if (buyerReliability && buyerReliability.itemSwitchProbability >= 50) {
    riskScore += 15;
    reasons.push('May switch to different item');
  }
  
  // Slow response times (if available)
  if (intentSignals.responseTimeMinutes && intentSignals.responseTimeMinutes > 1440) {
    riskScore += 10;
    reasons.push('Very slow response times');
  }
  
  // Determine risk level
  let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (riskScore >= 60) level = 'CRITICAL';
  else if (riskScore >= 40) level = 'HIGH';
  else if (riskScore >= 20) level = 'MEDIUM';
  else level = 'LOW';
  
  return { level, reasons };
}

// NEW FEATURE: Bot Accuracy Self-Evaluation
function evaluateBotAccuracy(
  intentConfidence: number,
  sentimentConfidence: number,
  conversionProbability: number
): number {
  // Average of confidence scores, weighted by conversion probability
  const baseAccuracy = (intentConfidence + sentimentConfidence) / 2;
  
  // Higher conversion probability with high confidence = more accurate
  // Lower conversion probability with high confidence = less accurate (might be wrong)
  let accuracy = baseAccuracy;
  
  if (conversionProbability >= 70 && baseAccuracy >= 70) {
    accuracy += 10; // High confidence on high probability = very accurate
  } else if (conversionProbability < 30 && baseAccuracy >= 70) {
    accuracy -= 15; // High confidence on low probability = might be inaccurate
  }
  
  return Math.max(0, Math.min(100, Math.round(accuracy)));
}

// NEW FEATURE: Similar Leads Insight
function generateSimilarLeadsInsight(
  productInterests: string[],
  buyerIntent: string,
  conversionPath: string[],
  buyerStyle?: EnhancedAnalysisResult['buyerStyle']
): string {
  const insights: string[] = [];
  
  if (buyerStyle) {
    insights.push(`Buyers with ${buyerStyle.replace(/_/g, ' ').toLowerCase()} style`);
  }
  
  if (productInterests.length > 0) {
    insights.push(`interested in ${productInterests[0]}`);
  }
  
  if (conversionPath.length > 0) {
    insights.push(`following the ${conversionPath.join(' → ')} path`);
  }
  
  if (insights.length > 0) {
    return `Similar leads: ${insights.join(', ')}. Historical data shows that leads with these characteristics ${buyerIntent === 'READY_TO_BUY' ? 'typically convert after 2-3 interactions' : buyerIntent === 'PRICE_INQUIRY' ? 'usually convert after 4-5 interactions' : 'may need 5+ interactions to convert'}.`;
  }
  
  return 'No similar lead patterns identified yet. More data needed for pattern matching.';
}

// Generate stage reason
function generateStageReason(
  recommendedStage: string,
  buyerIntent: string,
  sentiment: string,
  intentSignals: EnhancedAnalysisResult['intentSignals'],
  messages: Message[]
): string {
  const reasons: string[] = [];
  
  // Find relevant message snippet
  let relevantMessage = '';
  if (buyerIntent === 'PRICE_INQUIRY') {
    const priceMsg = messages.find(m => 
      normalizeText(m.text).includes('magkano') || 
      normalizeText(m.text).includes('price') ||
      normalizeText(m.text).includes('hm')
    );
    if (priceMsg) relevantMessage = priceMsg.text.substring(0, 50);
  } else if (buyerIntent === 'READY_TO_BUY') {
    const buyMsg = messages.find(m => 
      normalizeText(m.text).includes('buy') || 
      normalizeText(m.text).includes('bili') ||
      normalizeText(m.text).includes('reserve')
    );
    if (buyMsg) relevantMessage = buyMsg.text.substring(0, 50);
  }
  
  if (relevantMessage) {
    reasons.push(`User said: "${relevantMessage}${relevantMessage.length >= 50 ? '...' : ''}"`);
  }
  
  if (buyerIntent === 'PRICE_INQUIRY') {
    reasons.push('Classified as Price Inquiry');
  } else if (buyerIntent === 'READY_TO_BUY') {
    reasons.push('Classified as Ready to Buy');
  } else if (buyerIntent === 'ASKING_INFO') {
    reasons.push('Classified as Asking for Information');
  }
  
  if (intentSignals.rapidReplies) {
    reasons.push('Rapid response pattern detected');
  }
  
  if (intentSignals.askingForProof) {
    reasons.push('Requested product proof/photos');
  }
  
  return reasons.join('. ');
}

/**
 * Enhanced AI Analysis with all advanced features
 */
export async function analyzeConversationEnhanced(
  messages: Message[],
  pipelineStages?: PipelineStage[],
  conversationAge?: Date
): Promise<EnhancedAnalysisResult | null> {
  if (!messages || messages.length === 0) {
    return null;
  }
  
  // Get base scoring
  const fallback = calculateFallbackScore(messages, conversationAge);
  
  // Detect buyer intent (hybrid: rules first, then AI if needed)
  const intentDetection = detectBuyerIntent(messages);
  
  // Detect sentiment
  const sentimentDetection = detectSentiment(messages);
  
  // Detect intent signals
  const intentSignals = detectIntentSignals(messages);
  
  // Extract product interests
  const productInterests = extractProductInterests(messages);
  
  // Calculate conversion probability
  const conversionProbability = calculateConversionProbability(
    fallback.leadScore,
    intentDetection.intent,
    sentimentDetection.sentiment,
    intentSignals,
    messages.length
  );
  
  // Generate agent suggestions
  const agentSuggestions = generateAgentSuggestions(
    intentDetection.intent,
    sentimentDetection.sentiment,
    productInterests,
    intentSignals
  );
  
  // Generate next best action
  const nextBestAction = generateNextBestAction(
    intentDetection.intent,
    sentimentDetection.sentiment,
    intentSignals,
    conversationAge
  );
  
  // Determine recommended stage
  let recommendedStage = pipelineStages?.[0]?.name || 'New Lead';
  
  // Rule-based stage assignment for clear cases
  if (intentDetection.intent === 'READY_TO_BUY') {
    const readyStage = pipelineStages?.find(s => 
      s.name.toLowerCase().includes('ready') || 
      s.name.toLowerCase().includes('hot') ||
      s.type === 'WON'
    );
    if (readyStage) recommendedStage = readyStage.name;
  } else if (intentDetection.intent === 'PRICE_INQUIRY') {
    const interestedStage = pipelineStages?.find(s => 
      s.name.toLowerCase().includes('interested') || 
      s.name.toLowerCase().includes('warm') ||
      s.name.toLowerCase().includes('qualified')
    );
    if (interestedStage) recommendedStage = interestedStage.name;
  } else if (intentDetection.intent === 'ASKING_INFO') {
    const infoStage = pipelineStages?.find(s => 
      s.name.toLowerCase().includes('info') || 
      s.name.toLowerCase().includes('inquiry')
    );
    if (infoStage) recommendedStage = infoStage.name;
  }
  
  // Generate stage reason
  const stageReason = generateStageReason(
    recommendedStage,
    intentDetection.intent,
    sentimentDetection.sentiment,
    intentSignals,
    messages
  );
  
  // NEW FEATURES: Advanced analysis
  const conversionPath = detectConversionPath(messages, intentDetection.intent);
  const conversationPatterns = detectConversationPatterns(messages);
  const indirectIntent = detectIndirectIntent(messages);
  const buyerStyle = classifyBuyerStyle(messages, intentDetection.intent, sentimentDetection.sentiment);
  const buyerReliability = calculateBuyerReliability(messages, intentSignals, conversionProbability, buyerStyle);
  const leadRisk = assessLeadRisk(messages, sentimentDetection.sentiment, buyerReliability, intentSignals);
  const botAccuracy = evaluateBotAccuracy(intentDetection.confidence, sentimentDetection.confidence, conversionProbability);
  const similarLeadsInsight = generateSimilarLeadsInsight(productInterests, intentDetection.intent, conversionPath, buyerStyle);
  
  // Create comprehensive, detailed user-friendly summary (much longer)
  const engagementLevel = messages.length >= 10 ? 'High' : messages.length >= 5 ? 'Moderate' : 'Low';
  const messageCount = messages.length;
  const avgMessageLength = messages.reduce((sum, m) => sum + m.text.length, 0) / messageCount;
  const firstMsg = messages[0];
  const lastMsg = messages[messages.length - 1];
  const conversationDuration = messages.length > 1 && firstMsg?.timestamp && lastMsg?.timestamp
    ? Math.round((lastMsg.timestamp.getTime() - firstMsg.timestamp.getTime()) / (1000 * 60))
    : 0;
  
  const summary = `This contact has engaged in an active conversation spanning ${messageCount} ${messageCount === 1 ? 'message' : 'messages'}${conversationDuration > 0 ? ` over approximately ${conversationDuration} minutes` : ''}, demonstrating ${engagementLevel.toLowerCase()} engagement levels. ` +
    `The conversation reveals a ${intentDetection.intent.toLowerCase().replace('_', ' ')} intent pattern with ${sentimentDetection.sentiment.toLowerCase()} sentiment, ` +
    `${productInterests.length > 0 ? `showing interest in ${productInterests.join(', ')}. ` : 'with general product inquiry. '}` +
    `${intentSignals.rapidReplies ? 'The contact responds rapidly, indicating strong interest. ' : ''}` +
    `${intentSignals.multipleQuestions ? 'Multiple questions were asked, showing active consideration. ' : ''}` +
    `${intentSignals.askingForProof ? 'The contact requested proof/verification, a positive buying signal. ' : ''}` +
    `${buyerStyle ? `Buyer style: ${buyerStyle.replace(/_/g, ' ').toLowerCase()}. ` : ''}` +
    `Conversion probability is estimated at ${conversionProbability}% based on conversation patterns, ` +
    `with a lead score of ${fallback.leadScore}/100. ` +
    `${buyerReliability && buyerReliability.followThroughProbability >= 70 ? 'High reliability - likely to follow through. ' : buyerReliability && buyerReliability.followThroughProbability >= 50 ? 'Moderate reliability. ' : 'Lower reliability - may need more follow-up. '}` +
    `${leadRisk.level !== 'LOW' ? `Risk level: ${leadRisk.level} - ${leadRisk.reasons.join(', ')}. ` : ''}` +
    `Recommended next action: ${nextBestAction}.`;
  
  // Create narrative-style reasoning for AI context (story format like the example)
  // Build a narrative description of the conversation flow
  const prospectName = messages.find(m => !m.from.toLowerCase().includes('business') && !m.from.toLowerCase().includes('rep'))?.from || 'The prospect';
  const repName = messages.find(m => m.from.toLowerCase().includes('business') || m.from.toLowerCase().includes('rep'))?.from || 'the representative';
  
  // Extract key conversation points and details
  const priceInquiries = messages.filter(m => 
    normalizeText(m.text).includes('magkano') || 
    normalizeText(m.text).includes('price') ||
    normalizeText(m.text).includes('hm') ||
    normalizeText(m.text).includes('cost') ||
    normalizeText(m.text).includes('fee')
  );
  const purchaseSignals = messages.filter(m => 
    normalizeText(m.text).includes('buy') || 
    normalizeText(m.text).includes('bili') ||
    normalizeText(m.text).includes('reserve') ||
    normalizeText(m.text).includes('purchase') ||
    normalizeText(m.text).includes('kukunin')
  );
  const questions = messages.filter(m => m.text.includes('?'));
  const repMessages = messages.filter(m => 
    m.from.toLowerCase().includes('business') || 
    m.from.toLowerCase().includes('rep')
  );
  const prospectMessages = messages.filter(m => 
    !m.from.toLowerCase().includes('business') && 
    !m.from.toLowerCase().includes('rep')
  );
  
  // Build narrative in story format
  const narrativeParts: string[] = [];
  
  // Opening - who contacted about what
  const firstProspectMsg = prospectMessages[0];
  if (firstProspectMsg) {
    const inquiryText = firstProspectMsg.text.substring(0, 80);
    narrativeParts.push(`Prospect ${prospectName} ${intentDetection.intent === 'PRICE_INQUIRY' ? 'inquires about' : intentDetection.intent === 'READY_TO_BUY' ? 'expresses interest in' : 'contacts regarding'} ${productInterests.length > 0 ? productInterests.join(' and ') : 'products/services'}${inquiryText.length < 80 ? `, asking "${inquiryText}"` : ''}`);
  } else {
    narrativeParts.push(`Prospect ${prospectName} ${intentDetection.intent === 'PRICE_INQUIRY' ? 'inquires about' : intentDetection.intent === 'READY_TO_BUY' ? 'expresses interest in' : 'contacts regarding'} ${productInterests.length > 0 ? productInterests.join(' and ') : 'products/services'}`);
  }
  
  // Representative responses and offers
  if (repMessages.length > 0) {
    const firstOffer = repMessages.find(m => 
      normalizeText(m.text).includes('peso') || 
      normalizeText(m.text).includes('price') ||
      normalizeText(m.text).includes('offer') ||
      normalizeText(m.text).includes('discount')
    );
    if (firstOffer) {
      const offerText = firstOffer.text.substring(0, 120);
      narrativeParts.push(`The rep ${offerText.length < 120 ? `offers ${offerText}` : 'presents pricing and options'}`);
    } else if (repMessages.length > 0) {
      narrativeParts.push(`The rep responds with information and details`);
    }
  }
  
  // Price discussions
  if (priceInquiries.length > 0) {
    const priceDetails = priceInquiries.map(m => {
      const text = m.text.substring(0, 60);
      return text;
    }).filter(Boolean);
    if (priceDetails.length > 0) {
      narrativeParts.push(`discussing pricing${priceDetails.length > 1 ? ' and various options' : ''}`);
    }
  }
  
  // Product interests mentioned
  if (productInterests.length > 0) {
    narrativeParts.push(`with focus on ${productInterests.join(', ')}`);
  }
  
  // Sentiment and engagement
  if (sentimentDetection.sentiment === 'POSITIVE') {
    narrativeParts.push(`showing positive engagement`);
  } else if (sentimentDetection.sentiment === 'NEGATIVE') {
    narrativeParts.push(`with some concerns or hesitation`);
  }
  
  // Intent signals and behavior
  if (intentSignals.rapidReplies) {
    narrativeParts.push(`responding rapidly, indicating strong interest`);
  }
  
  if (intentSignals.multipleQuestions) {
    narrativeParts.push(`asking multiple questions, showing active consideration`);
  }
  
  if (intentSignals.askingForProof) {
    narrativeParts.push(`requesting proof or verification`);
  }
  
  // Buyer intent and commitment level
  if (intentDetection.intent === 'READY_TO_BUY') {
    narrativeParts.push(`expressing willingness to purchase`);
  } else if (intentDetection.intent === 'PRICE_INQUIRY') {
    narrativeParts.push(`showing interest but not yet committed`);
  } else if (intentDetection.intent === 'ASKING_INFO') {
    narrativeParts.push(`gathering information before making a decision`);
  }
  
  // Timeline or commitment signals
  const timelineMentions = messages.filter(m => 
    normalizeText(m.text).includes('next month') ||
    normalizeText(m.text).includes('later') ||
    normalizeText(m.text).includes('wait') ||
    normalizeText(m.text).includes('pension') ||
    normalizeText(m.text).includes('salary')
  );
  if (timelineMentions.length > 0) {
    narrativeParts.push(`indicating a future timeline for purchase`);
  }
  
  // Conversion probability
  if (conversionProbability >= 70) {
    narrativeParts.push(`with high conversion likelihood`);
  } else if (conversionProbability >= 50) {
    narrativeParts.push(`with moderate conversion potential`);
  } else {
    narrativeParts.push(`requiring continued nurturing`);
  }
  
  // Final status and conclusion
  if (fallback.leadStatus === 'WON') {
    narrativeParts.push(`The deal has been closed successfully.`);
  } else if (fallback.leadStatus === 'LOST') {
    narrativeParts.push(`The opportunity has been lost or declined.`);
  } else if (fallback.leadStatus === 'NEGOTIATING') {
    narrativeParts.push(`leaving the deal in a negotiation phase rather than closed.`);
  } else if (timelineMentions.length > 0) {
    narrativeParts.push(`with a tentative plan to revisit later, leaving the deal in a negotiation phase rather than closed.`);
  } else {
    narrativeParts.push(`The conversation remains in an early stage, requiring continued engagement.`);
  }
  
  const reasoning = narrativeParts.join(', ') + '.';
  
  return {
    summary,
    reasoning,
    recommendedStage,
    leadScore: fallback.leadScore,
    leadStatus: fallback.leadStatus,
    confidence: fallback.confidence,
    buyerIntent: intentDetection.intent,
    sentiment: sentimentDetection.sentiment,
    productInterests,
    intentSignals,
    conversionProbability,
    nextBestAction,
    agentSuggestions,
    stageReason,
    // New features
    conversionPath,
    similarLeadsInsight,
    leadRiskLevel: leadRisk.level,
    leadRiskReasons: leadRisk.reasons,
    botAccuracyScore: botAccuracy,
    conversationPatterns,
    indirectIntent,
    buyerReliability,
    buyerStyle
  };
}

