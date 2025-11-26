interface Message {
  from: string;
  text: string;
  timestamp?: Date;
  isFromBusiness?: boolean;
}

interface BestContactTime {
  dayOfWeek: string; // Monday, Tuesday, etc.
  timeRange: string; // e.g., "09:00-11:00", "14:00-16:00"
  confidence: number; // 0-100
  averageReplyTime?: number; // in minutes
  messageCount?: number; // number of messages used for this calculation
}

interface ReplyTimeAnalysis {
  bestContactTimes: BestContactTime[];
  averageReplyTime: number; // overall average in minutes
  fastestReplyTime: number; // fastest reply in minutes
  slowestReplyTime: number; // slowest reply in minutes
  totalMessagesAnalyzed: number;
  timezone?: string;
}

/**
 * Machine Learning-Style Algorithm for Best Contact Times
 * Uses weighted features, pattern recognition, and predictive modeling
 */
export function analyzeReplyTimes(
  messages: Message[],
  businessSenderId?: string
): ReplyTimeAnalysis | null {
  if (!messages || messages.length < 2) {
    return null;
  }

  // Identify which messages are from the contact (not from business)
  const contactMessages: Array<{ timestamp: Date; text: string }> = [];
  const businessMessages: Array<{ timestamp: Date; text: string }> = [];

  for (const msg of messages) {
    if (!msg.timestamp) continue;

    const isFromBusiness = businessSenderId 
      ? msg.from === businessSenderId || msg.from.includes('Page') || msg.from.includes('Business')
      : msg.isFromBusiness ?? false;

    if (isFromBusiness) {
      businessMessages.push({ timestamp: msg.timestamp, text: msg.text });
    } else {
      contactMessages.push({ timestamp: msg.timestamp, text: msg.text });
    }
  }

  if (contactMessages.length === 0 || businessMessages.length === 0) {
    return null;
  }

  // Calculate reply times with enhanced features
  const replyDataPoints: Array<{
    replyTimeMinutes: number;
    dayOfWeek: string;
    dayOfWeekNum: number; // 0-6 for ML features
    hour: number;
    minute: number;
    businessMessageTime: Date;
    contactReplyTime: Date;
    recencyWeight: number; // Exponential decay based on how recent
    messageLength: number; // Length of business message (feature)
    isWeekend: boolean;
    timeOfDay: 'morning' | 'afternoon' | 'evening' | 'night'; // Categorical feature
  }> = [];

  // Sort messages by timestamp
  const allMessages = [
    ...businessMessages.map(m => ({ ...m, isBusiness: true })),
    ...contactMessages.map(m => ({ ...m, isBusiness: false }))
  ].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  const now = new Date();
  const maxAgeDays = 30; // Consider messages up to 30 days old
  const decayFactor = 0.95; // Exponential decay per day

  // Find pairs: business message followed by contact reply
  for (let i = 0; i < allMessages.length - 1; i++) {
    const current = allMessages[i];
    const next = allMessages[i + 1];

    if (current.isBusiness && !next.isBusiness) {
      const replyTimeMs = next.timestamp.getTime() - current.timestamp.getTime();
      const replyTimeMinutes = replyTimeMs / (1000 * 60);

      // Only consider replies within reasonable time (up to 7 days)
      if (replyTimeMinutes > 0 && replyTimeMinutes <= 7 * 24 * 60) {
        const daysSince = (now.getTime() - next.timestamp.getTime()) / (1000 * 60 * 60 * 24);
        
        // Skip if too old
        if (daysSince > maxAgeDays) continue;

        // Calculate recency weight (exponential decay)
        const recencyWeight = Math.pow(decayFactor, daysSince);

        const dayOfWeek = getDayOfWeek(next.timestamp);
        const dayOfWeekNum = next.timestamp.getDay();
        const hour = next.timestamp.getHours();
        const minute = next.timestamp.getMinutes();
        const isWeekend = dayOfWeekNum === 0 || dayOfWeekNum === 6;

        // Categorize time of day
        let timeOfDay: 'morning' | 'afternoon' | 'evening' | 'night';
        if (hour >= 5 && hour < 12) timeOfDay = 'morning';
        else if (hour >= 12 && hour < 17) timeOfDay = 'afternoon';
        else if (hour >= 17 && hour < 22) timeOfDay = 'evening';
        else timeOfDay = 'night';

        replyDataPoints.push({
          replyTimeMinutes,
          dayOfWeek,
          dayOfWeekNum,
          hour,
          minute,
          businessMessageTime: current.timestamp,
          contactReplyTime: next.timestamp,
          recencyWeight,
          messageLength: current.text.length,
          isWeekend,
          timeOfDay,
        });
      }
    }
  }

  if (replyDataPoints.length === 0) {
    return null;
  }

  // Calculate overall statistics
  const allReplyTimes = replyDataPoints.map(r => r.replyTimeMinutes);
  const averageReplyTime = allReplyTimes.reduce((a, b) => a + b, 0) / allReplyTimes.length;
  const fastestReplyTime = Math.min(...allReplyTimes);
  const slowestReplyTime = Math.max(...allReplyTimes);

  // ML Feature Engineering: Create time slots with weighted scoring
  // Group by day of week and 2-hour time slots for better pattern recognition
  interface TimeSlotFeatures {
    replyTimes: number[];
    weights: number[];
    messageCount: number;
    avgReplyTime: number;
    weightedAvgReplyTime: number;
    variance: number;
    consistency: number;
    recencyScore: number;
    frequencyScore: number;
    patternStrength: number;
  }

  const timeSlots = new Map<string, TimeSlotFeatures>();

  for (const dataPoint of replyDataPoints) {
    // Create 2-hour time slots (e.g., 9-11, 11-13, etc.)
    const slotStart = Math.floor(dataPoint.hour / 2) * 2;
    const slotEnd = slotStart + 2;
    const key = `${dataPoint.dayOfWeek}-${slotStart}-${slotEnd}`;

    if (!timeSlots.has(key)) {
      timeSlots.set(key, {
        replyTimes: [],
        weights: [],
        messageCount: 0,
        avgReplyTime: 0,
        weightedAvgReplyTime: 0,
        variance: 0,
        consistency: 0,
        recencyScore: 0,
        frequencyScore: 0,
        patternStrength: 0,
      });
    }

    const slot = timeSlots.get(key)!;
    slot.replyTimes.push(dataPoint.replyTimeMinutes);
    slot.weights.push(dataPoint.recencyWeight);
    slot.messageCount++;
  }

  // Calculate ML features for each time slot
  for (const [key, slot] of timeSlots.entries()) {
    // Weighted average (recent replies weighted more)
    const totalWeight = slot.weights.reduce((a, b) => a + b, 0);
    slot.weightedAvgReplyTime = slot.replyTimes.reduce((sum, time, idx) => 
      sum + (time * slot.weights[idx]), 0) / totalWeight;

    // Simple average
    slot.avgReplyTime = slot.replyTimes.reduce((a, b) => a + b, 0) / slot.replyTimes.length;

    // Variance and consistency (lower variance = more consistent = better)
    const mean = slot.avgReplyTime;
    slot.variance = slot.replyTimes.reduce((sum, time) => 
      sum + Math.pow(time - mean, 2), 0) / slot.replyTimes.length;
    slot.consistency = Math.max(0, 100 - (Math.sqrt(slot.variance) / mean) * 20);

    // Recency score (how recent are the interactions in this slot)
    slot.recencyScore = (slot.weights.reduce((a, b) => a + b, 0) / slot.messageCount) * 100;

    // Frequency score (more messages = stronger pattern)
    slot.frequencyScore = Math.min(100, (slot.messageCount / replyDataPoints.length) * 200);

    // Pattern strength: composite score combining multiple factors
    // Factors: fast reply time, high consistency, high recency, high frequency
    const speedScore = Math.max(0, 100 - (slot.weightedAvgReplyTime / averageReplyTime) * 50);
    slot.patternStrength = (
      speedScore * 0.35 +           // 35% weight on reply speed
      slot.consistency * 0.25 +      // 25% weight on consistency
      slot.recencyScore * 0.20 +     // 20% weight on recency
      slot.frequencyScore * 0.20    // 20% weight on frequency
    );
  }

  // Generate best contact times with ML scoring
  const bestContactTimes: BestContactTime[] = [];

  for (const [key, slot] of timeSlots.entries()) {
    const [dayOfWeek, startHourStr, endHourStr] = key.split('-');
    const startHour = parseInt(startHourStr, 10);
    const endHour = parseInt(endHourStr, 10);

    // Format time range
    const startTime = `${String(startHour).padStart(2, '0')}:00`;
    const endTime = `${String(endHour).padStart(2, '0')}:00`;
    const timeRange = `${startTime}-${endTime}`;

    // Confidence score: combination of pattern strength and sample size
    const sampleSizeBonus = Math.min(30, slot.messageCount * 5); // Max 30 points for sample size
    const confidence = Math.round(Math.min(100, slot.patternStrength + sampleSizeBonus));

    bestContactTimes.push({
      dayOfWeek,
      timeRange,
      confidence,
      averageReplyTime: Math.round(slot.weightedAvgReplyTime), // Use weighted average
      messageCount: slot.messageCount,
    });
  }

  // Advanced sorting: prioritize by ML score (pattern strength + confidence)
  bestContactTimes.sort((a, b) => {
    // Primary: confidence (ML score)
    if (b.confidence !== a.confidence) {
      return b.confidence - a.confidence;
    }
    // Secondary: average reply time (faster is better)
    if (a.averageReplyTime !== b.averageReplyTime) {
      return a.averageReplyTime! - b.averageReplyTime!;
    }
    // Tertiary: message count (more samples = more reliable)
    return b.messageCount! - a.messageCount!;
  });

  // Take top 10-15 best times (multiple estimates)
  const topTimes = bestContactTimes.slice(0, 15);

  return {
    bestContactTimes: topTimes,
    averageReplyTime: Math.round(averageReplyTime),
    fastestReplyTime: Math.round(fastestReplyTime),
    slowestReplyTime: Math.round(slowestReplyTime),
    totalMessagesAnalyzed: replyDataPoints.length,
  };
}

/**
 * Get day of week name from date
 */
function getDayOfWeek(date: Date): string {
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  return days[date.getDay()];
}

/**
 * Enhanced analysis using AI to provide additional insights
 */
export async function analyzeReplyTimesWithAI(
  messages: Message[],
  replyTimeAnalysis: ReplyTimeAnalysis,
  businessSenderId?: string
): Promise<ReplyTimeAnalysis> {
  try {
    // Use AI to provide additional context and recommendations
    // This can be enhanced later with actual AI integration
    // For now, we'll use the statistical analysis
    
    // Add AI-generated insights if needed
    return replyTimeAnalysis;
  } catch (error) {
    console.error('[Reply Time Analyzer] AI analysis failed:', error);
    return replyTimeAnalysis; // Return statistical analysis as fallback
  }
}

