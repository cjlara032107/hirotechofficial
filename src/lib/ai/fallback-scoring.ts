/**
 * Fallback Scoring System
 * Provides intelligent lead scores when AI analysis fails
 * Prevents contacts from having 0 scores
 */

interface Message {
  from: string;
  text: string;
  timestamp?: Date;
}

interface FallbackScore {
  leadScore: number;
  leadStatus: string;
  reasoning: string;
  confidence: number;
}

/**
 * Calculate fallback lead score based on conversation characteristics
 * This prevents contacts from having 0 scores when AI fails
 */
export function calculateFallbackScore(
  messages: Message[],
  conversationAge?: Date
): FallbackScore {
  
  if (!messages || messages.length === 0) {
    return {
      leadScore: 15, // Minimum score for contacts with no conversation
      leadStatus: 'NEW',
      reasoning: 'No conversation data available - assigned minimum score',
      confidence: 50
    };
  }

  let score = 20; // Base score (better than 0)
  const factors: string[] = [];

  // Factor 1: Message count (shows engagement)
  const messageCount = messages.length;
  if (messageCount >= 20) {
    score += 25;
    factors.push('high message count (20+)');
  } else if (messageCount >= 10) {
    score += 15;
    factors.push('moderate message count (10-19)');
  } else if (messageCount >= 5) {
    score += 10;
    factors.push('some messages (5-9)');
  } else {
    score += 5;
    factors.push('few messages (<5)');
  }

  // Factor 2: Message length (shows serious interest)
  const avgMessageLength = messages.reduce((sum, msg) => sum + msg.text.length, 0) / messages.length;
  if (avgMessageLength > 100) {
    score += 15;
    factors.push('detailed messages (avg 100+ chars)');
  } else if (avgMessageLength > 50) {
    score += 10;
    factors.push('moderate messages (avg 50-100 chars)');
  } else {
    score += 5;
    factors.push('short messages');
  }

  // Factor 3: Buying signals (keyword detection)
  const conversationText = messages.map(m => m.text.toLowerCase()).join(' ');
  const buyingKeywords = [
    'price', 'cost', 'buy', 'purchase', 'order',
    'how much', 'available', 'delivery', 'shipping',
    'payment', 'invoice', 'quote', 'interested',
    'need', 'want', 'looking for', 'urgent'
  ];
  
  const keywordMatches = buyingKeywords.filter(keyword => 
    conversationText.includes(keyword)
  ).length;

  if (keywordMatches >= 5) {
    score += 20;
    factors.push('strong buying signals');
  } else if (keywordMatches >= 3) {
    score += 12;
    factors.push('some buying signals');
  } else if (keywordMatches >= 1) {
    score += 6;
    factors.push('minimal buying signals');
  }

  // Factor 4: Response pattern (back and forth = engaged)
  const senderChanges = messages.slice(1).filter((msg, i) => 
    msg.from !== messages[i].from
  ).length;
  
  const responseRate = senderChanges / Math.max(messages.length - 1, 1);
  if (responseRate > 0.7) {
    score += 15;
    factors.push('active conversation');
  } else if (responseRate > 0.4) {
    score += 8;
    factors.push('moderate back-and-forth');
  }

  // Factor 5: Recency (if available)
  if (conversationAge) {
    const daysSinceLastMessage = Math.floor(
      (Date.now() - conversationAge.getTime()) / (1000 * 60 * 60 * 24)
    );
    
    if (daysSinceLastMessage <= 1) {
      score += 10;
      factors.push('very recent activity');
    } else if (daysSinceLastMessage <= 7) {
      score += 5;
      factors.push('recent activity');
    } else if (daysSinceLastMessage > 30) {
      score -= 10;
      factors.push('old conversation');
    }
  }

  // Cap score at 80 (reserve 81-100 for AI with high confidence)
  score = Math.min(Math.max(score, 15), 80);

  // Determine lead status based on score
  let leadStatus: string;
  if (score >= 60) {
    leadStatus = 'QUALIFIED';
  } else if (score >= 40) {
    leadStatus = 'CONTACTED';
  } else {
    leadStatus = 'NEW';
  }

  // Create user-friendly reasoning without technical details
  const userFriendlyFactors: string[] = [];
  
  // Convert technical factors to natural language
  if (messageCount >= 20) {
    userFriendlyFactors.push('extensive conversation');
  } else if (messageCount >= 10) {
    userFriendlyFactors.push('active conversation');
  } else if (messageCount >= 5) {
    userFriendlyFactors.push('moderate conversation');
  } else {
    userFriendlyFactors.push('brief conversation');
  }
  
  if (avgMessageLength > 100) {
    userFriendlyFactors.push('detailed messages');
  } else if (avgMessageLength > 50) {
    userFriendlyFactors.push('moderate message length');
  }
  
  if (keywordMatches >= 5) {
    userFriendlyFactors.push('strong buying interest');
  } else if (keywordMatches >= 3) {
    userFriendlyFactors.push('shows interest');
  } else if (keywordMatches >= 1) {
    userFriendlyFactors.push('some interest');
  }
  
  if (responseRate > 0.7) {
    userFriendlyFactors.push('highly engaged');
  } else if (responseRate > 0.4) {
    userFriendlyFactors.push('responsive');
  }
  
  if (conversationAge) {
    const daysSinceLastMessage = Math.floor(
      (Date.now() - conversationAge.getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSinceLastMessage <= 1) {
      userFriendlyFactors.push('very recent activity');
    } else if (daysSinceLastMessage <= 7) {
      userFriendlyFactors.push('recent activity');
    } else if (daysSinceLastMessage > 30) {
      userFriendlyFactors.push('inactive');
    }
  }

  // Create detailed natural language summary (much more comprehensive)
  let reasoning: string;
  
  if (userFriendlyFactors.length > 0) {
    // Build a detailed narrative instead of just joining factors
    const parts: string[] = [];
    
    // Conversation overview
    if (messageCount >= 20) {
      parts.push(`This contact has engaged in an extensive conversation with ${messageCount} messages`);
    } else if (messageCount >= 10) {
      parts.push(`This contact has engaged in an active conversation with ${messageCount} messages`);
    } else if (messageCount >= 5) {
      parts.push(`This contact has engaged in a moderate conversation with ${messageCount} messages`);
    } else {
      parts.push(`This contact has engaged in a brief conversation with ${messageCount} messages`);
    }
    
    // Message quality
    if (avgMessageLength > 100) {
      parts.push(`with detailed, thoughtful messages averaging ${Math.round(avgMessageLength)} characters`);
    } else if (avgMessageLength > 50) {
      parts.push(`with moderate-length messages averaging ${Math.round(avgMessageLength)} characters`);
    } else {
      parts.push(`with concise messages averaging ${Math.round(avgMessageLength)} characters`);
    }
    
    // Buying signals
    if (keywordMatches >= 5) {
      parts.push(`showing strong buying interest with multiple purchase-related keywords mentioned`);
    } else if (keywordMatches >= 3) {
      parts.push(`showing clear interest with several purchase-related keywords mentioned`);
    } else if (keywordMatches >= 1) {
      parts.push(`showing some interest with purchase-related keywords mentioned`);
    }
    
    // Engagement pattern
    if (responseRate > 0.7) {
      parts.push(`demonstrating high engagement with active back-and-forth communication`);
    } else if (responseRate > 0.4) {
      parts.push(`demonstrating moderate engagement with some back-and-forth communication`);
    }
    
    // Recency
    if (conversationAge) {
      const daysSinceLastMessage = Math.floor(
        (Date.now() - conversationAge.getTime()) / (1000 * 60 * 60 * 24)
      );
      if (daysSinceLastMessage <= 1) {
        parts.push(`with very recent activity (within the last day)`);
      } else if (daysSinceLastMessage <= 7) {
        parts.push(`with recent activity (within the last week)`);
      } else if (daysSinceLastMessage > 30) {
        parts.push(`though the conversation is older (${daysSinceLastMessage} days ago)`);
      }
    }
    
    // Lead score context
    if (score >= 60) {
      parts.push(`indicating a qualified lead with strong potential`);
    } else if (score >= 40) {
      parts.push(`indicating a contacted lead with moderate potential`);
    } else {
      parts.push(`indicating a new lead requiring further engagement`);
    }
    
    reasoning = parts.join(', ') + '.';
  } else {
    reasoning = 'Limited conversation data available. This contact has minimal interaction history, requiring further engagement to assess their interest and potential.';
  }

  return {
    leadScore: score,
    leadStatus,
    reasoning,
    confidence: 60 // Lower confidence than AI
  };
}

/**
 * Check if a score looks like it might be a failed analysis (0 or suspiciously low)
 */
export function isLowQualityScore(score: number, hasMessages: boolean): boolean {
  // 0 score is always low quality
  if (score === 0) return true;
  
  // Very low score with messages suggests failed analysis
  if (hasMessages && score < 15) return true;
  
  return false;
}

/**
 * Enhance an existing score if it seems too low
 */
export function enhanceLowScore(
  currentScore: number,
  messages: Message[],
  conversationAge?: Date
): number {
  if (!isLowQualityScore(currentScore, messages.length > 0)) {
    return currentScore;
  }

  const fallback = calculateFallbackScore(messages, conversationAge);
  
  // Use the higher of current and fallback
  return Math.max(currentScore, fallback.leadScore);
}

