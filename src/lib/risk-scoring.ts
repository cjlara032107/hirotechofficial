/**
 * Risk Scoring System for Contact Validation
 * Calculates risk scores for contacts during sync (background, non-blocking)
 */

interface RiskFactors {
  // Data quality factors
  hasValidName: boolean;
  hasProfilePic: boolean;
  hasValidLocale: boolean;
  
  // Interaction factors
  messageCount: number;
  conversationAge: number; // days since first message
  lastInteractionAge: number; // days since last interaction
  
  // Pattern detection
  suspiciousPatterns: string[];
  hasContactInfo: boolean;
  
  // AI analysis factors (if available)
  aiConfidence?: number;
  aiRiskIndicators?: string[];
}

interface RiskScore {
  score: number; // 0-100, higher = more risky
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: RiskFactors;
  reasons: string[];
}

/**
 * Calculate risk score for a contact
 * This runs in background during sync (non-blocking)
 */
export function calculateRiskScore(factors: Partial<RiskFactors>): RiskScore {
  const reasons: string[] = [];
  let score = 0;

  // Data Quality Checks (0-30 points)
  if (!factors.hasValidName) {
    score += 10;
    reasons.push('Missing or invalid name');
  }
  
  if (!factors.hasProfilePic) {
    score += 5;
    reasons.push('No profile picture');
  }
  
  if (!factors.hasValidLocale) {
    score += 5;
    reasons.push('Missing locale information');
  }
  
  if (!factors.hasContactInfo) {
    score += 10;
    reasons.push('No contact information extracted');
  }

  // Interaction Patterns (0-40 points)
  if (factors.messageCount !== undefined) {
    if (factors.messageCount === 0) {
      score += 15;
      reasons.push('No messages found');
    } else if (factors.messageCount < 3) {
      score += 10;
      reasons.push('Very few messages (< 3)');
    }
  }
  
  if (factors.conversationAge !== undefined) {
    if (factors.conversationAge < 1) {
      score += 10;
      reasons.push('Very new conversation (< 1 day)');
    }
  }
  
  if (factors.lastInteractionAge !== undefined) {
    if (factors.lastInteractionAge > 365) {
      score += 15;
      reasons.push('No interaction in over a year');
    } else if (factors.lastInteractionAge > 180) {
      score += 10;
      reasons.push('No interaction in over 6 months');
    }
  }

  // Suspicious Patterns (0-20 points)
  if (factors.suspiciousPatterns && factors.suspiciousPatterns.length > 0) {
    score += Math.min(factors.suspiciousPatterns.length * 5, 20);
    reasons.push(`Suspicious patterns detected: ${factors.suspiciousPatterns.join(', ')}`);
  }

  // AI Analysis Factors (0-10 points)
  if (factors.aiConfidence !== undefined && factors.aiConfidence < 0.5) {
    score += 10;
    reasons.push('Low AI confidence in analysis');
  }
  
  if (factors.aiRiskIndicators && factors.aiRiskIndicators.length > 0) {
    score += Math.min(factors.aiRiskIndicators.length * 3, 10);
    reasons.push(`AI detected risk indicators: ${factors.aiRiskIndicators.join(', ')}`);
  }

  // Determine risk level
  let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (score < 20) {
    level = 'LOW';
  } else if (score < 40) {
    level = 'MEDIUM';
  } else if (score < 70) {
    level = 'HIGH';
  } else {
    level = 'CRITICAL';
  }

  return {
    score: Math.min(score, 100),
    level,
    factors: factors as RiskFactors,
    reasons,
  };
}

/**
 * Detect suspicious patterns in contact data
 */
export function detectSuspiciousPatterns(
  firstName: string,
  lastName: string | null,
  messages: Array<{ text: string }> = []
): string[] {
  const patterns: string[] = [];

  // Check name patterns
  if (firstName.match(/^User\s+\d+$/i)) {
    patterns.push('Generic username pattern');
  }
  
  if (firstName.length < 2) {
    patterns.push('Very short name');
  }
  
  if (firstName.match(/^[A-Z0-9]+$/)) {
    patterns.push('All caps or numbers in name');
  }

  // Check message patterns
  if (messages.length > 0) {
    const allMessages = messages.map(m => m.text?.toLowerCase() || '').join(' ');
    
    // Spam indicators
    const spamKeywords = ['free', 'click here', 'limited time', 'act now', 'winner', 'congratulations'];
    const spamCount = spamKeywords.filter(keyword => allMessages.includes(keyword)).length;
    if (spamCount >= 3) {
      patterns.push('Potential spam content');
    }
    
    // Very short messages only
    const avgMessageLength = messages.reduce((sum, m) => sum + (m.text?.length || 0), 0) / messages.length;
    if (avgMessageLength < 5 && messages.length > 5) {
      patterns.push('Only very short messages');
    }
  }

  return patterns;
}

/**
 * Check if contact requires approval based on risk score
 */
export function requiresApproval(riskScore: RiskScore, threshold: number = 40): boolean {
  return riskScore.score >= threshold || riskScore.level === 'HIGH' || riskScore.level === 'CRITICAL';
}

