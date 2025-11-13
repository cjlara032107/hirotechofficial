/**
 * Facebook-like emoji reactions for team messages
 */

export const REACTION_EMOJIS = {
  // Primary Facebook-style reactions
  LIKE: '👍',
  LOVE: '❤️',
  CARE: '🤗',
  HAHA: '😂',
  WOW: '😮',
  SAD: '😢',
  ANGRY: '😠',
  
  // Additional popular reactions
  CELEBRATE: '🎉',
  FIRE: '🔥',
  CLAP: '👏',
  THINKING: '🤔',
  EYES: '👀',
  CHECK: '✅',
  ROCKET: '🚀',
  STAR: '⭐',
  HEART_EYES: '😍',
  COOL: '😎'
} as const

export type ReactionType = typeof REACTION_EMOJIS[keyof typeof REACTION_EMOJIS]

export interface MessageReaction {
  emoji: ReactionType
  userIds: string[]
  count: number
}

/**
 * Get all available reaction emojis
 */
export function getAllReactions(): ReactionType[] {
  return Object.values(REACTION_EMOJIS)
}

/**
 * Get primary (Facebook-style) reactions
 */
export function getPrimaryReactions(): ReactionType[] {
  return [
    REACTION_EMOJIS.LIKE,
    REACTION_EMOJIS.LOVE,
    REACTION_EMOJIS.CARE,
    REACTION_EMOJIS.HAHA,
    REACTION_EMOJIS.WOW,
    REACTION_EMOJIS.SAD,
    REACTION_EMOJIS.ANGRY,
  ]
}

/**
 * Get extended reactions
 */
export function getExtendedReactions(): ReactionType[] {
  return [
    REACTION_EMOJIS.CELEBRATE,
    REACTION_EMOJIS.FIRE,
    REACTION_EMOJIS.CLAP,
    REACTION_EMOJIS.THINKING,
    REACTION_EMOJIS.EYES,
    REACTION_EMOJIS.CHECK,
    REACTION_EMOJIS.ROCKET,
    REACTION_EMOJIS.STAR,
    REACTION_EMOJIS.HEART_EYES,
    REACTION_EMOJIS.COOL,
  ]
}

/**
 * Get reaction name from emoji
 */
export function getReactionName(emoji: string): string {
  const entry = Object.entries(REACTION_EMOJIS).find(([_, value]) => value === emoji)
  if (!entry) return 'Unknown'
  
  const name = entry[0]
  return name.charAt(0) + name.slice(1).toLowerCase()
}

/**
 * Format reactions for display
 */
export function formatReactions(reactions: Record<string, string[]>): MessageReaction[] {
  return Object.entries(reactions).map(([emoji, userIds]) => ({
    emoji: emoji as ReactionType,
    userIds,
    count: userIds.length
  })).sort((a, b) => b.count - a.count)
}

/**
 * Check if user has reacted with specific emoji
 */
export function hasUserReacted(reactions: Record<string, string[]>, emoji: string, userId: string): boolean {
  return reactions[emoji]?.includes(userId) ?? false
}

/**
 * Get user's reaction to a message
 */
export function getUserReaction(reactions: Record<string, string[]>, userId: string): string | null {
  for (const [emoji, userIds] of Object.entries(reactions)) {
    if (userIds.includes(userId)) {
      return emoji
    }
  }
  return null
}

/**
 * Toggle reaction (add if not present, remove if present)
 */
export function toggleReaction(
  reactions: Record<string, string[]>,
  emoji: string,
  userId: string
): Record<string, string[]> {
  const newReactions = { ...reactions }
  
  // Remove user from any existing reactions
  for (const [existingEmoji, userIds] of Object.entries(newReactions)) {
    newReactions[existingEmoji] = userIds.filter(id => id !== userId)
    if (newReactions[existingEmoji].length === 0) {
      delete newReactions[existingEmoji]
    }
  }
  
  // Add user to new reaction
  if (reactions[emoji]?.includes(userId)) {
    // User already has this reaction, so it was removed above
    return newReactions
  } else {
    // Add new reaction
    if (!newReactions[emoji]) {
      newReactions[emoji] = []
    }
    newReactions[emoji].push(userId)
    return newReactions
  }
}

/**
 * Get total reaction count
 */
export function getTotalReactionCount(reactions: Record<string, string[]>): number {
  return Object.values(reactions).reduce((sum, userIds) => sum + userIds.length, 0)
}

/**
 * Get top reactions (most used)
 */
export function getTopReactions(reactions: Record<string, string[]>, limit = 3): MessageReaction[] {
  return formatReactions(reactions).slice(0, limit)
}

