'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { cn } from '@/lib/utils'
import { 
  getPrimaryReactions, 
  getExtendedReactions, 
  formatReactions,
  getReactionName,
  type ReactionType 
} from '@/lib/teams/reactions'
import { toast } from 'sonner'

interface MessageReactionsProps {
  messageId: string
  teamId: string
  reactions: Record<string, string[]>
  currentUserId: string
  onReactionUpdate?: (reactions: Record<string, string[]>) => void
}

export function MessageReactions({
  messageId,
  teamId,
  reactions,
  currentUserId,
  onReactionUpdate,
}: MessageReactionsProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [showAllReactions, setShowAllReactions] = useState(false)

  const formattedReactions = formatReactions(reactions)
  const primaryReactions = getPrimaryReactions()
  const extendedReactions = getExtendedReactions()

  const userReaction = Object.entries(reactions).find(([_, userIds]) => 
    userIds.includes(currentUserId)
  )?.[0]

  async function handleReaction(emoji: string) {
    try {
      const response = await fetch(`/api/teams/${teamId}/messages/${messageId}/reactions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ emoji })
      })

      if (!response.ok) {
        throw new Error('Failed to add reaction')
      }

      const data = await response.json()
      onReactionUpdate?.(data.message.reactions)
      setIsOpen(false)
    } catch (error) {
      console.error('Error adding reaction:', error)
      toast.error('Failed to add reaction')
    }
  }

  return (
    <div className="flex items-center gap-1">
      {/* Display existing reactions */}
      {formattedReactions.length > 0 && (
        <div className="flex items-center gap-1 mr-2">
          {formattedReactions.map((reaction) => (
            <Button
              key={reaction.emoji}
              variant={reaction.userIds.includes(currentUserId) ? 'default' : 'outline'}
              size="sm"
              className={cn(
                'h-6 px-2 text-xs',
                reaction.userIds.includes(currentUserId) && 'bg-blue-100 hover:bg-blue-200 text-blue-700'
              )}
              onClick={() => handleReaction(reaction.emoji)}
            >
              <span className="mr-1">{reaction.emoji}</span>
              {reaction.count > 1 && <span>{reaction.count}</span>}
            </Button>
          ))}
        </div>
      )}

      {/* Reaction picker */}
      <Popover open={isOpen} onOpenChange={setIsOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 rounded-full hover:bg-muted"
          >
            {userReaction ? (
              <span className="text-sm">{userReaction}</span>
            ) : (
              <span className="text-sm">😊</span>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-auto p-2" align="start">
          <div className="space-y-2">
            {/* Primary reactions (Facebook-style) */}
            <div>
              <div className="text-xs font-medium text-muted-foreground mb-2">
                Quick reactions
              </div>
              <div className="flex gap-1">
                {primaryReactions.map((emoji) => (
                  <Button
                    key={emoji}
                    variant="ghost"
                    size="sm"
                    className={cn(
                      'h-10 w-10 text-2xl p-0 hover:scale-110 transition-transform',
                      userReaction === emoji && 'bg-blue-100'
                    )}
                    onClick={() => handleReaction(emoji)}
                    title={getReactionName(emoji)}
                  >
                    {emoji}
                  </Button>
                ))}
              </div>
            </div>

            {/* Extended reactions */}
            {showAllReactions && (
              <div>
                <div className="text-xs font-medium text-muted-foreground mb-2">
                  More reactions
                </div>
                <div className="grid grid-cols-5 gap-1 max-w-[240px]">
                  {extendedReactions.map((emoji) => (
                    <Button
                      key={emoji}
                      variant="ghost"
                      size="sm"
                      className={cn(
                        'h-10 w-10 text-2xl p-0 hover:scale-110 transition-transform',
                        userReaction === emoji && 'bg-blue-100'
                      )}
                      onClick={() => handleReaction(emoji)}
                      title={getReactionName(emoji)}
                    >
                      {emoji}
                    </Button>
                  ))}
                </div>
              </div>
            )}

            {/* Show more/less toggle */}
            <Button
              variant="ghost"
              size="sm"
              className="w-full text-xs"
              onClick={() => setShowAllReactions(!showAllReactions)}
            >
              {showAllReactions ? 'Show less' : 'Show more reactions'}
            </Button>
          </div>
        </PopoverContent>
      </Popover>
    </div>
  )
}

