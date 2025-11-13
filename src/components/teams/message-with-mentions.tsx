'use client'

import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { formatDistanceToNow } from 'date-fns'
import { CheckCheck, Check, Clock, AlertCircle, Pin, Edit2 } from 'lucide-react'
import { MessageReactions } from './message-reactions'

interface TeamMember {
  id: string
  displayName?: string | null
  user: {
    id: string
    name: string | null
    email: string
    image?: string | null
  }
}

interface MessageWithMentionsProps {
  message: {
    id: string
    content: string
    createdAt: string | Date
    isEdited: boolean
    isPinned: boolean
    mentions: string[]
    reactions?: Record<string, string[]>
    sender: TeamMember
    thread?: {
      id: string
      title?: string | null
      type: string
    } | null
  }
  teamId: string
  currentMemberId: string
  teamMembers: TeamMember[]
  isOwnMessage: boolean
  onReactionUpdate?: (reactions: Record<string, string[]>) => void
  onEdit?: () => void
  onDelete?: () => void
}

export function MessageWithMentions({
  message,
  teamId,
  currentMemberId,
  teamMembers,
  isOwnMessage,
  onReactionUpdate,
  onEdit,
  onDelete
}: MessageWithMentionsProps) {
  const isMentioned = message.mentions.includes(currentMemberId)
  
  // Parse message content to highlight mentions
  const parsedContent = parseContentWithMentions(
    message.content,
    message.mentions,
    teamMembers
  )

  return (
    <div
      className={cn(
        'flex gap-3 items-start py-2 px-4 rounded-lg transition-colors',
        isMentioned && 'bg-yellow-50 dark:bg-yellow-950/20 border-l-4 border-yellow-500',
        isOwnMessage && 'flex-row-reverse'
      )}
    >
      {/* Avatar */}
      <Avatar className="h-10 w-10 flex-shrink-0">
        <AvatarImage src={message.sender.user.image || undefined} />
        <AvatarFallback className={isOwnMessage ? 'bg-blue-100 text-blue-700' : 'bg-gray-100'}>
          {message.sender.displayName?.[0] || message.sender.user.name?.[0] || 'U'}
        </AvatarFallback>
      </Avatar>

      {/* Message Content */}
      <div className={cn('flex-1 min-w-0', isOwnMessage && 'items-end')}>
        {/* Header */}
        <div className={cn('flex items-center gap-2 mb-1', isOwnMessage && 'flex-row-reverse')}>
          <span className="font-medium text-sm">
            {message.sender.displayName || message.sender.user.name || message.sender.user.email}
          </span>
          <span className="text-xs text-muted-foreground">
            {formatDistanceToNow(new Date(message.createdAt), { addSuffix: true })}
          </span>
          {message.isEdited && (
            <Badge variant="outline" className="text-xs py-0 px-1">
              <Edit2 className="h-2 w-2 mr-1" />
              Edited
            </Badge>
          )}
          {message.isPinned && (
            <Badge variant="secondary" className="text-xs py-0 px-1">
              <Pin className="h-2 w-2 mr-1" />
              Pinned
            </Badge>
          )}
        </div>

        {/* Message Bubble */}
        <div
          className={cn(
            'rounded-lg px-4 py-2 break-words',
            isOwnMessage
              ? 'bg-blue-500 text-white rounded-tr-none'
              : 'bg-muted rounded-tl-none'
          )}
        >
          <div className="text-sm whitespace-pre-wrap">
            {parsedContent.map((part, index) => (
              <span key={index}>
                {part.type === 'mention' ? (
                  <span className={cn(
                    'font-semibold px-1 rounded',
                    isOwnMessage 
                      ? 'bg-blue-600 text-blue-100' 
                      : 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-200'
                  )}>
                    @{part.name}
                  </span>
                ) : (
                  part.text
                )}
              </span>
            ))}
          </div>
        </div>

        {/* Reactions */}
        {message.reactions && Object.keys(message.reactions).length > 0 && (
          <div className="mt-2">
            <MessageReactions
              messageId={message.id}
              teamId={teamId}
              reactions={message.reactions}
              currentUserId={currentMemberId}
              onReactionUpdate={onReactionUpdate}
            />
          </div>
        )}

        {/* Mention Badge */}
        {isMentioned && (
          <div className="mt-2">
            <Badge variant="default" className="text-xs bg-yellow-500 hover:bg-yellow-600">
              You were mentioned
            </Badge>
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * Parse message content to highlight mentions
 */
function parseContentWithMentions(
  content: string,
  mentionIds: string[],
  teamMembers: TeamMember[]
): Array<{ type: 'text' | 'mention'; text?: string; name?: string; memberId?: string }> {
  if (mentionIds.length === 0) {
    return [{ type: 'text', text: content }]
  }

  const parts: Array<{ type: 'text' | 'mention'; text?: string; name?: string; memberId?: string }> = []
  let remaining = content

  // Find @mentions in content
  const mentionRegex = /@(\w+(?:\s+\w+)?)/g
  let lastIndex = 0
  let match

  while ((match = mentionRegex.exec(content)) !== null) {
    const mentionText = match[1]
    
    // Find matching team member
    const mentionedMember = teamMembers.find(m => {
      const name = m.displayName || m.user.name || m.user.email
      return name.toLowerCase().includes(mentionText.toLowerCase())
    })

    if (mentionedMember && mentionIds.includes(mentionedMember.id)) {
      // Add text before mention
      if (match.index > lastIndex) {
        parts.push({
          type: 'text',
          text: content.substring(lastIndex, match.index)
        })
      }

      // Add mention
      parts.push({
        type: 'mention',
        name: mentionedMember.displayName || mentionedMember.user.name || mentionedMember.user.email,
        memberId: mentionedMember.id
      })

      lastIndex = match.index + match[0].length
    }
  }

  // Add remaining text
  if (lastIndex < content.length) {
    parts.push({
      type: 'text',
      text: content.substring(lastIndex)
    })
  }

  return parts.length > 0 ? parts : [{ type: 'text', text: content }]
}

