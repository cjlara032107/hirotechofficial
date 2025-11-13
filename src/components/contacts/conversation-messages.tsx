'use client'

import { useEffect, useState, useRef, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { 
  Send, 
  MessageSquare, 
  Facebook, 
  Instagram, 
  CheckCheck, 
  Check,
  Clock,
  AlertCircle,
  Loader2,
  ChevronDown
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'

interface Message {
  id: string
  content: string
  platform: 'MESSENGER' | 'INSTAGRAM'
  isFromBusiness: boolean
  status: 'PENDING' | 'SENT' | 'DELIVERED' | 'READ' | 'FAILED'
  createdAt: string | Date
  sentAt?: string | Date | null
  deliveredAt?: string | Date | null
  readAt?: string | Date | null
  conversation?: {
    platform: string
    facebookPage: {
      pageName: string
    }
  }
}

interface ConversationMessagesProps {
  contactId: string
  contactName?: string
  platform?: 'MESSENGER' | 'INSTAGRAM'
  initialMessages?: Message[]
}

export function ConversationMessages({
  contactId,
  contactName,
  platform,
  initialMessages = []
}: ConversationMessagesProps) {
  const [messages, setMessages] = useState<Message[]>(initialMessages)
  const [loading, setLoading] = useState(!initialMessages.length)
  const [loadingMore, setLoadingMore] = useState(false)
  const [sending, setSending] = useState(false)
  const [newMessage, setNewMessage] = useState('')
  const [hasMore, setHasMore] = useState(true)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [page, setPage] = useState(1)

  const scrollAreaRef = useRef<HTMLDivElement>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const observerRef = useRef<IntersectionObserver | null>(null)
  const topSentinelRef = useRef<HTMLDivElement>(null)

  // Fetch initial messages
  const fetchMessages = useCallback(async (cursor?: string) => {
    try {
      const params = new URLSearchParams({
        limit: '50',
        ...(cursor && { cursor }),
        ...(platform && { platform })
      })

      const response = await fetch(`/api/contacts/${contactId}/messages?${params}`)
      if (!response.ok) throw new Error('Failed to fetch messages')

      const data = await response.json()
      
      if (cursor) {
        // Append for infinite scroll
        setMessages(prev => [...prev, ...data.messages])
      } else {
        // Initial load
        setMessages(data.messages)
      }

      setHasMore(data.hasMore)
      setNextCursor(data.nextCursor)
      setPage(data.page || 1)
    } catch (error) {
      console.error('Error fetching messages:', error)
      toast.error('Failed to load messages')
    }
  }, [contactId, platform])

  // Load more messages (infinite scroll)
  const loadMore = useCallback(async () => {
    if (!hasMore || loadingMore || !nextCursor) return

    setLoadingMore(true)
    await fetchMessages(nextCursor)
    setLoadingMore(false)
  }, [hasMore, loadingMore, nextCursor, fetchMessages])

  // Initial load
  useEffect(() => {
    if (!initialMessages.length) {
      setLoading(true)
      fetchMessages().finally(() => setLoading(false))
    }
  }, [fetchMessages, initialMessages.length])

  // Intersection Observer for infinite scroll
  useEffect(() => {
    if (!topSentinelRef.current) return

    observerRef.current = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMore && !loadingMore) {
          loadMore()
        }
      },
      { threshold: 0.1 }
    )

    observerRef.current.observe(topSentinelRef.current)

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect()
      }
    }
  }, [hasMore, loadingMore, loadMore])

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (bottomRef.current && messages.length > 0) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages.length])

  async function sendMessage() {
    if (!newMessage.trim()) return

    setSending(true)
    try {
      const response = await fetch(`/api/contacts/${contactId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: newMessage.trim(),
          platform: platform || 'MESSENGER'
        })
      })

      if (!response.ok) throw new Error('Failed to send message')

      const data = await response.json()
      setMessages(prev => [data.message, ...prev])
      setNewMessage('')
      toast.success('Message sent!')
    } catch (error) {
      console.error('Error sending message:', error)
      toast.error('Failed to send message')
    } finally {
      setSending(false)
    }
  }

  function getStatusIcon(status: string) {
    switch (status) {
      case 'READ':
        return <CheckCheck className="h-3 w-3 text-blue-500" />
      case 'DELIVERED':
        return <CheckCheck className="h-3 w-3 text-gray-500" />
      case 'SENT':
        return <Check className="h-3 w-3 text-gray-500" />
      case 'PENDING':
        return <Clock className="h-3 w-3 text-gray-400" />
      case 'FAILED':
        return <AlertCircle className="h-3 w-3 text-red-500" />
      default:
        return null
    }
  }

  function getPlatformIcon(plat: string) {
    return plat === 'INSTAGRAM' 
      ? <Instagram className="h-4 w-4" />
      : <Facebook className="h-4 w-4" />
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="flex justify-center py-12">
          <LoadingSpinner />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="flex flex-col h-[600px]">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="h-5 w-5" />
            <CardTitle>
              Conversation {contactName && `with ${contactName}`}
            </CardTitle>
          </div>
          {platform && (
            <Badge variant="outline" className="flex items-center gap-1">
              {getPlatformIcon(platform)}
              {platform}
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="flex-1 flex flex-col p-0">
        {/* Messages Area */}
        <ScrollArea ref={scrollAreaRef} className="flex-1 px-6">
          <div className="space-y-4 py-4">
            {/* Load More Sentinel */}
            {hasMore && (
              <div ref={topSentinelRef} className="flex justify-center py-2">
                {loadingMore && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Loading older messages...</span>
                  </div>
                )}
              </div>
            )}

            {/* Messages (reversed to show oldest first) */}
            {messages.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <MessageSquare className="h-12 w-12 mx-auto mb-4 opacity-20" />
                <p>No messages yet</p>
                <p className="text-sm mt-2">Send the first message to start the conversation</p>
              </div>
            ) : (
              [...messages].reverse().map((message, index) => {
                const isFromBusiness = message.isFromBusiness
                const timestamp = new Date(message.createdAt)

                return (
                  <div
                    key={message.id}
                    className={cn(
                      'flex gap-3 items-start',
                      isFromBusiness ? 'flex-row-reverse' : 'flex-row'
                    )}
                  >
                    <Avatar className="h-8 w-8 flex-shrink-0">
                      <AvatarFallback className={isFromBusiness ? 'bg-blue-100 text-blue-700' : 'bg-gray-100'}>
                        {isFromBusiness ? 'B' : (contactName?.[0] || 'C')}
                      </AvatarFallback>
                    </Avatar>

                    <div className={cn('flex flex-col gap-1 max-w-[70%]', isFromBusiness && 'items-end')}>
                      <div
                        className={cn(
                          'rounded-lg px-4 py-2',
                          isFromBusiness
                            ? 'bg-blue-500 text-white rounded-tr-none'
                            : 'bg-muted rounded-tl-none'
                        )}
                      >
                        <p className="text-sm whitespace-pre-wrap break-words">{message.content}</p>
                      </div>

                      <div className={cn('flex items-center gap-2 text-xs text-muted-foreground', isFromBusiness && 'flex-row-reverse')}>
                        <span>
                          {formatDistanceToNow(timestamp, { addSuffix: true })}
                        </span>
                        {isFromBusiness && getStatusIcon(message.status)}
                      </div>
                    </div>
                  </div>
                )
              })
            )}

            <div ref={bottomRef} />
          </div>
        </ScrollArea>

        {/* Message Input */}
        <div className="border-t p-4">
          <div className="flex gap-2">
            <Textarea
              placeholder="Type your message..."
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  sendMessage()
                }
              }}
              rows={2}
              className="resize-none"
            />
            <Button
              onClick={sendMessage}
              disabled={sending || !newMessage.trim()}
              size="icon"
              className="h-full aspect-square"
            >
              {sending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>

        {/* Load More Button (alternative to infinite scroll) */}
        {hasMore && !loadingMore && (
          <div className="border-t p-2 text-center">
            <Button
              variant="ghost"
              size="sm"
              onClick={loadMore}
              className="text-xs"
            >
              <ChevronDown className="h-3 w-3 mr-1" />
              Load older messages
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

