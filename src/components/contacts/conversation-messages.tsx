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
  const [chunkIndex, setChunkIndex] = useState(0)
  const [isStreaming, setIsStreaming] = useState(false)
  const [totalMessageCount, setTotalMessageCount] = useState<number | undefined>(undefined)
  const [maxMessages, setMaxMessages] = useState<number | undefined>(undefined)

  const scrollAreaRef = useRef<HTMLDivElement>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const observerRef = useRef<IntersectionObserver | null>(null)
  const topSentinelRef = useRef<HTMLDivElement>(null)

  // Fetch initial messages (chunked)
  const fetchMessages = useCallback(async (cursor?: string, chunkIndex?: number) => {
    try {
      const params = new URLSearchParams({
        limit: '50',
        ...(cursor && { cursor }),
        ...(chunkIndex !== undefined && { chunkIndex: String(chunkIndex) }),
        ...(platform && { platform })
      })

      const response = await fetch(`/api/contacts/${contactId}/messages?${params}`)
      if (!response.ok) throw new Error('Failed to fetch messages')

      const data = await response.json()
      
      // Track total message count and max messages limit for very large conversations
      if (data.totalMessageCount !== undefined) {
        setTotalMessageCount(data.totalMessageCount)
      }
      if (data.maxMessages !== undefined) {
        setMaxMessages(data.maxMessages)
      }
      
      if (cursor) {
        // Append for infinite scroll
        setMessages(prev => {
          const newMessages = [...prev, ...data.messages]
          // Check if we've reached the max messages limit
          const reachedMax = data.maxMessages && newMessages.length >= data.maxMessages
          setHasMore(data.hasMore && !reachedMax)
          return newMessages
        })
      } else {
        // Initial load
        setMessages(data.messages)
        // Check if we've reached the max messages limit
        const reachedMax = data.maxMessages && data.messages.length >= data.maxMessages
        setHasMore(data.hasMore && !reachedMax)
      }

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
    const nextChunkIndex = chunkIndex + 1
    setChunkIndex(nextChunkIndex)
    await fetchMessages(nextCursor, nextChunkIndex)
    setLoadingMore(false)
  }, [hasMore, loadingMore, nextCursor, fetchMessages, chunkIndex])

  // Stream messages using Server-Sent Events (optional)
  const streamMessages = useCallback(async () => {
    if (isStreaming) return

    setIsStreaming(true)
    setLoading(true)
    setMessages([]) // Clear existing messages

    try {
      const params = new URLSearchParams({
        ...(platform && { platform })
      })

      const response = await fetch(`/api/contacts/${contactId}/messages/stream?${params}`)
      if (!response.ok) throw new Error('Failed to stream messages')

      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (!reader) {
        throw new Error('Stream not available')
      }

      let buffer = ''
      let totalFetched = 0

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = JSON.parse(line.slice(6))

            if (data.type === 'metadata') {
              // Initial metadata received
              setHasMore(data.total > 0)
            } else if (data.type === 'chunk') {
              // Append chunk of messages
              setMessages(prev => [...prev, ...data.messages])
              totalFetched += data.messages.length
              setHasMore(data.hasMore)
            } else if (data.type === 'complete') {
              // Streaming complete
              setHasMore(false)
              toast.success(`Loaded ${totalFetched} messages`)
            } else if (data.type === 'error') {
              throw new Error(data.error || 'Streaming error')
            }
          }
        }
      }
    } catch (error) {
      console.error('Error streaming messages:', error)
      toast.error('Failed to stream messages')
      // Fallback to regular fetch
      await fetchMessages()
    } finally {
      setIsStreaming(false)
      setLoading(false)
    }
  }, [contactId, platform, isStreaming, fetchMessages])

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
            {/* Notification for very large conversations (10,000+ messages) */}
            {totalMessageCount !== undefined && maxMessages !== undefined && totalMessageCount > maxMessages && (
              <div className="bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-lg p-3 mb-4">
                <div className="flex items-start gap-2">
                  <AlertCircle className="h-4 w-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
                  <div className="flex-1 text-sm">
                    <p className="font-medium text-amber-900 dark:text-amber-100">
                      Large conversation detected
                    </p>
                    <p className="text-amber-700 dark:text-amber-300 mt-1">
                      Showing the most recent {maxMessages} of {totalMessageCount.toLocaleString()} messages. 
                      Scroll up to load older messages.
                    </p>
                  </div>
                </div>
              </div>
            )}

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

