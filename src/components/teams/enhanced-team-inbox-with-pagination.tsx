'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { formatDistanceToNow } from 'date-fns'
import { 
  Send, 
  Plus, 
  Users, 
  MoreVertical, 
  Pin, 
  Edit2, 
  Loader2,
  ChevronDown,
  Hash,
  MessageSquare
} from 'lucide-react'
import { toast } from 'sonner'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { useSupabaseRealtime } from '@/contexts/supabase-realtime-context'
import { MessageReactions } from './message-reactions'
import { CreateConversationDialog } from './create-conversation-dialog'
import { EditThreadDialog } from './edit-thread-dialog'
import { cn } from '@/lib/utils'

interface Thread {
  id: string
  title?: string | null
  groupName?: string | null
  type: string
  lastMessageAt?: Date | string | null
  participantIds: string[]
  isChannel: boolean
  isPinned: boolean
  _count?: {
    messages: number
  }
}

interface Message {
  id: string
  content: string
  createdAt: Date | string
  isPinned: boolean
  reactions?: Record<string, string[]>
  sender: {
    id: string
    displayName?: string | null
    user: {
      name: string | null
      image: string | null
      email: string
    }
  }
}

interface EnhancedTeamInboxProps {
  teamId: string
  currentMemberId: string
  currentUserId: string
  isAdmin: boolean
}

const MESSAGES_PER_PAGE = 20

export function EnhancedTeamInboxWithPagination({
  teamId,
  currentMemberId,
  currentUserId,
  isAdmin
}: EnhancedTeamInboxProps) {
  const [threads, setThreads] = useState<Thread[]>([])
  const [selectedThread, setSelectedThread] = useState<Thread | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingMessages, setLoadingMessages] = useState(false)
  const [sending, setSending] = useState(false)
  const [newMessage, setNewMessage] = useState('')
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [showEditDialog, setShowEditDialog] = useState(false)
  const [editingThread, setEditingThread] = useState<Thread | null>(null)
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1)
  const [totalMessages, setTotalMessages] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  
  const scrollAreaRef = useRef<HTMLDivElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  
  const { isConnected, subscribeToTeamMessages, subscribeToTeamThreads } = useSupabaseRealtime()

  const fetchThreads = useCallback(async () => {
    try {
      const response = await fetch(`/api/teams/${teamId}/threads`)
      const data = await response.json()
      setThreads(data.threads || [])
      if ((data.threads?.length > 0) && !selectedThread) {
        setSelectedThread(data.threads[0])
      }
    } catch (error) {
      console.error('Error fetching threads:', error)
      toast.error('Failed to load conversations')
    } finally {
      setLoading(false)
    }
  }, [teamId, selectedThread])

  const fetchMessages = useCallback(async (threadId: string, page = 1, append = false) => {
    try {
      if (!append) {
        setLoadingMessages(true)
      } else {
        setLoadingMore(true)
      }

      const offset = (page - 1) * MESSAGES_PER_PAGE
      const response = await fetch(
        `/api/teams/${teamId}/messages?threadId=${threadId}&limit=${MESSAGES_PER_PAGE}&offset=${offset}`
      )
      const data = await response.json()

      if (append) {
        setMessages(prev => [...data.messages, ...prev])
      } else {
        setMessages(data.messages || [])
      }

      setTotalMessages(data.total || 0)
      setHasMore((data.messages?.length || 0) === MESSAGES_PER_PAGE)
    } catch (error) {
      console.error('Error fetching messages:', error)
      toast.error('Failed to load messages')
    } finally {
      setLoadingMessages(false)
      setLoadingMore(false)
    }
  }, [teamId])

  const loadMoreMessages = useCallback(() => {
    if (!selectedThread || loadingMore || !hasMore) return
    
    const nextPage = currentPage + 1
    setCurrentPage(nextPage)
    fetchMessages(selectedThread.id, nextPage, true)
  }, [selectedThread, loadingMore, hasMore, currentPage, fetchMessages])

  useEffect(() => {
    fetchThreads()
  }, [fetchThreads])

  useEffect(() => {
    if (selectedThread) {
      setCurrentPage(1)
      fetchMessages(selectedThread.id, 1, false)
    }
  }, [selectedThread, fetchMessages])

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (messages.length > 0 && !loadingMessages) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages.length, loadingMessages])

  // Supabase Realtime subscriptions
  useEffect(() => {
    if (!isConnected || !teamId) return

    console.log('[Enhanced Inbox] Setting up realtime listeners')

    const unsubscribeMessages = subscribeToTeamMessages(teamId, {
      onInsert: async (message) => {
        try {
          const response = await fetch(`/api/teams/${teamId}/messages?limit=1&messageId=${message.id}`)
          const data = await response.json()
          
          if (data.messages && data.messages.length > 0) {
            const fullMessage = data.messages[0]
            
            if (selectedThread?.id === fullMessage.threadId) {
              setMessages(prev => {
                const exists = prev.some(m => m.id === fullMessage.id)
                if (exists) return prev
                return [...prev, fullMessage]
              })
            }
            
            if (fullMessage.threadId) {
              setThreads(prev => prev.map(t => 
                t.id === fullMessage.threadId 
                  ? { ...t, lastMessageAt: fullMessage.createdAt }
                  : t
              ))
            }
          }
        } catch (error) {
          console.error('[Realtime] Error fetching full message:', error)
        }
      },
      onUpdate: async (message) => {
        try {
          const response = await fetch(`/api/teams/${teamId}/messages?limit=1&messageId=${message.id}`)
          const data = await response.json()
          
          if (data.messages && data.messages.length > 0) {
            const fullMessage = data.messages[0]
            
            if (selectedThread?.id === fullMessage.threadId) {
              setMessages(prev => prev.map(m => 
                m.id === fullMessage.id ? fullMessage : m
              ))
            }
          }
        } catch (error) {
          console.error('[Realtime] Error fetching updated message:', error)
        }
      },
      onDelete: (messageId) => {
        setMessages(prev => prev.filter(m => m.id !== messageId))
      }
    })

    const unsubscribeThreads = subscribeToTeamThreads(teamId, {
      onInsert: (thread) => {
        setThreads(prev => [thread as Thread, ...prev])
      },
      onUpdate: (thread) => {
        setThreads(prev => prev.map(t => 
          t.id === thread.id ? (thread as Thread) : t
        ))
      }
    })

    return () => {
      console.log('[Enhanced Inbox] Cleaning up realtime listeners')
      unsubscribeMessages()
      unsubscribeThreads()
    }
  }, [isConnected, teamId, selectedThread?.id, subscribeToTeamMessages, subscribeToTeamThreads])

  async function sendMessage() {
    if (!newMessage.trim()) return

    setSending(true)
    try {
      const response = await fetch(`/api/teams/${teamId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: newMessage,
          threadId: selectedThread?.id
        })
      })

      if (!response.ok) throw new Error('Failed to send message')

      setNewMessage('')
      toast.success('Message sent')
    } catch (error) {
      toast.error('Failed to send message')
    } finally {
      setSending(false)
    }
  }

  async function handlePinMessage(messageId: string, currentlyPinned: boolean) {
    if (!isAdmin) {
      toast.error('Only admins can pin messages')
      return
    }

    try {
      const response = await fetch(
        `/api/teams/${teamId}/messages/${messageId}/pin`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pin: !currentlyPinned })
        }
      )

      if (!response.ok) throw new Error('Failed to pin message')

      toast.success(currentlyPinned ? 'Message unpinned' : 'Message pinned')
    } catch (error) {
      toast.error('Failed to pin message')
    }
  }

  function handleEditThread(thread: Thread) {
    setEditingThread(thread)
    setShowEditDialog(true)
  }

  function getThreadName(thread: Thread) {
    if (thread.title) return thread.title
    if (thread.groupName) return thread.groupName
    if (thread.isChannel) return 'Unnamed Channel'
    return 'Unnamed Thread'
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="flex justify-center py-8">
          <LoadingSpinner />
        </CardContent>
      </Card>
    )
  }

  const pinnedMessages = messages.filter(m => m.isPinned)

  return (
    <>
      <div className="grid grid-cols-3 gap-4 h-[700px]">
        {/* Threads List */}
        <Card className="col-span-1">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Conversations</CardTitle>
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => setShowCreateDialog(true)}
              >
                <Plus className="w-4 h-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[580px]">
              {threads.map((thread) => (
                <button
                  key={thread.id}
                  onClick={() => setSelectedThread(thread)}
                  className={cn(
                    'w-full p-4 text-left border-b hover:bg-muted/50 transition-colors',
                    selectedThread?.id === thread.id && 'bg-muted'
                  )}
                >
                  <div className="flex items-center gap-2 mb-1">
                    {thread.isChannel ? (
                      <Hash className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <MessageSquare className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="font-medium text-sm truncate">
                      {getThreadName(thread)}
                    </span>
                    {thread.isPinned && (
                      <Pin className="w-3 h-3 text-blue-500" />
                    )}
                  </div>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      {thread._count?.messages || 0} messages
                    </p>
                    {thread.lastMessageAt && (
                      <p className="text-xs text-muted-foreground">
                        {formatDistanceToNow(new Date(thread.lastMessageAt), { addSuffix: true })}
                      </p>
                    )}
                  </div>
                </button>
              ))}
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Messages Area */}
        <Card className="col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CardTitle className="text-lg">
                  {selectedThread ? getThreadName(selectedThread) : 'Select a conversation'}
                </CardTitle>
                {selectedThread?.isChannel && (
                  <Badge variant="outline" className="text-xs">
                    Channel
                  </Badge>
                )}
              </div>
              
              {selectedThread && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm">
                      <MoreVertical className="w-4 h-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => handleEditThread(selectedThread)}>
                      <Edit2 className="w-4 h-4 mr-2" />
                      Edit Thread
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem>
                      View Details
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
          </CardHeader>
          
          <CardContent className="space-y-4">
            {/* Pinned Messages */}
            {pinnedMessages.length > 0 && (
              <div className="border-b pb-4">
                <div className="flex items-center gap-2 mb-2">
                  <Pin className="w-4 h-4 text-blue-500" />
                  <span className="text-sm font-medium">Pinned Messages</span>
                </div>
                <div className="space-y-2">
                  {pinnedMessages.map((message) => (
                    <div key={message.id} className="bg-blue-50 p-2 rounded text-sm">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium">
                          {message.sender.displayName || message.sender.user.name}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatDistanceToNow(new Date(message.createdAt), { addSuffix: true })}
                        </span>
                      </div>
                      <p>{message.content}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <ScrollArea className="h-[450px] pr-4" ref={scrollAreaRef}>
              {/* Load More Button */}
              {hasMore && (
                <div className="flex justify-center py-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={loadMoreMessages}
                    disabled={loadingMore}
                  >
                    {loadingMore ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Loading...
                      </>
                    ) : (
                      <>
                        <ChevronDown className="w-4 h-4 mr-2" />
                        Load older messages ({totalMessages - messages.length} more)
                      </>
                    )}
                  </Button>
                </div>
              )}

              {loadingMessages ? (
                <div className="flex justify-center py-8">
                  <LoadingSpinner />
                </div>
              ) : messages.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">
                  No messages yet. Start the conversation!
                </p>
              ) : (
                <div className="space-y-4">
                  {messages.map((message) => (
                    <div key={message.id} className="flex gap-3 group">
                      <Avatar className="h-8 w-8">
                        <AvatarImage src={message.sender.user.image || undefined} />
                        <AvatarFallback>
                          {(message.sender.displayName || message.sender.user.name)?.[0] || 'U'}
                        </AvatarFallback>
                      </Avatar>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-medium text-sm">
                            {message.sender.displayName || message.sender.user.name}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {formatDistanceToNow(new Date(message.createdAt), { addSuffix: true })}
                          </span>
                          {message.isPinned && (
                            <Pin className="w-3 h-3 text-blue-500" />
                          )}
                          
                          {/* Message Actions */}
                          <div className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 w-6 p-0"
                              onClick={() => handlePinMessage(message.id, message.isPinned)}
                            >
                              <Pin className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                        <p className="text-sm mb-2">{message.content}</p>
                        
                        {/* Reactions */}
                        <MessageReactions
                          messageId={message.id}
                          teamId={teamId}
                          reactions={message.reactions || {}}
                          currentUserId={currentMemberId}
                          onReactionUpdate={(reactions) => {
                            setMessages(prev => prev.map(m =>
                              m.id === message.id ? { ...m, reactions } : m
                            ))
                          }}
                        />
                      </div>
                    </div>
                  ))}
                  <div ref={messagesEndRef} />
                </div>
              )}
            </ScrollArea>

            {/* Message Input */}
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
                disabled={!selectedThread}
              />
              <Button 
                onClick={sendMessage} 
                disabled={sending || !newMessage.trim() || !selectedThread}
              >
                {sending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Dialogs */}
      <CreateConversationDialog
        teamId={teamId}
        open={showCreateDialog}
        onOpenChange={setShowCreateDialog}
        isAdmin={isAdmin}
        onCreated={() => {
          fetchThreads()
          setShowCreateDialog(false)
        }}
      />

      {editingThread && (
        <EditThreadDialog
          teamId={teamId}
          thread={editingThread}
          open={showEditDialog}
          onOpenChange={setShowEditDialog}
          isAdmin={isAdmin}
          onUpdated={() => {
            fetchThreads()
            setShowEditDialog(false)
          }}
        />
      )}
    </>
  )
}

