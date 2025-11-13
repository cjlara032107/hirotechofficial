'use client'

import { useEffect, useState, useRef, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
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
  Search,
  Paperclip,
  Smile,
  MoreVertical,
  Pin,
  Reply,
  Edit2,
  Trash2,
  Users,
  Radio,
  MessageSquare,
  Hash,
  X
} from 'lucide-react'
import { toast } from 'sonner'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { CreateConversationDialog } from './create-conversation-dialog'
import { useSupabaseRealtime } from '@/contexts/supabase-realtime-context'
import { useSession } from '@/hooks/use-session'

interface EnhancedTeamInboxProps {
  teamId: string
  currentMemberId: string
  isAdmin: boolean
}

interface Thread {
  id: string
  title?: string
  description?: string
  type: string
  participantIds: string[]
  avatar?: string
  isChannel: boolean
  enableTopics: boolean
  isPinned: boolean
  lastMessageAt?: string
  topics?: Topic[]
  participants?: Array<{
    id: string
    user: {
      id: string
      name: string | null
      image: string | null
    }
    displayName?: string | null
  }>
}

interface Topic {
  id: string
  name: string
  description?: string
  icon?: string
  color: string
  order: number
}

interface Message {
  id: string
  content: string
  senderId: string
  sender: {
    id: string
    user: {
      name: string
      image?: string
    }
    displayName?: string
    avatar?: string
  }
  mentions: string[]
  reactions?: Record<string, string[]>
  attachments?: Array<{
    name: string
    url: string
    type: string
    size: number
  }>
  replyToId?: string
  replyTo?: Message
  isPinned: boolean
  isEdited: boolean
  createdAt: string
}

export function EnhancedTeamInbox({
  teamId,
  currentMemberId,
  isAdmin
}: EnhancedTeamInboxProps) {
  const [threads, setThreads] = useState<Thread[]>([])
  const [selectedThread, setSelectedThread] = useState<Thread | null>(null)
  const [selectedTopic, setSelectedTopic] = useState<string | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [newMessage, setNewMessage] = useState('')
  const [replyingTo, setReplyingTo] = useState<Message | null>(null)
  const [editingMessage, setEditingMessage] = useState<Message | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typingUsers, setTypingUsers] = useState<Record<string, string>>({})
  const fileInputRef = useRef<HTMLInputElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  
  const { isConnected, subscribeToTeamMessages, subscribeToTeamThreads, emitTyping, stopTyping, onTyping } = useSupabaseRealtime()
  const { data: session } = useSession()

  const fetchThreads = useCallback(async () => {
    try {
      console.log('Fetching threads for teamId:', teamId)
      
      if (!teamId) {
        console.error('No teamId provided')
        toast.error('Team ID is missing')
        setThreads([])
        setLoading(false)
        return
      }
      
      const response = await fetch(`/api/teams/${teamId}/threads`)
      const data = await response.json()
      
      console.log('API Response:', { ok: response.ok, status: response.status, data })
      
      // Handle specific error status codes
      if (response.status === 401) {
        // 401 is expected when not logged in - will redirect to login
        console.log('[Team Inbox] Not authenticated, redirecting to login')
        setThreads([])
        return
      }
      
      if (response.status === 403) {
        console.error('Forbidden - User not a team member or not active')
        toast.error('You do not have access to this team')
        setThreads([])
        return
      }
      
      // Check if response has error
      if (!response.ok) {
        const errorMsg = data.error || data.details || 'Failed to fetch threads'
        console.error('API Error:', errorMsg, 'Status:', response.status)
        console.error('Full error response:', data)
        toast.error(`Unable to load conversations: ${errorMsg}`)
        setThreads([])
        return
      }
      
      // Ensure threads is an array
      const fetchedThreads = Array.isArray(data.threads) ? data.threads : []
      console.log('Fetched threads count:', fetchedThreads.length)
      setThreads(fetchedThreads)
      
      // Auto-select first thread if available
      if (fetchedThreads.length > 0 && !selectedThread) {
        setSelectedThread(fetchedThreads[0])
      }
      
      // Show info message if no threads found
      if (fetchedThreads.length === 0) {
        console.log('No threads found for this team')
      }
    } catch (error) {
      console.error('Error fetching threads:', error)
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'
      toast.error(`Failed to load conversations: ${errorMessage}`)
      setThreads([]) // Set to empty array on error
    } finally {
      setLoading(false)
    }
  }, [teamId])

  const fetchMessages = useCallback(async (threadId: string, topicId: string | null = null) => {
    try {
      const url = topicId
        ? `/api/teams/${teamId}/messages?threadId=${threadId}&topicId=${topicId}`
        : `/api/teams/${teamId}/messages?threadId=${threadId}`
      
      const response = await fetch(url)
      const data = await response.json()
      setMessages(data.messages)
      
      // Scroll to bottom
      setTimeout(() => {
        if (scrollRef.current) {
          scrollRef.current.scrollTop = scrollRef.current.scrollHeight
        }
      }, 100)
    } catch (err) {
      console.error('Error fetching messages:', err)
    }
  }, [teamId, scrollRef])

  useEffect(() => {
    fetchThreads()
  }, [fetchThreads])

  useEffect(() => {
    if (selectedThread) {
      fetchMessages(selectedThread.id, selectedTopic)
    }
  }, [selectedThread, selectedTopic, fetchMessages])

  // Supabase Realtime connection for real-time updates
  useEffect(() => {
    if (!isConnected || !teamId) return

    console.log('[Supabase Realtime] Setting up team inbox listeners for team:', teamId)
    
    // Subscribe to team messages
    const unsubscribeMessages = subscribeToTeamMessages(teamId, {
      onInsert: async (message) => {
        console.log('[Supabase Realtime] ✅ New message event received:', {
          messageId: message.id,
          teamId: message.teamId,
          threadId: message.threadId,
          currentThreadId: selectedThread?.id,
          timestamp: new Date().toISOString()
        })
        
        // Fetch full message data with relations from API
        try {
          const response = await fetch(`/api/teams/${teamId}/messages?limit=1&messageId=${message.id}`)
          
          if (!response.ok) {
            console.error('[Supabase Realtime] ❌ API fetch failed:', response.status, response.statusText)
            return
          }
          
          const data = await response.json()
          
          if (!data.messages || data.messages.length === 0) {
            console.error('[Supabase Realtime] ❌ No message data returned')
            return
          }
          
          const fullMessage = data.messages[0]
          console.log('[Supabase Realtime] 📦 Full message fetched:', {
            id: fullMessage.id,
            threadId: fullMessage.threadId,
            sender: fullMessage.sender?.user?.name,
            content: fullMessage.content.substring(0, 50)
          })
          
          // ALWAYS update thread last message time (even if not viewing)
          if (fullMessage.threadId) {
            setThreads(prev => {
              const updated = prev.map(t => 
                t.id === fullMessage.threadId 
                  ? { ...t, lastMessageAt: fullMessage.createdAt }
                  : t
              )
              console.log('[Supabase Realtime] 🔄 Thread list updated')
              return updated
            })
          }
          
          // Only add to messages if viewing this thread
          if (selectedThread?.id === fullMessage.threadId) {
            setMessages(prev => {
              // Check if message already exists (avoid duplicates)
              const exists = prev.some(m => m.id === fullMessage.id)
              if (exists) {
                console.log('[Supabase Realtime] ⚠️ Message already exists, skipping')
                return prev
              }
              console.log('[Supabase Realtime] ✅ Message added to view')
              return [...prev, fullMessage]
            })
            
            // Scroll to bottom
            setTimeout(() => {
              if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight
              }
            }, 100)
          } else {
            console.log('[Supabase Realtime] ℹ️ Message for different thread, not adding to view but thread updated')
          }
        } catch (error) {
          console.error('[Supabase Realtime] ❌ Error fetching full message:', error)
        }
      },
      onUpdate: async (message) => {
        console.log('[Supabase Realtime] Message updated:', message)
        
        // Fetch full message data with relations from API
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
          console.error('[Supabase Realtime] Error fetching updated message:', error)
        }
      },
      onDelete: (messageId) => {
        console.log('[Supabase Realtime] Message deleted:', messageId)
        setMessages(prev => prev.filter(m => m.id !== messageId))
      }
    })

    // Subscribe to team threads
    const unsubscribeThreads = subscribeToTeamThreads(teamId, {
      onInsert: (thread) => {
        console.log('[Supabase Realtime] New thread created:', thread)
        setThreads(prev => [thread as Thread, ...prev])
      },
      onUpdate: (thread) => {
        console.log('[Supabase Realtime] Thread updated:', thread)
        setThreads(prev => prev.map(t => 
          t.id === thread.id ? (thread as Thread) : t
        ))
      }
    })

    return () => {
      console.log('[Supabase Realtime] Cleaning up team inbox listeners')
      unsubscribeMessages()
      unsubscribeThreads()
    }
  }, [isConnected, teamId, selectedThread?.id, subscribeToTeamMessages, subscribeToTeamThreads])

  // Subscribe to typing indicators for selected thread
  useEffect(() => {
    if (!isConnected || !selectedThread) return

    console.log('[Supabase Realtime] Setting up typing indicators for thread:', selectedThread.id)

    const unsubscribeTyping = onTyping(selectedThread.id, (data) => {
      if (data.userName && data.userId !== session?.user?.id) {
        setTypingUsers(prev => ({ ...prev, [data.userId]: data.userName }))
        
        // Auto-clear typing after 3 seconds
        setTimeout(() => {
          setTypingUsers(prev => {
            const newState = { ...prev }
            delete newState[data.userId]
            return newState
          })
        }, 3000)
      } else if (!data.userName) {
        // Stop typing
        setTypingUsers(prev => {
          const newState = { ...prev }
          delete newState[data.userId]
          return newState
        })
      }
    })

    return () => {
      console.log('[Supabase Realtime] Cleaning up typing indicators')
      unsubscribeTyping()
    }
  }, [isConnected, selectedThread?.id, session?.user?.id, onTyping])

  async function searchMessages(query: string) {
    if (!query.trim()) {
      fetchMessages(selectedThread!.id, selectedTopic)
      return
    }

    try {
      const response = await fetch(
        `/api/teams/${teamId}/messages/search?q=${encodeURIComponent(query)}&threadId=${selectedThread!.id}`
      )
      const data = await response.json()
      setMessages(data.messages)
    } catch {
      toast.error('Search failed')
    }
  }

  async function sendMessage() {
    if (!newMessage.trim() && !editingMessage) return

    setSending(true)
    try {
      if (editingMessage) {
        // Edit existing message
        const response = await fetch(
          `/api/teams/${teamId}/messages/${editingMessage.id}`,
          {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: newMessage })
          }
        )

        if (!response.ok) throw new Error('Failed to edit message')

        const data = await response.json()
        setMessages(messages.map(m => m.id === editingMessage.id ? data.message : m))
        setEditingMessage(null)
        toast.success('Message updated')
      } else {
        // Send new message
        const response = await fetch(`/api/teams/${teamId}/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content: newMessage,
            threadId: selectedThread?.id,
            topicId: selectedTopic,
            replyToId: replyingTo?.id
          })
        })

        if (!response.ok) throw new Error('Failed to send message')

        const data = await response.json()
        setMessages([...messages, data.message])
        setReplyingTo(null)
      }

      setNewMessage('')
    } catch {
      toast.error('Failed to send message')
    } finally {
      setSending(false)
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files
    if (!files || files.length === 0) return

    // Validate files
    for (const file of Array.from(files)) {
      if (file.size > 10 * 1024 * 1024) {
        toast.error(`${file.name} is too large. Max size is 10MB`)
        return
      }
    }

    setSending(true)
    try {
      const attachments = []

      for (const file of Array.from(files)) {
        const reader = new FileReader()
        const base64 = await new Promise<string>((resolve) => {
          reader.onloadend = () => resolve(reader.result as string)
          reader.readAsDataURL(file)
        })

        attachments.push({
          name: file.name,
          url: base64, // In production, upload to cloud storage
          type: file.type,
          size: file.size
        })
      }

      const response = await fetch(`/api/teams/${teamId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: newMessage || 'Sent an attachment',
          threadId: selectedThread?.id,
          topicId: selectedTopic,
          attachments
        })
      })

      if (!response.ok) throw new Error('Failed to send message')

      const data = await response.json()
      setMessages([...messages, data.message])
      setNewMessage('')
      toast.success('File(s) sent')
    } catch {
      toast.error('Failed to send file(s)')
    } finally {
      setSending(false)
    }
  }

  async function addReaction(messageId: string, emoji: string) {
    try {
      const response = await fetch(
        `/api/teams/${teamId}/messages/${messageId}/reactions`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ emoji })
        }
      )

      if (!response.ok) throw new Error('Failed to add reaction')

      const data = await response.json()
      setMessages(messages.map(m => m.id === messageId ? data.message : m))
    } catch {
      toast.error('Failed to add reaction')
    }
  }

  async function pinMessage(messageId: string) {
    try {
      const response = await fetch(
        `/api/teams/${teamId}/messages/${messageId}/pin`,
        {
          method: 'POST'
        }
      )

      if (!response.ok) throw new Error('Failed to pin message')

      const data = await response.json()
      setMessages(messages.map(m => m.id === messageId ? data.message : m))
      toast.success('Message pinned')
    } catch {
      toast.error('Failed to pin message')
    }
  }

  async function deleteMessage(messageId: string) {
    if (!confirm('Delete this message?')) return

    try {
      const response = await fetch(
        `/api/teams/${teamId}/messages/${messageId}`,
        {
          method: 'DELETE'
        }
      )

      if (!response.ok) throw new Error('Failed to delete message')

      setMessages(messages.filter(m => m.id !== messageId))
      toast.success('Message deleted')
    } catch {
      toast.error('Failed to delete message')
    }
  }

  // Enhanced search functionality - search by title, description, and participant names
  const filteredThreads = searchQuery
    ? (threads || []).filter(t => {
        const query = searchQuery.toLowerCase()
        const matchesTitle = t.title?.toLowerCase().includes(query)
        const matchesDescription = t.description?.toLowerCase().includes(query)
        
        // Search by participant names if available
        const matchesParticipant = t.participants?.some(p =>
          p.user?.name?.toLowerCase().includes(query) ||
          p.displayName?.toLowerCase().includes(query)
        )
        
        return matchesTitle || matchesDescription || matchesParticipant
      })
    : (threads || [])

  const pinnedMessages = messages.filter(m => m.isPinned)

  const getThreadIcon = (thread: Thread) => {
    if (thread.isChannel) return <Radio className="w-4 h-4" />
    if (thread.type === 'DIRECT') return <MessageSquare className="w-4 h-4" />
    return <Users className="w-4 h-4" />
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

  return (
    <div className="grid grid-cols-4 gap-4 h-[700px]">
      {/* Sidebar: Thread List */}
      <Card className="col-span-1">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Conversations</CardTitle>
            <CreateConversationDialog
              teamId={teamId}
              open={false}
              onOpenChange={() => {}}
              isAdmin={false}
              onCreated={fetchThreads}
            />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {/* Search */}
          <div className="px-3 pb-3">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search conversations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8"
              />
            </div>
          </div>

          <ScrollArea className="h-[580px]">
            {filteredThreads.map((thread) => (
              <button
                key={thread.id}
                onClick={() => {
                  setSelectedThread(thread)
                  setSelectedTopic(null)
                  setSearchQuery('')
                }}
                className={`w-full p-3 text-left border-b hover:bg-muted/50 transition-colors ${
                  selectedThread?.id === thread.id ? 'bg-muted' : ''
                }`}
              >
                <div className="flex items-start gap-2">
                  {thread.avatar ? (
                    <Avatar className="h-10 w-10">
                      <AvatarImage src={thread.avatar} />
                      <AvatarFallback>
                        {getThreadIcon(thread)}
                      </AvatarFallback>
                    </Avatar>
                  ) : (
                    <div className="h-10 w-10 rounded-full bg-muted flex items-center justify-center">
                      {getThreadIcon(thread)}
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm truncate">
                        {thread.title || 'Unnamed Thread'}
                      </span>
                      {thread.isPinned && (
                        <Pin className="w-3 h-3 text-muted-foreground" />
                      )}
                    </div>
                    {thread.description && (
                      <p className="text-xs text-muted-foreground truncate">
                        {thread.description}
                      </p>
                    )}
                    {thread.lastMessageAt && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {formatDistanceToNow(new Date(thread.lastMessageAt), {
                          addSuffix: true
                        })}
                      </p>
                    )}
                  </div>
                </div>
              </button>
            ))}
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Main Area: Messages */}
      <Card className="col-span-3 flex flex-col">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {selectedThread?.avatar ? (
                <Avatar>
                  <AvatarImage src={selectedThread.avatar} />
                  <AvatarFallback>
                    {getThreadIcon(selectedThread)}
                  </AvatarFallback>
                </Avatar>
              ) : (
                selectedThread && (
                  <div className="h-10 w-10 rounded-full bg-muted flex items-center justify-center">
                    {getThreadIcon(selectedThread)}
                  </div>
                )
              )}
              <div>
                <h3 className="font-semibold">
                  {selectedThread?.title || 'Select a conversation'}
                </h3>
                {selectedThread?.description && (
                  <p className="text-sm text-muted-foreground">
                    {selectedThread.description}
                  </p>
                )}
              </div>
            </div>

            {selectedThread && (
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search messages..."
                    className="pl-8 w-[200px]"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        searchMessages((e.target as HTMLInputElement).value)
                      }
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Topics (if enabled) */}
          {selectedThread?.enableTopics && selectedThread.topics && selectedThread.topics.length > 0 && (
            <div className="mt-3 flex gap-2 overflow-x-auto">
              <Button
                variant={selectedTopic === null ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedTopic(null)}
              >
                <Hash className="w-4 h-4 mr-1" />
                All
              </Button>
              {selectedThread.topics.map((topic) => (
                <Button
                  key={topic.id}
                  variant={selectedTopic === topic.id ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setSelectedTopic(topic.id)}
                  style={{ borderColor: topic.color }}
                >
                  {topic.icon && <span className="mr-1">{topic.icon}</span>}
                  {topic.name}
                </Button>
              ))}
            </div>
          )}
        </CardHeader>

        <Separator />

        {/* Pinned Messages */}
        {pinnedMessages.length > 0 && (
          <>
            <div className="px-4 py-2 bg-muted/50">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Pin className="w-4 h-4" />
                Pinned Messages
              </div>
              <ScrollArea className="max-h-[100px] mt-2">
                {pinnedMessages.map((msg) => (
                  <div key={msg.id} className="text-sm p-2 bg-background rounded mb-1">
                    <span className="font-medium">
                      {msg.sender.displayName || msg.sender.user.name}:
                    </span>{' '}
                    {msg.content}
                  </div>
                ))}
              </ScrollArea>
            </div>
            <Separator />
          </>
        )}

        <CardContent className="flex-1 flex flex-col p-0">
          {/* Messages List */}
          <ScrollArea className="flex-1 p-4" ref={scrollRef}>
            {!selectedThread ? (
              <div className="flex items-center justify-center h-full">
                <p className="text-muted-foreground">Select a conversation to start messaging</p>
              </div>
            ) : messages.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <p className="text-muted-foreground">No messages yet. Start the conversation!</p>
              </div>
            ) : (
              <div className="space-y-4">
                {messages.map((message) => {
                  const isOwnMessage = message.senderId === currentMemberId

                  return (
                    <div key={message.id} className="group">
                      {message.replyTo && (
                        <div className="ml-12 mb-1 pl-3 border-l-2 border-muted-foreground/30 text-sm text-muted-foreground">
                          <span className="font-medium">
                            {message.replyTo.sender.displayName || message.replyTo.sender.user.name}
                          </span>
                          : {message.replyTo.content}
                        </div>
                      )}

                      <div className="flex gap-3">
                        <Avatar className="h-8 w-8">
                          <AvatarImage
                            src={message.sender.avatar || message.sender.user.image}
                          />
                          <AvatarFallback>
                            {message.sender.user.name?.[0] || 'U'}
                          </AvatarFallback>
                        </Avatar>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium text-sm">
                              {message.sender.displayName || message.sender.user.name}
                            </span>
                            <span className="text-xs text-muted-foreground">
                              {formatDistanceToNow(new Date(message.createdAt), {
                                addSuffix: true
                              })}
                            </span>
                            {message.isEdited && (
                              <Badge variant="secondary" className="text-xs">
                                Edited
                              </Badge>
                            )}
                            {message.isPinned && (
                              <Pin className="w-3 h-3 text-muted-foreground" />
                            )}
                          </div>

                          <div className="text-sm bg-muted p-3 rounded-lg">
                            {message.content}
                          </div>

                          {/* Attachments */}
                          {message.attachments && message.attachments.length > 0 && (
                            <div className="mt-2 space-y-2">
                              {message.attachments.map((att, idx) => (
                                <div
                                  key={idx}
                                  className="flex items-center gap-2 p-2 border rounded-lg"
                                >
                                  <Paperclip className="w-4 h-4" />
                                  <span className="text-sm flex-1">{att.name}</span>
                                  <span className="text-xs text-muted-foreground">
                                    {(att.size / 1024).toFixed(1)} KB
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* Reactions */}
                          {message.reactions && Object.keys(message.reactions).length > 0 && (
                            <div className="flex gap-1 mt-2">
                              {Object.entries(message.reactions).map(([emoji, users]) => (
                                <Button
                                  key={emoji}
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 px-2"
                                  onClick={() => addReaction(message.id, emoji)}
                                >
                                  {emoji} {users.length}
                                </Button>
                              ))}
                            </div>
                          )}
                        </div>

                        {/* Message Actions */}
                        <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm">
                                <MoreVertical className="w-4 h-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => setReplyingTo(message)}>
                                <Reply className="w-4 h-4 mr-2" />
                                Reply
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => addReaction(message.id, '👍')}>
                                <Smile className="w-4 h-4 mr-2" />
                                React
                              </DropdownMenuItem>
                              {isAdmin && (
                                <DropdownMenuItem onClick={() => pinMessage(message.id)}>
                                  <Pin className="w-4 h-4 mr-2" />
                                  {message.isPinned ? 'Unpin' : 'Pin'}
                                </DropdownMenuItem>
                              )}
                              {isOwnMessage && (
                                <>
                                  <DropdownMenuSeparator />
                                  <DropdownMenuItem
                                    onClick={() => {
                                      setEditingMessage(message)
                                      setNewMessage(message.content)
                                    }}
                                  >
                                    <Edit2 className="w-4 h-4 mr-2" />
                                    Edit
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() => deleteMessage(message.id)}
                                    className="text-destructive"
                                  >
                                    <Trash2 className="w-4 h-4 mr-2" />
                                    Delete
                                  </DropdownMenuItem>
                                </>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </ScrollArea>

          {/* Message Input */}
          {selectedThread && (
            <div className="p-4 border-t">
              {/* Typing Indicators */}
              {Object.keys(typingUsers).length > 0 && (
                <div className="mb-2 text-sm text-muted-foreground italic">
                  {Object.values(typingUsers).join(', ')} {Object.keys(typingUsers).length === 1 ? 'is' : 'are'} typing...
                </div>
              )}
              
              {/* Reply Preview */}
              {replyingTo && (
                <div className="mb-2 p-2 bg-muted rounded flex items-center justify-between">
                  <div className="text-sm">
                    <span className="font-medium">Replying to {replyingTo.sender.displayName || replyingTo.sender.user.name}</span>
                    <p className="text-muted-foreground truncate">{replyingTo.content}</p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setReplyingTo(null)}
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>
              )}

              {/* Edit Preview */}
              {editingMessage && (
                <div className="mb-2 p-2 bg-muted rounded flex items-center justify-between">
                  <div className="text-sm">
                    <span className="font-medium">Editing message</span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setEditingMessage(null)
                      setNewMessage('')
                    }}
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>
              )}

              <div className="flex gap-2">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  className="hidden"
                  multiple
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={sending || (selectedThread?.isChannel && !isAdmin)}
                >
                  <Paperclip className="w-4 h-4" />
                </Button>
                <Textarea
                  placeholder={
                    selectedThread?.isChannel && !isAdmin
                      ? 'Only admins can post in channels'
                      : 'Type your message...'
                  }
                  value={newMessage}
                  onChange={(e) => {
                    setNewMessage(e.target.value)
                    
                    // Typing indicator
                    if (e.target.value && selectedThread && session?.user?.name) {
                      emitTyping(teamId, selectedThread.id, session.user.name)
                      
                      // Clear existing timeout
                      if (typingTimeoutRef.current) {
                        clearTimeout(typingTimeoutRef.current)
                      }
                      
                      // Stop typing after 3 seconds of inactivity
                      typingTimeoutRef.current = setTimeout(() => {
                        stopTyping(teamId, selectedThread.id)
                      }, 3000)
                    } else if (!e.target.value && selectedThread) {
                      stopTyping(teamId, selectedThread.id)
                      if (typingTimeoutRef.current) {
                        clearTimeout(typingTimeoutRef.current)
                      }
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault()
                      sendMessage()
                      if (selectedThread) {
                        stopTyping(teamId, selectedThread.id)
                      }
                      if (typingTimeoutRef.current) {
                        clearTimeout(typingTimeoutRef.current)
                      }
                    }
                  }}
                  rows={2}
                  disabled={selectedThread?.isChannel && !isAdmin}
                  className="flex-1"
                />
                <Button
                  onClick={sendMessage}
                  disabled={sending || !newMessage.trim() || (selectedThread?.isChannel && !isAdmin)}
                >
                  {sending ? (
                    <LoadingSpinner />
                  ) : (
                    <Send className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

