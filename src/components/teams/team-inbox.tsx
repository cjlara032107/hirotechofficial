'use client'

import { useEffect, useState, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { ScrollArea } from '@/components/ui/scroll-area'
import { formatDistanceToNow } from 'date-fns'
import { Send, Plus, Users } from 'lucide-react'
import { toast } from 'sonner'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { useSupabaseRealtime } from '@/contexts/supabase-realtime-context'

interface Thread {
  id: string
  title?: string | null
  type: string
  lastMessageAt?: Date | string | null
  participantIds: string[]
}

interface Message {
  id: string
  content: string
  createdAt: Date | string
  sender: {
    id: string
    user: {
      name: string | null
      image: string | null
    }
  }
}

interface TeamInboxProps {
  teamId: string
  currentMemberId: string
}

export function TeamInbox({ teamId }: TeamInboxProps) {
  const [threads, setThreads] = useState<Thread[]>([])
  const [selectedThread, setSelectedThread] = useState<Thread | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [newMessage, setNewMessage] = useState('')
  
  const { isConnected, subscribeToTeamMessages, subscribeToTeamThreads } = useSupabaseRealtime()

  const fetchThreads = useCallback(async () => {
    try {
      const response = await fetch(`/api/teams/${teamId}/threads`)
      const data = await response.json()
      setThreads(data.threads)
      if (data.threads.length > 0 && !selectedThread) {
        setSelectedThread(data.threads[0])
      }
    } catch (error) {
      console.error('Error fetching threads:', error)
      toast.error('Failed to load conversations')
    } finally {
      setLoading(false)
    }
  }, [teamId, selectedThread])

  const fetchMessages = useCallback(async (threadId: string) => {
    try {
      const response = await fetch(`/api/teams/${teamId}/messages?threadId=${threadId}`)
      const data = await response.json()
      setMessages(data.messages)
    } catch (error) {
      console.error('Error fetching messages:', error)
    }
  }, [teamId])

  useEffect(() => {
    fetchThreads()
  }, [fetchThreads])

  useEffect(() => {
    if (selectedThread) {
      fetchMessages(selectedThread.id)
    }
  }, [selectedThread, fetchMessages])

  // Supabase Realtime subscriptions
  useEffect(() => {
    if (!isConnected || !teamId) return

    console.log('[Supabase Realtime] Setting up basic inbox listeners for team:', teamId)

    // Subscribe to team messages
    const unsubscribeMessages = subscribeToTeamMessages(teamId, {
      onInsert: async (message) => {
        // Fetch full message data with relations from API
        try {
          const response = await fetch(`/api/teams/${teamId}/messages?limit=1&messageId=${message.id}`)
          const data = await response.json()
          
          if (data.messages && data.messages.length > 0) {
            const fullMessage = data.messages[0]
            
            if (selectedThread?.id === fullMessage.threadId) {
              setMessages(prev => {
                // Check if message already exists (avoid duplicates)
                const exists = prev.some(m => m.id === fullMessage.id)
                if (exists) return prev
                return [...prev, fullMessage]
              })
            }
            
            // Update thread last message time
            if (fullMessage.threadId) {
              setThreads(prev => prev.map(t => 
                t.id === fullMessage.threadId 
                  ? { ...t, lastMessageAt: fullMessage.createdAt }
                  : t
              ))
            }
          }
        } catch (error) {
          console.error('[Supabase Realtime] Error fetching full message:', error)
        }
      },
      onUpdate: async (message) => {
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
        setMessages(prev => prev.filter(m => m.id !== messageId))
      }
    })

    // Subscribe to team threads
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
      console.log('[Supabase Realtime] Cleaning up basic inbox listeners')
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

      const data = await response.json()
      // Message will be added via Realtime subscription
      setNewMessage('')
      toast.success('Message sent')
    } catch (error) {
      toast.error('Failed to send message')
    } finally {
      setSending(false)
    }
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
    <div className="grid grid-cols-3 gap-4 h-[600px]">
      <Card className="col-span-1">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Conversations</CardTitle>
            <Button size="sm" variant="outline">
              <Plus className="w-4 h-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <ScrollArea className="h-[500px]">
            {threads.map((thread) => (
              <button
                key={thread.id}
                onClick={() => setSelectedThread(thread)}
                className={`w-full p-4 text-left border-b hover:bg-muted/50 transition-colors ${
                  selectedThread?.id === thread.id ? 'bg-muted' : ''
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Users className="w-4 h-4" />
                  <span className="font-medium text-sm">{thread.title || 'Unnamed Thread'}</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {thread.participantIds.length} participants
                </p>
              </button>
            ))}
          </ScrollArea>
        </CardContent>
      </Card>

      <Card className="col-span-2">
        <CardHeader>
          <CardTitle>
            {selectedThread?.title || 'Select a conversation'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <ScrollArea className="h-[400px] pr-4">
            {messages.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">
                No messages yet. Start the conversation!
              </p>
            ) : (
              <div className="space-y-4">
                {messages.map((message) => (
                  <div key={message.id} className="flex gap-3">
                    <Avatar className="h-8 w-8">
                      <AvatarImage src={message.sender.user.image || undefined} />
                      <AvatarFallback>
                        {message.sender.user.name?.[0] || 'U'}
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-sm">
                          {message.sender.user.name}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {formatDistanceToNow(new Date(message.createdAt), { addSuffix: true })}
                        </span>
                      </div>
                      <p className="text-sm">{message.content}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>

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
            />
            <Button onClick={sendMessage} disabled={sending || !newMessage.trim()}>
              <Send className="w-4 h-4" />
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
