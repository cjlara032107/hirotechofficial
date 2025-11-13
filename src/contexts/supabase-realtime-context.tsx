'use client'

import { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react'
import { createClient } from '@/lib/supabase/client'
import { RealtimeChannel, RealtimePostgresChangesPayload } from '@supabase/supabase-js'

interface TeamMessage {
  id: string
  content: string
  senderId: string
  teamId: string
  threadId: string | null
  createdAt: string
  isEdited: boolean
  isDeleted: boolean
  mentions: string[]
  reactions?: Record<string, string[]>
  attachments?: any
  replyToId?: string
  isPinned: boolean
}

interface TeamThread {
  id: string
  teamId: string
  title?: string
  description?: string
  type: string
  participantIds: string[]
  avatar?: string
  isChannel: boolean
  enableTopics: boolean
  isPinned: boolean
  lastMessageAt?: string
}

interface SupabaseRealtimeContextType {
  isConnected: boolean
  subscribeToTeamMessages: (teamId: string, callbacks: MessageCallbacks) => () => void
  subscribeToTeamThreads: (teamId: string, callbacks: ThreadCallbacks) => () => void
  subscribeToThreadMessages: (threadId: string, callbacks: MessageCallbacks) => () => void
  emitTyping: (teamId: string, threadId: string, userName: string) => void
  stopTyping: (teamId: string, threadId: string) => void
  onTyping: (threadId: string, callback: (data: TypingData) => void) => () => void
}

interface MessageCallbacks {
  onInsert?: (message: TeamMessage) => void | Promise<void>
  onUpdate?: (message: TeamMessage) => void | Promise<void>
  onDelete?: (messageId: string) => void | Promise<void>
}

interface ThreadCallbacks {
  onInsert?: (thread: TeamThread) => void
  onUpdate?: (thread: TeamThread) => void
}

interface TypingData {
  threadId: string
  userId: string
  userName: string
}

const SupabaseRealtimeContext = createContext<SupabaseRealtimeContextType>({
  isConnected: false,
  subscribeToTeamMessages: () => () => {},
  subscribeToTeamThreads: () => () => {},
  subscribeToThreadMessages: () => () => {},
  emitTyping: () => {},
  stopTyping: () => {},
  onTyping: () => () => {}
})

export function useSupabaseRealtime() {
  return useContext(SupabaseRealtimeContext)
}

export function SupabaseRealtimeProvider({ children }: { children: React.ReactNode }) {
  const [isConnected, setIsConnected] = useState(false)
  const supabase = createClient()
  const channelsRef = useRef<Map<string, RealtimeChannel>>(new Map())
  const typingCallbacksRef = useRef<Map<string, Set<(data: TypingData) => void>>>(new Map())

  useEffect(() => {
    // Check if Supabase is properly configured
    if (supabase) {
      // Defer state update to avoid synchronous setState in effect
      queueMicrotask(() => {
        setIsConnected(true)
        console.log('[Supabase Realtime] Connected and ready')
      })
    }

    return () => {
      // Cleanup all channels on unmount
      console.log('[Supabase Realtime] Cleaning up all channels')
      const channels = channelsRef.current
      const typingCallbacks = typingCallbacksRef.current
      
      channels.forEach((channel) => {
        supabase.removeChannel(channel)
      })
      channels.clear()
      typingCallbacks.clear()
    }
  }, [supabase])

  const subscribeToTeamMessages = useCallback((teamId: string, callbacks: MessageCallbacks) => {
    const channelName = `team:${teamId}:messages`
    
    console.log('[Supabase Realtime] Subscribing to team messages:', channelName)

    const channel = supabase
      .channel(channelName)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'TeamMessage',
          filter: `teamId=eq.${teamId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamMessage>) => {
          console.log('[Supabase Realtime] 🔔 INSERT event received:', {
            table: 'TeamMessage',
            messageId: (payload.new as TeamMessage)?.id,
            teamId: (payload.new as TeamMessage)?.teamId,
            eventType: payload.eventType,
            timestamp: new Date().toISOString()
          })
          
          if (callbacks.onInsert && payload.new) {
            callbacks.onInsert(payload.new as TeamMessage)
          } else {
            console.warn('[Supabase Realtime] ⚠️ INSERT callback missing or no payload')
          }
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'TeamMessage',
          filter: `teamId=eq.${teamId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamMessage>) => {
          console.log('[Supabase Realtime] Message updated:', payload.new)
          if (callbacks.onUpdate && payload.new) {
            callbacks.onUpdate(payload.new as TeamMessage)
          }
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'DELETE',
          schema: 'public',
          table: 'TeamMessage',
          filter: `teamId=eq.${teamId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamMessage>) => {
          console.log('[Supabase Realtime] Message deleted:', payload.old)
          if (callbacks.onDelete && payload.old) {
            callbacks.onDelete((payload.old as TeamMessage).id)
          }
        }
      )
      .subscribe((status, err) => {
        console.log('[Supabase Realtime] 📡 Team messages subscription status:', {
          status,
          error: err,
          channel: channelName,
          teamId,
          timestamp: new Date().toISOString()
        })
        
        if (status === 'SUBSCRIBED') {
          console.log('[Supabase Realtime] ✅ Successfully subscribed to team messages')
        } else if (status === 'CHANNEL_ERROR') {
          console.error('[Supabase Realtime] ❌ Channel error - check Supabase configuration!')
        } else if (status === 'TIMED_OUT') {
          console.error('[Supabase Realtime] ⏱️ Subscription timed out')
        } else if (status === 'CLOSED') {
          console.warn('[Supabase Realtime] 🔌 Channel closed')
        }
      })

    channelsRef.current.set(channelName, channel)

    // Return cleanup function
    return () => {
      console.log('[Supabase Realtime] Unsubscribing from team messages:', channelName)
      supabase.removeChannel(channel)
      channelsRef.current.delete(channelName)
    }
  }, [supabase])

  const subscribeToTeamThreads = useCallback((teamId: string, callbacks: ThreadCallbacks) => {
    const channelName = `team:${teamId}:threads`
    
    console.log('[Supabase Realtime] Subscribing to team threads:', channelName)

    const channel = supabase
      .channel(channelName)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'TeamThread',
          filter: `teamId=eq.${teamId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamThread>) => {
          console.log('[Supabase Realtime] New thread:', payload.new)
          if (callbacks.onInsert && payload.new) {
            callbacks.onInsert(payload.new as TeamThread)
          }
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'TeamThread',
          filter: `teamId=eq.${teamId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamThread>) => {
          console.log('[Supabase Realtime] Thread updated:', payload.new)
          if (callbacks.onUpdate && payload.new) {
            callbacks.onUpdate(payload.new as TeamThread)
          }
        }
      )
      .subscribe((status) => {
        console.log('[Supabase Realtime] Team threads subscription status:', status)
      })

    channelsRef.current.set(channelName, channel)

    return () => {
      console.log('[Supabase Realtime] Unsubscribing from team threads:', channelName)
      supabase.removeChannel(channel)
      channelsRef.current.delete(channelName)
    }
  }, [supabase])

  const subscribeToThreadMessages = useCallback((threadId: string, callbacks: MessageCallbacks) => {
    const channelName = `thread:${threadId}:messages`
    
    console.log('[Supabase Realtime] Subscribing to thread messages:', channelName)

    const channel = supabase
      .channel(channelName)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'TeamMessage',
          filter: `threadId=eq.${threadId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamMessage>) => {
          console.log('[Supabase Realtime] New message in thread:', payload.new)
          if (callbacks.onInsert && payload.new) {
            callbacks.onInsert(payload.new as TeamMessage)
          }
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'TeamMessage',
          filter: `threadId=eq.${threadId}`
        },
        (payload: RealtimePostgresChangesPayload<TeamMessage>) => {
          console.log('[Supabase Realtime] Message updated in thread:', payload.new)
          if (callbacks.onUpdate && payload.new) {
            callbacks.onUpdate(payload.new as TeamMessage)
          }
        }
      )
      .subscribe((status) => {
        console.log('[Supabase Realtime] Thread messages subscription status:', status)
      })

    channelsRef.current.set(channelName, channel)

    return () => {
      console.log('[Supabase Realtime] Unsubscribing from thread messages:', channelName)
      supabase.removeChannel(channel)
      channelsRef.current.delete(channelName)
    }
  }, [supabase])

  const emitTyping = useCallback((teamId: string, threadId: string, userName: string) => {
    const channelName = `typing:${threadId}`
    
    let channel = channelsRef.current.get(channelName)
    
    if (!channel) {
      channel = supabase.channel(channelName)
      channel.subscribe()
      channelsRef.current.set(channelName, channel)
    }

    channel.send({
      type: 'broadcast',
      event: 'typing',
      payload: {
        threadId,
        userName,
        timestamp: Date.now()
      }
    })
  }, [supabase])

  const stopTyping = useCallback((teamId: string, threadId: string) => {
    const channelName = `typing:${threadId}`
    
    const channel = channelsRef.current.get(channelName)
    if (channel) {
      channel.send({
        type: 'broadcast',
        event: 'stop-typing',
        payload: {
          threadId,
          timestamp: Date.now()
        }
      })
    }
  }, [supabase])

  const onTyping = useCallback((threadId: string, callback: (data: TypingData) => void) => {
    const channelName = `typing:${threadId}`
    
    // Store callback
    if (!typingCallbacksRef.current.has(channelName)) {
      typingCallbacksRef.current.set(channelName, new Set())
    }
    typingCallbacksRef.current.get(channelName)!.add(callback)

    let channel = channelsRef.current.get(channelName)
    
    if (!channel) {
      channel = supabase
        .channel(channelName)
        .on('broadcast', { event: 'typing' }, ({ payload }) => {
          console.log('[Supabase Realtime] Typing event:', payload)
          const callbacks = typingCallbacksRef.current.get(channelName)
          if (callbacks) {
            callbacks.forEach(cb => cb(payload as TypingData))
          }
        })
        .on('broadcast', { event: 'stop-typing' }, ({ payload }) => {
          console.log('[Supabase Realtime] Stop typing event:', payload)
          const callbacks = typingCallbacksRef.current.get(channelName)
          if (callbacks) {
            callbacks.forEach(cb => cb({ ...payload, userName: '' } as TypingData))
          }
        })
        .subscribe()

      channelsRef.current.set(channelName, channel)
    }

    // Return cleanup function
    return () => {
      const callbacks = typingCallbacksRef.current.get(channelName)
      if (callbacks) {
        callbacks.delete(callback)
        
        // If no more callbacks, remove channel
        if (callbacks.size === 0) {
          const ch = channelsRef.current.get(channelName)
          if (ch) {
            supabase.removeChannel(ch)
            channelsRef.current.delete(channelName)
          }
          typingCallbacksRef.current.delete(channelName)
        }
      }
    }
  }, [supabase])

  return (
    <SupabaseRealtimeContext.Provider
      value={{
        isConnected,
        subscribeToTeamMessages,
        subscribeToTeamThreads,
        subscribeToThreadMessages,
        emitTyping,
        stopTyping,
        onTyping
      }}
    >
      {children}
    </SupabaseRealtimeContext.Provider>
  )
}

