'use client'

import { useEffect, useState } from 'react'
import { useSupabaseRealtime } from '@/contexts/supabase-realtime-context'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { CheckCircle, XCircle, AlertCircle } from 'lucide-react'

interface DebugInfo {
  isConnected: boolean
  subscriptionActive: boolean
  lastEventTime: string | null
  eventCount: number
  errors: string[]
}

export function RealtimeDebugPanel({ teamId }: { teamId: string }) {
  const { isConnected } = useSupabaseRealtime()
  const [debugInfo, setDebugInfo] = useState<DebugInfo>({
    isConnected: false,
    subscriptionActive: false,
    lastEventTime: null,
    eventCount: 0,
    errors: []
  })

  useEffect(() => {
    // Defer state update to avoid synchronous setState in effect
    Promise.resolve().then(() => {
      setDebugInfo(prev => ({
        ...prev,
        isConnected
      }))
    })
  }, [isConnected])

  // Listen for console logs to detect events
  useEffect(() => {
    const originalLog = console.log
    const originalError = console.error

    console.log = (...args) => {
      originalLog(...args)
      if (args[0]?.includes?.('[Supabase Realtime]')) {
        setDebugInfo(prev => ({
          ...prev,
          subscriptionActive: true,
          lastEventTime: new Date().toISOString(),
          eventCount: prev.eventCount + 1
        }))
      }
    }

    console.error = (...args) => {
      originalError(...args)
      if (args[0]?.includes?.('[Supabase Realtime]')) {
        setDebugInfo(prev => ({
          ...prev,
          errors: [...prev.errors, args.join(' ')].slice(-5)
        }))
      }
    }

    return () => {
      console.log = originalLog
      console.error = originalError
    }
  }, [])

  return (
    <Card className="mb-4 border-yellow-500">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          🐛 Realtime Debug Panel
          {isConnected ? (
            <Badge variant="default" className="gap-1">
              <CheckCircle className="w-3 h-3" />
              Connected
            </Badge>
          ) : (
            <Badge variant="destructive" className="gap-1">
              <XCircle className="w-3 h-3" />
              Disconnected
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-xs">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <span className="font-semibold">Team ID:</span> {teamId}
          </div>
          <div>
            <span className="font-semibold">Events Received:</span> {debugInfo.eventCount}
          </div>
          <div>
            <span className="font-semibold">Subscription:</span>{' '}
            {debugInfo.subscriptionActive ? '✅ Active' : '❌ Inactive'}
          </div>
          <div>
            <span className="font-semibold">Last Event:</span>{' '}
            {debugInfo.lastEventTime 
              ? new Date(debugInfo.lastEventTime).toLocaleTimeString()
              : 'None'}
          </div>
        </div>

        {debugInfo.errors.length > 0 && (
          <div className="mt-3 p-2 bg-red-50 dark:bg-red-950 rounded">
            <div className="flex items-center gap-2 mb-1">
              <AlertCircle className="w-4 h-4 text-red-600" />
              <span className="font-semibold text-red-600">Recent Errors:</span>
            </div>
            {debugInfo.errors.map((error, i) => (
              <div key={i} className="text-red-700 dark:text-red-300 text-xs">
                {error}
              </div>
            ))}
          </div>
        )}

        <div className="mt-3 p-2 bg-blue-50 dark:bg-blue-950 rounded text-blue-900 dark:text-blue-100">
          <strong>Troubleshooting:</strong>
          <ol className="list-decimal list-inside mt-1 space-y-1">
            <li>Check Supabase Dashboard → Database → Replication</li>
            <li>Ensure TeamMessage table replication is enabled</li>
            <li>Open browser console and look for Realtime logs</li>
            <li>Try refreshing the page</li>
          </ol>
        </div>
      </CardContent>
    </Card>
  )
}

