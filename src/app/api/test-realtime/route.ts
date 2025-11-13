import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

/**
 * Test endpoint to verify Supabase Realtime configuration
 * Visit: /api/test-realtime
 */
export async function GET() {
  try {
    const supabase = await createClient()
    
    // Check if we can connect to Supabase
    const { data: { user }, error: authError } = await supabase.auth.getUser()
    
    // Test database connection
    const { data: teams, error: dbError } = await supabase
      .from('Team')
      .select('id, name')
      .limit(1)
    
    // Get Supabase configuration
    const config = {
      supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL,
      hasAnonKey: !!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
      userAuthenticated: !!user,
      databaseConnection: !dbError,
    }
    
    return NextResponse.json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      config,
      warnings: [
        !config.hasAnonKey && 'Missing NEXT_PUBLIC_SUPABASE_ANON_KEY',
        !config.databaseConnection && 'Database connection failed',
        !config.userAuthenticated && 'User not authenticated (expected for this endpoint)',
      ].filter(Boolean),
      instructions: {
        realtimeSetup: [
          '1. Go to Supabase Dashboard',
          '2. Navigate to Database → Replication',
          '3. Enable replication for:',
          '   - TeamMessage table',
          '   - TeamThread table',
          '4. Or run SQL:',
          '   ALTER TABLE "TeamMessage" REPLICA IDENTITY FULL;',
          '   ALTER TABLE "TeamThread" REPLICA IDENTITY FULL;',
          '   CREATE PUBLICATION supabase_realtime FOR TABLE "TeamMessage", "TeamThread";'
        ],
        testing: [
          '1. Open two browser tabs',
          '2. Go to /team page in both',
          '3. Send message in Tab 1',
          '4. Should appear in Tab 2 within 1 second',
          '5. Check console for "[Supabase Realtime] New message received"'
        ]
      }
    })
  } catch (error) {
    return NextResponse.json({
      status: 'ERROR',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    }, { status: 500 })
  }
}

