import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { prisma } from '@/lib/db'
import { auth } from '@/auth'

/**
 * Test endpoint to verify Supabase Realtime configuration
 * Visit: /api/test-realtime
 * 
 * Checks:
 * 1. Supabase connection
 * 2. Database connection
 * 3. Realtime publication status for required tables
 */
export async function GET() {
  // Require authentication for security
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  try {
    const supabase = await createClient()
    
    // Check if we can connect to Supabase
    const { data: { user }, error: authError } = await supabase.auth.getUser()
    
    // Test database connection
    const { data: teams, error: dbError } = await supabase
      .from('Team')
      .select('id, name')
      .limit(1)
    
    // Check which tables have realtime enabled
    const requiredTables = ['Contact', 'Pipeline', 'PipelineStage', 'PipelineAutomation', 'TeamMessage', 'TeamThread']
    
    const realtimeStatus: Record<string, boolean> = {}
    let realtimeError: string | null = null
    
    try {
      // Query PostgreSQL publication tables to check if realtime is enabled
      const enabledTables = await prisma.$queryRaw<Array<{ schemaname: string; tablename: string }>>`
        SELECT schemaname, tablename 
        FROM pg_publication_tables 
        WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
      `
      
      const enabledTableNames = enabledTables.map(t => t.tablename)
      
      // Check each required table
      requiredTables.forEach(table => {
        realtimeStatus[table] = enabledTableNames.includes(table)
      })
    } catch (error) {
      realtimeError = error instanceof Error ? error.message : 'Unknown error querying realtime status'
    }
    
    // Get Supabase configuration
    const config = {
      supabaseUrl: process.env.NEXT_PUBLIC_SUPABASE_URL,
      hasAnonKey: !!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
      userAuthenticated: !!user,
      databaseConnection: !dbError,
    }
    
    const allRealtimeEnabled = requiredTables.every(table => realtimeStatus[table] === true)
    const missingTables = requiredTables.filter(table => !realtimeStatus[table])
    
    return NextResponse.json({
      status: allRealtimeEnabled ? 'OK' : 'CONFIGURATION_NEEDED',
      timestamp: new Date().toISOString(),
      config,
      realtime: {
        enabled: allRealtimeEnabled,
        status: realtimeStatus,
        missingTables: missingTables.length > 0 ? missingTables : null,
        error: realtimeError,
      },
      warnings: [
        !config.hasAnonKey && 'Missing NEXT_PUBLIC_SUPABASE_ANON_KEY',
        !config.databaseConnection && 'Database connection failed',
        !allRealtimeEnabled && `Realtime not enabled for: ${missingTables.join(', ')}`,
        realtimeError && `Error checking realtime status: ${realtimeError}`,
      ].filter(Boolean),
      instructions: {
        realtimeSetup: [
          '1. Go to Supabase Dashboard',
          '2. Navigate to Database → Replication',
          '3. Enable replication for these tables:',
          ...requiredTables.map(table => `   - ${table} (${realtimeStatus[table] ? '✅ Enabled' : '❌ Not Enabled'})`),
          '',
          'Or run SQL in Supabase SQL Editor:',
          ...requiredTables
            .filter(table => !realtimeStatus[table])
            .map(table => `ALTER PUBLICATION supabase_realtime ADD TABLE "${table}";`),
          '',
          'Verify with:',
          'SELECT schemaname, tablename FROM pg_publication_tables WHERE pubname = \'supabase_realtime\';'
        ],
        testing: [
          '1. Open pipeline page: /pipelines/[id]',
          '2. Open browser console (F12)',
          '3. Look for: "[Supabase Realtime] Successfully subscribed to all pipeline updates"',
          '4. Should see: "● Live" indicator (green dot)',
          '5. Open same pipeline in another tab',
          '6. Move a contact in Tab 2',
          '7. Should update instantly in Tab 1'
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

