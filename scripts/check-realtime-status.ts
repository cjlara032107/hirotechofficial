/**
 * Quick script to check Supabase Realtime status
 * Run: npx tsx scripts/check-realtime-status.ts
 */

import { prisma } from '../src/lib/db'

const requiredTables = [
  'Contact',
  'Pipeline',
  'PipelineStage',
  'PipelineAutomation',
  'TeamMessage',
  'TeamThread'
]

async function checkRealtimeStatus() {
  console.log('🔍 Checking Supabase Realtime Status...\n')

  try {
    // Query PostgreSQL publication tables
    const enabledTables = await prisma.$queryRaw<Array<{ schemaname: string; tablename: string }>>`
      SELECT schemaname, tablename 
      FROM pg_publication_tables 
      WHERE pubname = 'supabase_realtime'
      AND schemaname = 'public'
      ORDER BY tablename
    `

    const enabledTableNames = enabledTables.map(t => t.tablename)

    console.log('📊 Realtime Status:\n')
    
    let allEnabled = true
    const missingTables: string[] = []

    requiredTables.forEach(table => {
      const isEnabled = enabledTableNames.includes(table)
      const status = isEnabled ? '✅ Enabled' : '❌ Not Enabled'
      console.log(`   ${table.padEnd(25)} ${status}`)
      
      if (!isEnabled) {
        allEnabled = false
        missingTables.push(table)
      }
    })

    console.log('\n' + '='.repeat(50) + '\n')

    if (allEnabled) {
      console.log('✅ All required tables have Realtime enabled!')
      console.log('🎉 Your Supabase Realtime is fully configured.\n')
    } else {
      console.log('⚠️  Some tables are missing Realtime configuration.\n')
      console.log('📝 To enable Realtime, run this SQL in Supabase SQL Editor:\n')
      console.log('```sql')
      missingTables.forEach(table => {
        console.log(`ALTER PUBLICATION supabase_realtime ADD TABLE "${table}";`)
      })
      console.log('```\n')
      
      console.log('Or enable via Supabase Dashboard:')
      console.log('1. Go to Database → Replication')
      console.log('2. Enable INSERT, UPDATE, DELETE for each missing table\n')
    }

    // Show all enabled tables (including ones not in our required list)
    if (enabledTableNames.length > 0) {
      console.log('📋 All tables with Realtime enabled:')
      enabledTableNames.forEach(table => {
        const isRequired = requiredTables.includes(table)
        console.log(`   ${table}${isRequired ? ' (required)' : ' (optional)'}`)
      })
      console.log()
    } else {
      console.log('⚠️  No tables have Realtime enabled!\n')
    }

  } catch (error) {
    console.error('❌ Error checking Realtime status:')
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

checkRealtimeStatus()

