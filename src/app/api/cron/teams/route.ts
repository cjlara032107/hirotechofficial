import { NextRequest, NextResponse } from 'next/server'
import { runScheduledJobs } from '@/lib/teams/cron-jobs'

export const dynamic = 'force-dynamic'
export const maxDuration = 300 // 5 minutes max execution time

/**
 * API endpoint for team-related cron jobs
 * 
 * Can be called by:
 * - Vercel Cron (vercel.json configuration)
 * - External cron services (with proper authentication)
 * - Manual trigger for testing
 * 
 * Usage:
 * GET /api/cron/teams?job=every-10-min
 * GET /api/cron/teams?job=hourly
 * GET /api/cron/teams?job=daily
 */
export async function GET(request: NextRequest) {
  try {
    // Optional: Add authentication check
    const authHeader = request.headers.get('authorization')
    const cronSecret = process.env.CRON_SECRET
    
    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    const { searchParams } = new URL(request.url)
    const jobType = searchParams.get('job') as 'every-10-min' | 'hourly' | 'daily'

    if (!jobType || !['every-10-min', 'hourly', 'daily'].includes(jobType)) {
      return NextResponse.json(
        { error: 'Invalid job type. Use: every-10-min, hourly, or daily' },
        { status: 400 }
      )
    }

    await runScheduledJobs(jobType)

    return NextResponse.json({
      success: true,
      job: jobType,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error('Cron job error:', error)
    return NextResponse.json(
      { error: 'Cron job failed', details: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    )
  }
}

