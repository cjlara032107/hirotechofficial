import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { getTeamActivities, getMemberEngagementMetrics, getActivityHeatmap } from '@/lib/teams/activity'
import { isTeamAdmin } from '@/lib/teams/permissions'
import { TeamActivityType } from '@prisma/client'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/activities
 * Get team activity logs
 */
export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id } = await params
    const { searchParams } = new URL(request.url)
    
    const memberId = searchParams.get('memberId')
    const type = searchParams.get('type')
    const entityType = searchParams.get('entityType')
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const limit = searchParams.get('limit')
    const offset = searchParams.get('offset')
    const view = searchParams.get('view') // 'heatmap', 'metrics', or default 'list'

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Non-admins can only view their own activity
    const isAdmin = await isTeamAdmin(session.user.id, id)
    let targetMemberId = memberId

    if (!isAdmin && memberId && memberId !== member.id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // If not admin and no memberId specified, show own activity
    if (!isAdmin && !memberId) {
      targetMemberId = member.id
    }

    if (view === 'heatmap') {
      if (!isAdmin) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
      
      const days = parseInt(searchParams.get('days') || '30')
      const heatmap = await getActivityHeatmap(id, days)
      return NextResponse.json({ heatmap })
    }

    if (view === 'metrics' && targetMemberId) {
      const metrics = await getMemberEngagementMetrics(
        id,
        targetMemberId,
        startDate ? new Date(startDate) : undefined,
        endDate ? new Date(endDate) : undefined
      )
      return NextResponse.json({ metrics })
    }

    const { activities, total } = await getTeamActivities(id, {
      memberId: targetMemberId || undefined,
      type: type ? (type as TeamActivityType) : undefined,
      entityType: entityType || undefined,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: limit ? parseInt(limit) : undefined,
      offset: offset ? parseInt(offset) : undefined
    })

    return NextResponse.json({ activities, total })
  } catch (error) {
    console.error('Error fetching team activities:', error)
    return NextResponse.json(
      { error: 'Failed to fetch team activities' },
      { status: 500 }
    )
  }
}

