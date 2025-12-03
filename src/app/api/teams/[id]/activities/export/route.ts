import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { isTeamAdmin } from '@/lib/teams/permissions'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/activities/export
 * Export team activities as CSV or JSON
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
    
    const format = searchParams.get('format') || 'csv'
    const memberId = searchParams.get('memberId')
    const days = parseInt(searchParams.get('days') || '30')
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Only admins can export all team activities
    const isAdmin = await isTeamAdmin(session.user.id, id)
    if (!isAdmin && memberId !== member.id) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Build query
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const where: Record<string, any> = { teamId: id }
    
    if (memberId && memberId !== 'all') {
      where.memberId = memberId
    }

    if (startDate && endDate) {
      where.createdAt = {
        gte: new Date(startDate),
        lte: new Date(endDate)
      }
    } else {
      const daysAgo = new Date()
      daysAgo.setDate(daysAgo.getDate() - days)
      where.createdAt = {
        gte: daysAgo
      }
    }

    // Fetch activities
    const activities = await prisma.teamActivity.findMany({
      where,
      include: {
        member: {
          include: {
            user: {
              select: {
                name: true,
                email: true
              }
            }
          }
        }
      },
      orderBy: { createdAt: 'desc' },
      take: 10000 // Limit to 10k records
    })

    if (format === 'json') {
      return NextResponse.json({ activities })
    } else {
      // Generate CSV
      const csvHeader = 'Timestamp,Member,Email,Activity Type,Action,Entity Type,Entity Name\n'
      const csvRows = activities.map(activity => {
        const memberName = activity.member?.user?.name || 'System'
        const memberEmail = activity.member?.user?.email || ''
        const timestamp = new Date(activity.createdAt).toISOString()
        
        return [
          timestamp,
          `"${memberName}"`,
          `"${memberEmail}"`,
          activity.type,
          `"${activity.action}"`,
          activity.entityType || '',
          `"${activity.entityName || ''}"
        `
        ].join(',')
      }).join('\n')

      const csv = csvHeader + csvRows

      return new NextResponse(csv, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="team-activities-${Date.now()}.csv"`
        }
      })
    }
  } catch (error) {
    console.error('Error exporting activities:', error)
    return NextResponse.json(
      { error: 'Failed to export activities' },
      { status: 500 }
    )
  }
}

