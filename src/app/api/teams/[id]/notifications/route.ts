import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { getNotifications } from '@/lib/teams/notifications'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/notifications
 * Get team member notifications
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

    const { id: teamId } = await params
    const { searchParams } = new URL(request.url)
    
    // Reduced default page size for better performance
    const limit = parseInt(searchParams.get('limit') || '25')
    const offset = parseInt(searchParams.get('offset') || '0')
    const unreadOnly = searchParams.get('unreadOnly') === 'true'

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const { notifications, total } = await getNotifications({
      memberId: member.id,
      limit,
      offset,
      unreadOnly
    })

    return NextResponse.json({
      notifications,
      total,
      hasMore: offset + notifications.length < total
    })
  } catch (error) {
    console.error('Error fetching notifications:', error)
    return NextResponse.json(
      { error: 'Failed to fetch notifications' },
      { status: 500 }
    )
  }
}

