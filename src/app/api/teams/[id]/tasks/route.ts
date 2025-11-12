import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { logActivity } from '@/lib/teams/activity'
import { TaskPriority, TaskStatus } from '@prisma/client'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/teams/[id]/tasks
 * Get team tasks
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
    const status = searchParams.get('status')
    const assignedTo = searchParams.get('assignedTo')
    const priority = searchParams.get('priority')

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const where: {
      teamId: string;
      status?: TaskStatus;
      assignedToId?: string;
      priority?: TaskPriority;
    } = { teamId: id }
    if (status) where.status = status as TaskStatus
    if (assignedTo) where.assignedToId = assignedTo
    if (priority) where.priority = priority as TaskPriority

    const tasks = await prisma.teamTask.findMany({
      where,
      include: {
        assignedTo: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true
              }
            }
          }
        },
        createdBy: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true
              }
            }
          }
        }
      },
      orderBy: [
        { status: 'asc' },
        { priority: 'desc' },
        { dueDate: 'asc' }
      ]
    })

    return NextResponse.json({ tasks })
  } catch (error) {
    console.error('Error fetching team tasks:', error)
    return NextResponse.json(
      { error: 'Failed to fetch team tasks' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/teams/[id]/tasks
 * Create a new task
 */
export async function POST(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const body = await request.json()
    const {
      title,
      description,
      priority,
      status,
      assignedToId,
      dueDate,
      tags,
      relatedEntityType,
      relatedEntityId
    } = body

    if (!title || title.trim().length === 0) {
      return NextResponse.json(
        { error: 'Task title is required' },
        { status: 400 }
      )
    }

    const task = await prisma.teamTask.create({
      data: {
        teamId: id,
        title: title.trim(),
        description: description?.trim(),
        priority: priority || 'MEDIUM',
        status: status || 'TODO',
        assignedToId,
        createdById: member.id,
        dueDate: dueDate ? new Date(dueDate) : null,
        tags: tags || [],
        relatedEntityType,
        relatedEntityId
      },
      include: {
        assignedTo: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true
              }
            }
          }
        },
        createdBy: {
          include: {
            user: {
              select: {
                id: true,
                name: true,
                email: true,
                image: true
              }
            }
          }
        }
      }
    })

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'CREATE_ENTITY',
      action: `Created task: ${task.title}`,
      entityType: 'task',
      entityId: task.id,
      entityName: task.title
    })

    // TODO: Send notification to assigned member

    return NextResponse.json({ task }, { status: 201 })
  } catch (error) {
    console.error('Error creating team task:', error)
    return NextResponse.json(
      { error: 'Failed to create team task' },
      { status: 500 }
    )
  }
}

