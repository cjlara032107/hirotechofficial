import { NextRequest, NextResponse } from 'next/server'
import { auth } from '@/auth'
import { prisma } from '@/lib/db'
import { logActivity } from '@/lib/teams/activity'
import { TaskPriority, TaskStatus } from '@prisma/client'

interface RouteParams {
  params: Promise<{ id: string; taskId: string }>
}

/**
 * PATCH /api/teams/[id]/tasks/[taskId]
 * Update a task
 */
export async function PATCH(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id, taskId } = await params

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
      tags
    } = body

    type UpdateData = {
      title?: string;
      description?: string | null;
      priority?: TaskPriority;
      status?: TaskStatus;
      completedAt?: Date;
      dueDate?: Date | null;
      tags?: string[];
    } & (
      | { assignedToId: string }
      | { assignedToId: { set: null } }
      | { assignedToId?: never }
    )
    
    const updateData: UpdateData = {}
    if (title !== undefined) updateData.title = title.trim()
    if (description !== undefined) updateData.description = description?.trim()
    if (priority !== undefined) updateData.priority = priority as TaskPriority
    if (status !== undefined) {
      const statusEnum = status as TaskStatus
      updateData.status = statusEnum
      if (statusEnum === 'COMPLETED') {
        updateData.completedAt = new Date()
      }
    }
    if (assignedToId !== undefined) {
      if (assignedToId === null) {
        Object.assign(updateData, { assignedToId: { set: null } })
      } else {
        Object.assign(updateData, { assignedToId })
      }
    }
    if (dueDate !== undefined) updateData.dueDate = dueDate ? new Date(dueDate) : null
    if (tags !== undefined) updateData.tags = tags

    const task = await prisma.teamTask.update({
      where: { id: taskId },
      data: updateData,
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
    if (status === 'COMPLETED') {
      await logActivity({
        teamId: id,
        memberId: member.id,
        type: 'COMPLETE_TASK',
        action: `Completed task: ${task.title}`,
        entityType: 'task',
        entityId: task.id,
        entityName: task.title
      })
    } else {
      await logActivity({
        teamId: id,
        memberId: member.id,
        type: 'EDIT_ENTITY',
        action: `Updated task: ${task.title}`,
        entityType: 'task',
        entityId: task.id,
        entityName: task.title
      })
    }

    return NextResponse.json({ task })
  } catch (error) {
    console.error('Error updating team task:', error)
    return NextResponse.json(
      { error: 'Failed to update team task' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/teams/[id]/tasks/[taskId]
 * Delete a task
 */
export async function DELETE(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { id, taskId } = await params

    // Check if user is a member
    const member = await prisma.teamMember.findUnique({
      where: {
        userId_teamId: { userId: session.user.id, teamId: id }
      }
    })

    if (!member || member.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const task = await prisma.teamTask.findUnique({
      where: { id: taskId },
      select: { title: true, createdById: true }
    })

    if (!task) {
      return NextResponse.json({ error: 'Task not found' }, { status: 404 })
    }

    // Only creator or admin can delete
    if (task.createdById !== member.id && member.role !== 'ADMIN' && member.role !== 'OWNER') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    await prisma.teamTask.delete({
      where: { id: taskId }
    })

    // Log activity
    await logActivity({
      teamId: id,
      memberId: member.id,
      type: 'DELETE_ENTITY',
      action: `Deleted task: ${task.title}`,
      entityType: 'task',
      entityId: taskId,
      entityName: task.title
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Error deleting team task:', error)
    return NextResponse.json(
      { error: 'Failed to delete team task' },
      { status: 500 }
    )
  }
}

