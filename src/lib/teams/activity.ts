import { prisma } from '@/lib/db'
import { TeamActivityType, Prisma } from '@prisma/client'
import { safePrismaOperation } from '../prisma-error-handler'

export interface ActivityLogOptions {
  teamId: string
  memberId?: string
  type: TeamActivityType
  action: string
  entityType?: string
  entityId?: string
  entityName?: string
  metadata?: Record<string, unknown>
  ipAddress?: string
  userAgent?: string
  duration?: number
  /**
   * Optional unique identifier for idempotency.
   * If provided, will check for existing log entry before creating.
   * Format: `${type}-${entityType}-${entityId}-${timestamp}` or custom
   */
  idempotencyKey?: string
}

/**
 * Logs a team activity with error handling, retry logic, idempotency, and non-blocking behavior.
 * 
 * Features:
 * - Handles database errors gracefully (wraps in safePrismaOperation)
 * - Handles duplicate log entries (idempotency via idempotencyKey)
 * - Uses retry logic for resilience (via safePrismaOperation)
 * - Is non-blocking (catches and logs errors without throwing)
 * 
 * @param options Activity log options
 * @returns Promise that resolves to the created activity or null if error occurred
 */
export async function logActivity(options: ActivityLogOptions): Promise<any> {
  // Non-blocking: wrap in try-catch to prevent throwing
  try {
    // If idempotency key is provided, check for existing entry
    if (options.idempotencyKey) {
      try {
        const existing = await safePrismaOperation(
          async () => {
            // Check if a similar activity already exists within the last 5 minutes
            // This prevents duplicate logs from rapid retries or concurrent requests
            const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
            
            return await prisma.teamActivity.findFirst({
              where: {
                teamId: options.teamId,
                type: options.type,
                action: options.action,
                entityType: options.entityType || null,
                entityId: options.entityId || null,
                createdAt: { gte: fiveMinutesAgo },
              },
              orderBy: { createdAt: 'desc' },
            });
          },
          {
            operationName: 'check duplicate activity log',
            maxRetries: 2, // Fewer retries for read operations
          }
        );

        // If duplicate found, return existing entry (idempotent behavior)
        if (existing) {
          return existing;
        }
      } catch (checkError) {
        // Non-blocking: if duplicate check fails, continue to create
        // This ensures idempotency check doesn't block logging
        console.warn('[Activity Log] Duplicate check failed, proceeding with create:', {
          error: checkError instanceof Error ? checkError.message : String(checkError),
        });
      }
    }

    // Create activity log with retry logic and error handling
    const activity = await safePrismaOperation(
      async () => {
        return await prisma.teamActivity.create({
          data: {
            ...options,
            metadata: options.metadata ? (options.metadata as Prisma.InputJsonValue) : undefined
          }
        });
      },
      {
        operationName: 'create activity log',
        maxRetries: 3,
        initialDelay: 1000,
        maxDelay: 10000,
      }
    );

    return activity;
  } catch (error) {
    // Non-blocking: log error but don't throw
    // This ensures logging failures don't break the main application flow
    console.error('[Activity Log] Failed to log activity:', {
      error: error instanceof Error ? error.message : String(error),
      teamId: options.teamId,
      type: options.type,
      action: options.action,
    });
    
    // Return null instead of throwing (non-blocking behavior)
    return null;
  }
}

/**
 * Logs a page view
 */
export async function logPageView(
  teamId: string,
  memberId: string,
  pagePath: string,
  duration?: number
) {
  return logActivity({
    teamId,
    memberId,
    type: 'VIEW_PAGE',
    action: `Viewed ${pagePath}`,
    metadata: { pagePath },
    duration
  })
}

/**
 * Logs login activity
 */
export async function logLogin(
  teamId: string,
  memberId: string,
  ipAddress?: string,
  userAgent?: string
) {
  // Update member's last login
  await prisma.teamMember.update({
    where: { id: memberId },
    data: { lastLoginAt: new Date(), lastActiveAt: new Date() }
  })
  
  return logActivity({
    teamId,
    memberId,
    type: 'LOGIN',
    action: 'Logged in to team',
    ipAddress,
    userAgent
  })
}

/**
 * Logs entity creation
 */
export async function logEntityCreation(
  teamId: string,
  memberId: string,
  entityType: string,
  entityId: string,
  entityName: string
) {
  return logActivity({
    teamId,
    memberId,
    type: 'CREATE_ENTITY',
    action: `Created ${entityType}: ${entityName}`,
    entityType,
    entityId,
    entityName
  })
}

/**
 * Logs entity update
 */
export async function logEntityUpdate(
  teamId: string,
  memberId: string,
  entityType: string,
  entityId: string,
  entityName: string,
  changes?: Record<string, unknown>
) {
  return logActivity({
    teamId,
    memberId,
    type: 'EDIT_ENTITY',
    action: `Updated ${entityType}: ${entityName}`,
    entityType,
    entityId,
    entityName,
    metadata: changes ? { changes } : undefined
  })
}

/**
 * Logs entity deletion
 */
export async function logEntityDeletion(
  teamId: string,
  memberId: string,
  entityType: string,
  entityId: string,
  entityName: string
) {
  return logActivity({
    teamId,
    memberId,
    type: 'DELETE_ENTITY',
    action: `Deleted ${entityType}: ${entityName}`,
    entityType,
    entityId,
    entityName
  })
}

/**
 * Gets activity logs for a team with filters
 */
export async function getTeamActivities(
  teamId: string,
  filters?: {
    memberId?: string
    type?: TeamActivityType
    entityType?: string
    startDate?: Date
    endDate?: Date
    limit?: number
    offset?: number
  }
) {
  const where: {
    teamId: string
    memberId?: string
    type?: TeamActivityType
    entityType?: string
    createdAt?: {
      gte?: Date
      lte?: Date
    }
  } = { teamId }
  
  if (filters?.memberId) where.memberId = filters.memberId
  if (filters?.type) where.type = filters.type
  if (filters?.entityType) where.entityType = filters.entityType
  
  if (filters?.startDate || filters?.endDate) {
    where.createdAt = {}
    if (filters.startDate) where.createdAt.gte = filters.startDate
    if (filters.endDate) where.createdAt.lte = filters.endDate
  }
  
  const [activities, total] = await Promise.all([
    prisma.teamActivity.findMany({
      where,
      include: {
        member: {
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
      orderBy: { createdAt: 'desc' },
      take: filters?.limit || 50,
      skip: filters?.offset || 0
    }),
    prisma.teamActivity.count({ where })
  ])
  
  return { activities, total }
}

/**
 * Gets engagement metrics for a team member
 */
export async function getMemberEngagementMetrics(
  teamId: string,
  memberId: string,
  startDate?: Date,
  endDate?: Date
) {
  const where: {
    teamId: string
    memberId: string
    type?: TeamActivityType
    createdAt?: {
      gte?: Date
      lte?: Date
    }
  } = { teamId, memberId }
  
  if (startDate || endDate) {
    where.createdAt = {}
    if (startDate) where.createdAt.gte = startDate
    if (endDate) where.createdAt.lte = endDate
  }
  
  const [
    totalActivities,
    messagesSent,
    tasksCompleted,
    pagesAccessed,
    totalTimeSpent
  ] = await Promise.all([
    prisma.teamActivity.count({ where }),
    prisma.teamActivity.count({ where: { ...where, type: 'SEND_MESSAGE' } }),
    prisma.teamActivity.count({ where: { ...where, type: 'COMPLETE_TASK' } }),
    prisma.teamActivity.count({ where: { ...where, type: 'VIEW_PAGE' } }),
    prisma.teamActivity.aggregate({
      where,
      _sum: { duration: true }
    })
  ])
  
  const member = await prisma.teamMember.findUnique({
    where: { id: memberId },
    select: { totalTimeSpent: true }
  })
  
  return {
    totalActivities,
    messagesSent,
    tasksCompleted,
    pagesAccessed,
    totalTimeSpent: member?.totalTimeSpent || 0,
    averageSessionDuration: totalTimeSpent._sum.duration || 0
  }
}

/**
 * Gets activity heatmap data
 */
export async function getActivityHeatmap(
  teamId: string,
  days: number = 30
) {
  const startDate = new Date()
  startDate.setDate(startDate.getDate() - days)
  
  // Fetch all activities within the date range
  const activities = await prisma.teamActivity.findMany({
    where: {
      teamId,
      createdAt: { gte: startDate }
    },
    select: {
      createdAt: true
    }
  })
  
  // Group by day and hour
  const heatmap: Record<string, Record<number, number>> = {}
  
  activities.forEach(({ createdAt }) => {
    const date = new Date(createdAt)
    const day = date.toISOString().split('T')[0]
    const hour = date.getHours()
    
    if (!heatmap[day]) {
      heatmap[day] = {}
    }
    heatmap[day][hour] = (heatmap[day][hour] || 0) + 1
  })
  
  return heatmap
}

/**
 * Updates member's total time spent
 */
export async function updateMemberTimeSpent(
  memberId: string,
  additionalSeconds: number
) {
  return prisma.teamMember.update({
    where: { id: memberId },
    data: {
      totalTimeSpent: { increment: additionalSeconds },
      lastActiveAt: new Date()
    }
  })
}

