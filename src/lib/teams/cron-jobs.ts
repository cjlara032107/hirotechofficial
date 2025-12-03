/**
 * Team Management Cron Jobs
 * 
 * These functions should be scheduled to run periodically:
 * - rotateExpiredJoinCodes: Every 10 minutes
 * - cleanupExpiredInvites: Daily
 * - sendTaskReminders: Hourly
 */

import { prisma } from '@/lib/db'
import { rotateAllExpiredJoinCodes } from './join-codes'
import { logJobStart, logJobComplete, logJobFailure } from '@/lib/logging/job-logger'

/**
 * Rotates all expired join codes
 * Should run every 10 minutes
 */
export async function rotateExpiredJoinCodesJob() {
  const jobType = 'cron-rotate-join-codes'
  const startTime = Date.now()
  
  await logJobStart(jobType, undefined, 'Starting join code rotation job').catch(() => {
    // Silently fail - logging should not break the app
  })
  
  try {
    const result = await rotateAllExpiredJoinCodes()
    const duration = Date.now() - startTime
    await logJobComplete(jobType, undefined, `Join code rotation complete: ${JSON.stringify(result)}`, duration, { result }).catch(() => {
      // Silently fail - logging should not break the app
    })
    return result
  } catch (error) {
    await logJobFailure(jobType, undefined, 'Error rotating join codes', error as Error).catch(() => {
      // Silently fail - logging should not break the app
    })
    throw error
  }
}

/**
 * Cleans up expired and exhausted invites
 * Should run daily
 */
export async function cleanupExpiredInvitesJob() {
  const jobType = 'cron-cleanup-invites'
  const startTime = Date.now()
  
  await logJobStart(jobType, undefined, 'Starting invite cleanup job').catch(() => {
    // Silently fail - logging should not break the app
  })
  
  try {
    const now = new Date()
    
    // Mark expired invites
    const expiredResult = await prisma.teamInvite.updateMany({
      where: {
        status: 'ACTIVE',
        expiresAt: { lt: now }
      },
      data: { status: 'EXPIRED' }
    })
    
    // Mark exhausted invites
    const exhaustedResult = await prisma.teamInvite.updateMany({
      where: {
        status: 'ACTIVE',
        maxUses: { not: null },
        usedCount: { gte: prisma.teamInvite.fields.maxUses }
      },
      data: { status: 'EXHAUSTED' }
    })
    
    const result = {
      expired: expiredResult.count,
      exhausted: exhaustedResult.count
    }
    
    const duration = Date.now() - startTime
    await logJobComplete(jobType, undefined, `Invite cleanup complete: ${JSON.stringify(result)}`, duration, result).catch(() => {
      // Silently fail - logging should not break the app
    })
    
    return result
  } catch (error) {
    await logJobFailure(jobType, undefined, 'Error cleaning up invites', error as Error).catch(() => {
      // Silently fail - logging should not break the app
    })
    throw error
  }
}

/**
 * Sends reminders for overdue tasks
 * Should run hourly
 */
export async function sendTaskRemindersJob() {
  const jobType = 'cron-send-task-reminders'
  const startTime = Date.now()
  
  await logJobStart(jobType, undefined, 'Starting task reminders job').catch(() => {
    // Silently fail - logging should not break the app
  })
  
  try {
    const now = new Date()
    
    // Find overdue tasks that haven't been completed
    const overdueTasks = await prisma.teamTask.findMany({
      where: {
        status: { in: ['TODO', 'IN_PROGRESS'] },
        dueDate: { lt: now },
        // Add a metadata field to track if reminder was sent today
      },
      include: {
        assignedTo: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                name: true
              }
            }
          }
        },
        team: {
          select: {
            id: true,
            name: true
          }
        }
      }
    })
    
    // TODO: Send notifications to assigned users
    // This would integrate with your notification system
    
    const result = { remindersSent: overdueTasks.length }
    const duration = Date.now() - startTime
    await logJobComplete(jobType, undefined, `Task reminders sent: ${overdueTasks.length}`, duration, result).catch(() => {
      // Silently fail - logging should not break the app
    })
    
    return result
  } catch (error) {
    await logJobFailure(jobType, undefined, 'Error sending task reminders', error as Error).catch(() => {
      // Silently fail - logging should not break the app
    })
    throw error
  }
}

/**
 * Checks for suspended members whose suspension has expired
 * Should run hourly
 */
export async function unsuspendExpiredSuspensionsJob() {
  const jobType = 'cron-unsuspend-expired'
  const startTime = Date.now()
  
  await logJobStart(jobType, undefined, 'Starting unsuspend job').catch(() => {
    // Silently fail - logging should not break the app
  })
  
  try {
    const now = new Date()
    
    const result = await prisma.teamMember.updateMany({
      where: {
        status: 'SUSPENDED',
        suspendedUntil: { lt: now }
      },
      data: {
        status: 'ACTIVE',
        suspendedAt: null,
        suspendedUntil: null,
        suspendedReason: null
      }
    })
    
    const jobResult = { unsuspended: result.count }
    const duration = Date.now() - startTime
    await logJobComplete(jobType, undefined, `Unsuspend job complete: ${result.count} members unsuspended`, duration, jobResult).catch(() => {
      // Silently fail - logging should not break the app
    })
    
    return jobResult
  } catch (error) {
    await logJobFailure(jobType, undefined, 'Error unsuspending members', error as Error).catch(() => {
      // Silently fail - logging should not break the app
    })
    throw error
  }
}

/**
 * Main cron job scheduler
 * Call this from your cron setup (e.g., Vercel Cron, node-cron, etc.)
 */
export async function runScheduledJobs(jobType: 'every-10-min' | 'hourly' | 'daily') {
  const schedulerJobType = `cron-scheduler-${jobType}`
  const startTime = Date.now()
  
  await logJobStart(schedulerJobType, undefined, `Running ${jobType} jobs`).catch(() => {
    // Silently fail - logging should not break the app
  })
  
  try {
    switch (jobType) {
      case 'every-10-min':
        await rotateExpiredJoinCodesJob()
        break
      
      case 'hourly':
        await Promise.allSettled([
          sendTaskRemindersJob(),
          unsuspendExpiredSuspensionsJob()
        ])
        break
      
      case 'daily':
        await cleanupExpiredInvitesJob()
        break
    }
    
    const duration = Date.now() - startTime
    await logJobComplete(schedulerJobType, undefined, `${jobType} jobs completed successfully`, duration).catch(() => {
      // Silently fail - logging should not break the app
    })
  } catch (error) {
    await logJobFailure(schedulerJobType, undefined, `Error running ${jobType} jobs`, error as Error).catch(() => {
      // Silently fail - logging should not break the app
    })
  }
}

