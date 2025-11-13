'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { 
  Calendar, 
  CheckCircle2, 
  Circle, 
  AlertCircle,
  ChevronRight 
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import Link from 'next/link'

interface Task {
  id: string
  title: string
  description?: string | null
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'URGENT'
  status: 'TODO' | 'IN_PROGRESS' | 'IN_REVIEW' | 'DONE' | 'CANCELLED'
  dueDate?: Date | string | null
  createdAt: Date | string
  assignedTo?: {
    id: string
    displayName?: string | null
    user: {
      name: string | null
      email: string
    }
  } | null
}

interface PendingTasksWidgetProps {
  teamId: string
  memberId?: string
  showOnlyAssigned?: boolean
  limit?: number
}

export function PendingTasksWidget({
  teamId,
  memberId,
  showOnlyAssigned = false,
  limit = 5,
}: PendingTasksWidgetProps) {
  const [tasks, setTasks] = useState<Task[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'assigned'>('all')

  useEffect(() => {
    fetchTasks()
  }, [teamId, memberId, filter])

  async function fetchTasks() {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      
      // Only show pending tasks (TODO or IN_PROGRESS)
      params.append('status', 'TODO')
      
      if (showOnlyAssigned && memberId) {
        params.append('assignedTo', memberId)
      } else if (filter === 'assigned' && memberId) {
        params.append('assignedTo', memberId)
      }

      const response = await fetch(`/api/teams/${teamId}/tasks?${params.toString()}`)
      const data = await response.json()

      // Sort by priority and due date
      const sortedTasks = (data.tasks || []).sort((a: Task, b: Task) => {
        // Priority order: URGENT > HIGH > MEDIUM > LOW
        const priorityOrder = { URGENT: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
        const aPriority = priorityOrder[a.priority] || 0
        const bPriority = priorityOrder[b.priority] || 0
        
        if (aPriority !== bPriority) {
          return bPriority - aPriority
        }

        // Then sort by due date
        if (a.dueDate && b.dueDate) {
          return new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime()
        }
        if (a.dueDate) return -1
        if (b.dueDate) return 1

        return 0
      })

      setTasks(sortedTasks.slice(0, limit))
    } catch (error) {
      console.error('Error fetching tasks:', error)
    } finally {
      setLoading(false)
    }
  }

  function getPriorityColor(priority: string) {
    switch (priority) {
      case 'URGENT':
        return 'destructive'
      case 'HIGH':
        return 'default'
      case 'MEDIUM':
        return 'secondary'
      case 'LOW':
        return 'outline'
      default:
        return 'outline'
    }
  }

  function isOverdue(dueDate?: Date | string | null) {
    if (!dueDate) return false
    return new Date(dueDate) < new Date()
  }

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Pending Tasks</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">Pending Tasks</CardTitle>
          {!showOnlyAssigned && (
            <div className="flex gap-2">
              <Button
                variant={filter === 'all' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilter('all')}
              >
                All
              </Button>
              <Button
                variant={filter === 'assigned' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilter('assigned')}
              >
                Assigned to me
              </Button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {tasks.length === 0 ? (
          <div className="text-center py-8">
            <CheckCircle2 className="h-12 w-12 text-muted-foreground mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">
              No pending tasks
            </p>
          </div>
        ) : (
          <ScrollArea className="h-[300px] pr-4">
            <div className="space-y-3">
              {tasks.map((task) => (
                <Link 
                  key={task.id} 
                  href={`/teams/${teamId}/tasks/${task.id}`}
                  className="block"
                >
                  <div className="flex items-start gap-3 p-3 rounded-lg border hover:bg-muted/50 transition-colors cursor-pointer">
                    <div className="flex-shrink-0 mt-0.5">
                      {task.status === 'IN_PROGRESS' ? (
                        <Circle className="h-5 w-5 text-blue-500 fill-blue-500/20" />
                      ) : (
                        <Circle className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <h4 className="text-sm font-medium truncate">
                          {task.title}
                        </h4>
                        <Badge variant={getPriorityColor(task.priority)} className="text-xs">
                          {task.priority}
                        </Badge>
                      </div>
                      
                      {task.description && (
                        <p className="text-xs text-muted-foreground line-clamp-1 mb-2">
                          {task.description}
                        </p>
                      )}

                      <div className="flex items-center gap-3 text-xs text-muted-foreground">
                        {task.dueDate && (
                          <div className={`flex items-center gap-1 ${isOverdue(task.dueDate) ? 'text-red-500' : ''}`}>
                            {isOverdue(task.dueDate) ? (
                              <AlertCircle className="h-3 w-3" />
                            ) : (
                              <Calendar className="h-3 w-3" />
                            )}
                            <span>
                              {isOverdue(task.dueDate) ? 'Overdue' : 'Due'}{' '}
                              {formatDistanceToNow(new Date(task.dueDate), { addSuffix: true })}
                            </span>
                          </div>
                        )}

                        {task.assignedTo && (
                          <span>
                            Assigned to {task.assignedTo.displayName || task.assignedTo.user.name || task.assignedTo.user.email}
                          </span>
                        )}
                      </div>
                    </div>

                    <ChevronRight className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                  </div>
                </Link>
              ))}
            </div>
          </ScrollArea>
        )}

        {tasks.length > 0 && (
          <Link href={`/teams/${teamId}/tasks`}>
            <Button variant="outline" size="sm" className="w-full mt-4">
              View all tasks
            </Button>
          </Link>
        )}
      </CardContent>
    </Card>
  )
}

