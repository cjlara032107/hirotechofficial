'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Plus, CheckCircle2, Clock, AlertCircle, User } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'sonner'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

interface TeamMember {
  id: string
  user: {
    id: string
    name: string | null
    email: string
    image: string | null
  }
  role: string
  status: string
}

interface Task {
  id: string
  title: string
  description?: string | null
  priority: string
  status: string
  dueDate?: Date | string | null
  assignedToId?: string | null
  createdAt: Date | string
  assignedTo?: {
    user: {
      name: string | null
    }
  }
}

interface TeamTasksProps {
  teamId: string
  currentMemberId: string
  isAdmin: boolean
}

export function TeamTasks({ teamId, currentMemberId }: TeamTasksProps) {
  const [tasks, setTasks] = useState<Task[]>([])
  const [members, setMembers] = useState<TeamMember[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingMembers, setLoadingMembers] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [newTask, setNewTask] = useState({
    title: '',
    description: '',
    priority: 'MEDIUM',
    dueDate: '',
    assignedToId: currentMemberId
  })

  useEffect(() => {
    fetchTasks()
    fetchMembers()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId])

  async function fetchTasks() {
    try {
      const response = await fetch(`/api/teams/${teamId}/tasks`)
      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch tasks')
      }
      
      setTasks(data.tasks || [])
    } catch {
      toast.error('Failed to fetch tasks')
    } finally {
      setLoading(false)
    }
  }

  async function fetchMembers() {
    try {
      const response = await fetch(`/api/teams/${teamId}/members`)
      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch members')
      }
      
      // Filter only active members
      const activeMembers = (data.members || []).filter(
        (m: TeamMember) => m.status === 'ACTIVE'
      )
      setMembers(activeMembers)
    } catch {
      toast.error('Failed to load team members')
    } finally {
      setLoadingMembers(false)
    }
  }

  async function createTask(e: React.FormEvent) {
    e.preventDefault()
    
    if (!newTask.title || newTask.title.trim().length === 0) {
      toast.error('Task title is required')
      return
    }

    if (!newTask.assignedToId) {
      toast.error('Please select a team member to assign this task')
      return
    }

    setSubmitting(true)
    
    try {
      const response = await fetch(`/api/teams/${teamId}/tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newTask)
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create task')
      }

      setTasks([data.task, ...tasks])
      setNewTask({ 
        title: '', 
        description: '', 
        priority: 'MEDIUM', 
        dueDate: '',
        assignedToId: currentMemberId 
      })
      setCreateOpen(false)
      toast.success('Task created successfully')
    } catch (error) {
      console.error('Error creating task:', error)
      toast.error(error instanceof Error ? error.message : 'Failed to create task')
    } finally {
      setSubmitting(false)
    }
  }

  async function updateTaskStatus(taskId: string, status: string) {
    try {
      const response = await fetch(`/api/teams/${teamId}/tasks/${taskId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      })

      if (!response.ok) throw new Error('Failed to update task')

      const data = await response.json()
      setTasks(tasks.map(t => t.id === taskId ? data.task : t))
      toast.success('Task updated')
    } catch {
      toast.error('Failed to update task')
    }
  }

  const priorityColors: Record<string, string> = {
    LOW: 'bg-blue-500',
    MEDIUM: 'bg-yellow-500',
    HIGH: 'bg-orange-500',
    URGENT: 'bg-red-500'
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const statusIcons: Record<string, any> = {
    TODO: Clock,
    IN_PROGRESS: AlertCircle,
    COMPLETED: CheckCircle2
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="flex justify-center py-8">
          <LoadingSpinner />
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Tasks</h2>
          <p className="text-sm text-muted-foreground">
            Manage and track team tasks
          </p>
        </div>
        
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="w-4 h-4 mr-2" />
              Create Task
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Task</DialogTitle>
              <DialogDescription>
                Add a new task to your team
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={createTask} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="title">Title *</Label>
                <Input
                  id="title"
                  value={newTask.title}
                  onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={newTask.description}
                  onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                  rows={3}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="assignedTo">Assign To *</Label>
                <Select
                  value={newTask.assignedToId}
                  onValueChange={(value) => setNewTask({ ...newTask, assignedToId: value })}
                  disabled={loadingMembers}
                >
                  <SelectTrigger>
                    <SelectValue placeholder={loadingMembers ? "Loading members..." : "Select a team member"} />
                  </SelectTrigger>
                  <SelectContent>
                    {members.map((member) => (
                      <SelectItem key={member.id} value={member.id}>
                        <div className="flex items-center gap-2">
                          <User className="w-4 h-4" />
                          {member.user.name || member.user.email}
                          {member.id === currentMemberId && ' (You)'}
                          {member.role === 'OWNER' && ' - Owner'}
                          {member.role === 'ADMIN' && ' - Admin'}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="priority">Priority</Label>
                  <Select
                    value={newTask.priority}
                    onValueChange={(value) => setNewTask({ ...newTask, priority: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="LOW">Low</SelectItem>
                      <SelectItem value="MEDIUM">Medium</SelectItem>
                      <SelectItem value="HIGH">High</SelectItem>
                      <SelectItem value="URGENT">Urgent</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="dueDate">Due Date</Label>
                  <Input
                    id="dueDate"
                    type="date"
                    value={newTask.dueDate}
                    onChange={(e) => setNewTask({ ...newTask, dueDate: e.target.value })}
                    min={new Date().toISOString().split('T')[0]}
                  />
                </div>
              </div>

              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? 'Creating...' : 'Create Task'}
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4">
        {tasks.length === 0 ? (
          <Card>
            <CardContent className="text-center py-8">
              <p className="text-sm text-muted-foreground">
                No tasks yet. Create one to get started!
              </p>
            </CardContent>
          </Card>
        ) : (
          tasks.map((task) => {
            const StatusIcon = statusIcons[task.status] || Clock
            return (
              <Card key={task.id}>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <CardTitle className="text-lg">{task.title}</CardTitle>
                      {task.description && (
                        <CardDescription>{task.description}</CardDescription>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${priorityColors[task.priority]}`} />
                      <Badge variant="outline">
                        <StatusIcon className="w-3 h-3 mr-1" />
                        {task.status.replace(/_/g, ' ')}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      {task.assignedTo && `Assigned to ${task.assignedTo.user.name}`}
                      {task.dueDate && ` • Due ${formatDistanceToNow(new Date(task.dueDate), { addSuffix: true })}`}
                    </div>
                    <div className="flex gap-2">
                      {task.status !== 'COMPLETED' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => updateTaskStatus(task.id, 'COMPLETED')}
                        >
                          Mark Complete
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })
        )}
      </div>
    </div>
  )
}

