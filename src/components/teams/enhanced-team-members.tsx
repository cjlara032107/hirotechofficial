'use client'

import { useEffect, useState, useMemo } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Checkbox } from '@/components/ui/checkbox'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { MoreVertical, Shield, User, Crown, Ban, Trash2, Search, Download, Users as UsersIcon } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'sonner'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { cn } from '@/lib/utils'

interface TeamMember {
  id: string
  userId: string
  role: string
  status: string
  lastActiveAt: string | null
  user: {
    id: string
    name: string | null
    email: string
    image: string | null
  }
}

interface EnhancedTeamMembersProps {
  teamId: string
  currentUserId: string
  isAdmin: boolean
}

export function EnhancedTeamMembers({ teamId, currentUserId, isAdmin }: EnhancedTeamMembersProps) {
  const [members, setMembers] = useState<TeamMember[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<string>('name')
  const [selectedMembers, setSelectedMembers] = useState<Set<string>>(new Set())
  const [bulkAction, setBulkAction] = useState<string | null>(null)
  const [bulkRole, setBulkRole] = useState<string>('MEMBER')
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [processing, setProcessing] = useState(false)

  useEffect(() => {
    fetchMembers()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId])

  async function fetchMembers() {
    setLoading(true)
    try {
      const response = await fetch(`/api/teams/${teamId}/members`)
      if (response.ok) {
        const data = await response.json()
        setMembers(data.members)
      }
    } catch (error) {
      console.error('Error fetching members:', error)
      toast.error('Failed to load members')
    } finally {
      setLoading(false)
    }
  }

  // Filtered and sorted members
  const filteredMembers = useMemo(() => {
    const filtered = members.filter(member => {
      // Search filter
      const matchesSearch = searchQuery.trim() === '' || 
        member.user.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        member.user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
        member.role.toLowerCase().includes(searchQuery.toLowerCase())

      // Role filter
      const matchesRole = roleFilter === 'all' || member.role === roleFilter

      // Status filter
      const matchesStatus = statusFilter === 'all' || member.status === statusFilter

      return matchesSearch && matchesRole && matchesStatus
    })

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'name':
          return (a.user.name || a.user.email).localeCompare(b.user.name || b.user.email)
        case 'email':
          return a.user.email.localeCompare(b.user.email)
        case 'role':
          return a.role.localeCompare(b.role)
        case 'lastActive':
          if (!a.lastActiveAt) return 1
          if (!b.lastActiveAt) return -1
          return new Date(b.lastActiveAt).getTime() - new Date(a.lastActiveAt).getTime()
        default:
          return 0
      }
    })

    return filtered
  }, [members, searchQuery, roleFilter, statusFilter, sortBy])

  function toggleMember(memberId: string) {
    const newSelected = new Set(selectedMembers)
    if (newSelected.has(memberId)) {
      newSelected.delete(memberId)
    } else {
      newSelected.add(memberId)
    }
    setSelectedMembers(newSelected)
  }

  function toggleAll() {
    if (selectedMembers.size === filteredMembers.length) {
      setSelectedMembers(new Set())
    } else {
      setSelectedMembers(new Set(filteredMembers.map(m => m.id)))
    }
  }

  async function executeBulkAction() {
    if (selectedMembers.size === 0) {
      toast.error('No members selected')
      return
    }

    if (bulkAction === 'remove') {
      setShowDeleteDialog(true)
      return
    }

    setProcessing(true)
    try {
      const endpoint = `/api/teams/${teamId}/members/bulk-update`
      const body: Record<string, unknown> = {
        memberIds: Array.from(selectedMembers),
        action: bulkAction
      }

      if (bulkAction === 'CHANGE_ROLE') {
        body.newRole = bulkRole
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })

      const data = await response.json()

      if (response.ok) {
        toast.success(data.message)
        setSelectedMembers(new Set())
        setBulkAction(null)
        fetchMembers()
      } else {
        toast.error(data.error || 'Operation failed')
      }
    } catch (error) {
      console.error('Bulk action error:', error)
      toast.error('Failed to execute bulk action')
    } finally {
      setProcessing(false)
    }
  }

  async function confirmBulkDelete() {
    setProcessing(true)
    try {
      const response = await fetch(`/api/teams/${teamId}/members/bulk-delete`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          memberIds: Array.from(selectedMembers)
        })
      })

      const data = await response.json()

      if (response.ok) {
        toast.success(data.message)
        setSelectedMembers(new Set())
        setBulkAction(null)
        setShowDeleteDialog(false)
        fetchMembers()
      } else {
        toast.error(data.error || 'Failed to remove members')
      }
    } catch (error) {
      console.error('Bulk delete error:', error)
      toast.error('Failed to remove members')
    } finally {
      setProcessing(false)
    }
  }

  async function exportMembers() {
    try {
      toast.success('Export started...')
      // Export logic can be added here
    } catch (error) {
      toast.error('Export failed')
    }
  }

  const roleIcons: Record<string, any> = {
    OWNER: Crown,
    ADMIN: Shield,
    MANAGER: User,
    MEMBER: User
  }

  const roleColors: Record<string, string> = {
    OWNER: 'bg-yellow-500',
    ADMIN: 'bg-red-500',
    MANAGER: 'bg-blue-500',
    MEMBER: 'bg-gray-500'
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
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Team Members</CardTitle>
              <CardDescription>
                Manage team members and their permissions ({filteredMembers.length} {filteredMembers.length === 1 ? 'member' : 'members'})
              </CardDescription>
            </div>
            {isAdmin && (
              <Button variant="outline" size="sm" onClick={exportMembers}>
                <Download className="w-4 h-4 mr-2" />
                Export
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Search and Filters */}
          <div className="grid gap-4 md:grid-cols-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search members..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>

            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger>
                <SelectValue placeholder="All Roles" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                <SelectItem value="OWNER">Owner</SelectItem>
                <SelectItem value="ADMIN">Admin</SelectItem>
                <SelectItem value="MANAGER">Manager</SelectItem>
                <SelectItem value="MEMBER">Member</SelectItem>
              </SelectContent>
            </Select>

            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger>
                <SelectValue placeholder="All Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="ACTIVE">Active</SelectItem>
                <SelectItem value="PENDING">Pending</SelectItem>
                <SelectItem value="SUSPENDED">Suspended</SelectItem>
              </SelectContent>
            </Select>

            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="name">Name</SelectItem>
                <SelectItem value="email">Email</SelectItem>
                <SelectItem value="role">Role</SelectItem>
                <SelectItem value="lastActive">Last Active</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Bulk Actions */}
          {isAdmin && selectedMembers.size > 0 && (
            <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
              <UsersIcon className="h-4 w-4" />
              <span className="text-sm font-medium">
                {selectedMembers.size} selected
              </span>
              
              <Select value={bulkAction || ''} onValueChange={setBulkAction}>
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Bulk action..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="CHANGE_ROLE">Change Role</SelectItem>
                  <SelectItem value="SUSPEND">Suspend</SelectItem>
                  <SelectItem value="ACTIVATE">Activate</SelectItem>
                  <SelectItem value="remove">Remove</SelectItem>
                </SelectContent>
              </Select>

              {bulkAction === 'CHANGE_ROLE' && (
                <Select value={bulkRole} onValueChange={setBulkRole}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ADMIN">Admin</SelectItem>
                    <SelectItem value="MANAGER">Manager</SelectItem>
                    <SelectItem value="MEMBER">Member</SelectItem>
                  </SelectContent>
                </Select>
              )}

              <Button
                onClick={executeBulkAction}
                disabled={!bulkAction || processing}
                size="sm"
              >
                {processing ? 'Processing...' : 'Apply'}
              </Button>
              
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSelectedMembers(new Set())
                  setBulkAction(null)
                }}
              >
                Cancel
              </Button>
            </div>
          )}

          {/* Select All */}
          {isAdmin && (
            <div className="flex items-center space-x-2">
              <Checkbox
                id="select-all"
                checked={selectedMembers.size === filteredMembers.length && filteredMembers.length > 0}
                onCheckedChange={toggleAll}
              />
              <label
                htmlFor="select-all"
                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
              >
                Select all ({filteredMembers.length})
              </label>
            </div>
          )}

          {/* Members List */}
          <div className="space-y-2">
            {filteredMembers.map((member) => {
              const RoleIcon = roleIcons[member.role] || User
              const isCurrentUser = member.userId === currentUserId
              const isOwner = member.role === 'OWNER'

              return (
                <div
                  key={member.id}
                  className={cn(
                    'flex items-center justify-between p-4 border rounded-lg',
                    selectedMembers.has(member.id) && 'bg-muted'
                  )}
                >
                  <div className="flex items-center gap-4">
                    {isAdmin && !isOwner && !isCurrentUser && (
                      <Checkbox
                        checked={selectedMembers.has(member.id)}
                        onCheckedChange={() => toggleMember(member.id)}
                      />
                    )}

                    <Avatar>
                      <AvatarImage src={member.user.image || undefined} />
                      <AvatarFallback>
                        {member.user.name?.[0] || member.user.email[0]}
                      </AvatarFallback>
                    </Avatar>

                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{member.user.name || 'Unnamed'}</span>
                        {isCurrentUser && (
                          <Badge variant="secondary">You</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {member.user.email}
                      </p>
                      {member.lastActiveAt && (
                        <p className="text-xs text-muted-foreground">
                          Last active {formatDistanceToNow(new Date(member.lastActiveAt), { addSuffix: true })}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Badge className={roleColors[member.role]}>
                      <RoleIcon className="w-3 h-3 mr-1" />
                      {member.role}
                    </Badge>

                    {member.status === 'SUSPENDED' && (
                      <Badge variant="destructive">Suspended</Badge>
                    )}

                    {isAdmin && !isCurrentUser && !isOwner && (
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreVertical className="w-4 h-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          {/* Individual actions */}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {filteredMembers.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              No members found matching your filters
            </div>
          )}
        </CardContent>
      </Card>

      {/* Bulk Delete Confirmation Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Confirm Bulk Removal</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove {selectedMembers.size} member{selectedMembers.size > 1 ? 's' : ''}? 
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={processing}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={confirmBulkDelete} disabled={processing}>
              {processing ? 'Removing...' : 'Remove Members'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

