'use client'

import { useState, useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'

interface Thread {
  id: string
  title?: string | null
  groupName?: string | null
  description?: string | null
  type: string
  isChannel: boolean
}

interface EditThreadDialogProps {
  teamId: string
  thread: Thread
  open: boolean
  onOpenChange: (open: boolean) => void
  isAdmin: boolean
  onUpdated: () => void
}

export function EditThreadDialog({
  teamId,
  thread,
  open,
  onOpenChange,
  isAdmin,
  onUpdated
}: EditThreadDialogProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (open && thread) {
      setName(thread.title || thread.groupName || '')
      setDescription(thread.description || '')
    }
  }, [open, thread])

  async function handleSave() {
    if (!name.trim()) {
      toast.error('Name is required')
      return
    }

    // Check permissions
    if (thread.isChannel && !isAdmin) {
      toast.error('Only admins can edit channels')
      return
    }

    setSaving(true)
    try {
      const response = await fetch(`/api/teams/${teamId}/threads/${thread.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          [thread.isChannel ? 'title' : 'groupName']: name.trim(),
          description: description.trim() || null
        })
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to update thread')
      }

      toast.success('Thread updated successfully')
      onUpdated()
    } catch (error) {
      console.error('Error updating thread:', error)
      toast.error(error instanceof Error ? error.message : 'Failed to update thread')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit {thread.isChannel ? 'Channel' : 'Group Chat'}</DialogTitle>
          <DialogDescription>
            Update the name and description for this {thread.isChannel ? 'channel' : 'group chat'}.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              placeholder={thread.isChannel ? 'Channel name' : 'Group name'}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description (optional)</Label>
            <Textarea
              id="description"
              placeholder="Describe the purpose of this conversation..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
            />
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={saving}
          >
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving || !name.trim()}>
            {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Save Changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

