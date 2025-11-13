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
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { toast } from 'sonner'
import { Loader2, User } from 'lucide-react'

interface Member {
  id: string
  displayName?: string | null
  bio?: string | null
  avatar?: string | null
  user: {
    name: string | null
    email: string
    image?: string | null
  }
}

interface EditMemberProfileDialogProps {
  teamId: string
  member: Member
  open: boolean
  onOpenChange: (open: boolean) => void
  isOwnProfile: boolean
  isAdmin: boolean
  onUpdated: () => void
}

export function EditMemberProfileDialog({
  teamId,
  member,
  open,
  onOpenChange,
  isOwnProfile,
  isAdmin,
  onUpdated
}: EditMemberProfileDialogProps) {
  const [displayName, setDisplayName] = useState('')
  const [bio, setBio] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (open && member) {
      setDisplayName(member.displayName || member.user.name || '')
      setBio(member.bio || '')
    }
  }, [open, member])

  async function handleSave() {
    // Check permissions
    if (!isOwnProfile && !isAdmin) {
      toast.error('You can only edit your own profile')
      return
    }

    setSaving(true)
    try {
      const response = await fetch(`/api/teams/${teamId}/members/${member.id}/nickname`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          displayName: displayName.trim() || null,
          bio: bio.trim() || null
        })
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to update profile')
      }

      toast.success('Profile updated successfully')
      onUpdated()
    } catch (error) {
      console.error('Error updating profile:', error)
      toast.error(error instanceof Error ? error.message : 'Failed to update profile')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Profile</DialogTitle>
          <DialogDescription>
            Update your display name and bio for this team.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Avatar Preview */}
          <div className="flex justify-center">
            <Avatar className="h-20 w-20">
              <AvatarImage src={member.avatar || member.user.image || undefined} />
              <AvatarFallback className="text-2xl">
                {(displayName || member.user.name)?.[0] || <User className="h-8 w-8" />}
              </AvatarFallback>
            </Avatar>
          </div>

          <div className="space-y-2">
            <Label htmlFor="displayName">Display Name</Label>
            <Input
              id="displayName"
              placeholder="Your nickname in this team"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              This is how other team members will see you
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="bio">Bio (optional)</Label>
            <Textarea
              id="bio"
              placeholder="Tell your team a bit about yourself..."
              value={bio}
              onChange={(e) => setBio(e.target.value)}
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
          <Button onClick={handleSave} disabled={saving}>
            {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Save Changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

