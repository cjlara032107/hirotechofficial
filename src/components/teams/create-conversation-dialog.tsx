'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { toast } from 'sonner'
import { Plus, Users, MessageSquare, Radio, Upload, Loader2 } from 'lucide-react'

interface TeamMember {
  id: string
  user: {
    name: string | null
    image: string | null
  }
  displayName?: string | null
  avatar?: string | null
  title?: string | null
  role: string
  status: string
}

interface CreateConversationDialogProps {
  teamId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  isAdmin: boolean
  onCreated: () => void
}

export function CreateConversationDialog({
  teamId,
  open,
  onOpenChange,
  isAdmin,
  onCreated
}: CreateConversationDialogProps) {
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [members, setMembers] = useState<TeamMember[]>([])
  const [type, setType] = useState<'direct' | 'group' | 'channel'>('direct')

  // Common fields
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [avatar, setAvatar] = useState('')
  const [selectedMembers, setSelectedMembers] = useState<string[]>([])
  const [selectAll, setSelectAll] = useState(false)

  // Group/Channel specific
  const [enableTopics, setEnableTopics] = useState(false)

  const fetchMembers = useCallback(async () => {
    try {
      const response = await fetch(`/api/teams/${teamId}/members`)
      const data = await response.json()
      
      if (!response.ok) {
        console.error('Failed to fetch members:', data.error)
        toast.error(data.error || 'Failed to load team members')
        setMembers([])
        return
      }
      
      const membersList = data.members || []
      setMembers(membersList.filter((m: TeamMember) => 
        m.status === 'ACTIVE'
      ))
    } catch (err) {
      console.error('Error fetching members:', err)
      toast.error('Failed to load team members')
      setMembers([])
    }
  }, [teamId])

  useEffect(() => {
    if (open) {
      fetchMembers()
    }
  }, [open, fetchMembers])

  function toggleMember(memberId: string) {
    setSelectedMembers(prev =>
      prev.includes(memberId)
        ? prev.filter(id => id !== memberId)
        : [...prev, memberId]
    )
  }

  function handleSelectAll() {
    if (selectAll) {
      setSelectedMembers([])
    } else {
      setSelectedMembers(members.map(m => m.id))
    }
    setSelectAll(!selectAll)
  }

  async function handleAvatarUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    if (!file.type.startsWith('image/')) {
      toast.error('Please upload an image file')
      return
    }

    if (file.size > 5 * 1024 * 1024) {
      toast.error('Image size must be less than 5MB')
      return
    }

    setUploading(true)
    try {
      const reader = new FileReader()
      reader.onloadend = () => {
        setAvatar(reader.result as string)
        toast.success('Image uploaded')
      }
      reader.readAsDataURL(file)
    } catch (error) {
      toast.error('Failed to upload image')
    } finally {
      setUploading(false)
    }
  }

  async function createConversation() {
    // Admin-only check for channels
    if (type === 'channel' && !isAdmin) {
      toast.error('Only admins can create channels')
      return
    }

    if (type === 'direct' && selectedMembers.length !== 1) {
      toast.error('Please select exactly one member for direct message')
      return
    }

    if ((type === 'group' || type === 'channel') && !title.trim()) {
      toast.error('Please enter a name')
      return
    }

    if ((type === 'group' || type === 'channel') && selectedMembers.length === 0) {
      toast.error('Please select at least one member')
      return
    }

    setLoading(true)
    try {
      const response = await fetch(`/api/teams/${teamId}/threads`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: type.toUpperCase(),
          title: title.trim() || null,
          description: description.trim() || null,
          avatar: avatar || null,
          participantIds: selectedMembers,
          isChannel: type === 'channel',
          groupName: type === 'group' ? title.trim() : null,
          enableTopics: type === 'group' ? enableTopics : false
        })
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to create conversation')
      }

      toast.success(`${type === 'channel' ? 'Channel' : type === 'group' ? 'Group' : 'Conversation'} created successfully`)
      onCreated()
      resetForm()
      onOpenChange(false)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to create conversation')
    } finally {
      setLoading(false)
    }
  }

  function resetForm() {
    setTitle('')
    setDescription('')
    setAvatar('')
    setSelectedMembers([])
    setSelectAll(false)
    setEnableTopics(false)
    setType('direct')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Create New Conversation</DialogTitle>
          <DialogDescription>
            Start a direct message, create a group chat, or set up a channel
          </DialogDescription>
        </DialogHeader>

        <Tabs value={type} onValueChange={(v) => setType(v as 'direct' | 'group' | 'channel')}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="direct">
              <MessageSquare className="w-4 h-4 mr-2" />
              Direct Message
            </TabsTrigger>
            <TabsTrigger value="group">
              <Users className="w-4 h-4 mr-2" />
              Group Chat
            </TabsTrigger>
            <TabsTrigger value="channel" disabled={!isAdmin}>
              <Radio className="w-4 h-4 mr-2" />
              Channel {!isAdmin && '(Admin Only)'}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="direct" className="space-y-4 mt-4">
            <div className="space-y-2">
              <Label>Select Member</Label>
              <ScrollArea className="h-[300px] border rounded-lg p-4">
                <div className="space-y-2">
                  {members.map((member) => (
                    <div
                      key={member.id}
                      className="flex items-center space-x-3 p-2 hover:bg-muted rounded-lg cursor-pointer"
                      onClick={() => {
                        setSelectedMembers([member.id])
                      }}
                    >
                      <Checkbox
                        checked={selectedMembers.includes(member.id)}
                        onCheckedChange={() => {
                          setSelectedMembers([member.id])
                        }}
                      />
                      <Avatar className="h-8 w-8">
                        <AvatarImage src={member.user.image || member.avatar || undefined} />
                        <AvatarFallback>{member.user.name?.[0] || 'U'}</AvatarFallback>
                      </Avatar>
                      <div className="flex-1">
                        <p className="text-sm font-medium">
                          {member.displayName || member.user.name}
                        </p>
                        {member.title && (
                          <p className="text-xs text-muted-foreground">{member.title}</p>
                        )}
                      </div>
                      <Badge variant="secondary">{member.role}</Badge>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>

          <TabsContent value="group" className="space-y-4 mt-4">
            <div className="space-y-4">
              {/* Avatar Upload */}
              <div className="flex items-center gap-4">
                <Avatar className="h-16 w-16">
                  <AvatarImage src={avatar} />
                  <AvatarFallback>
                    <Users className="w-8 h-8" />
                  </AvatarFallback>
                </Avatar>
                <div>
                  <input
                    type="file"
                    id="group-avatar"
                    accept="image/*"
                    onChange={handleAvatarUpload}
                    className="hidden"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => document.getElementById('group-avatar')?.click()}
                    disabled={uploading}
                  >
                    {uploading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Upload className="w-4 h-4 mr-2" />
                    )}
                    Upload Picture
                  </Button>
                </div>
              </div>

              {/* Group Name */}
              <div className="space-y-2">
                <Label htmlFor="group-name">Group Name *</Label>
                <Input
                  id="group-name"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="Enter group name"
                />
              </div>

              {/* Group Description */}
              <div className="space-y-2">
                <Label htmlFor="group-description">Description</Label>
                <Textarea
                  id="group-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What's this group about?"
                  rows={2}
                />
              </div>

              {/* Enable Topics (Telegram-style) */}
              <div className="flex items-center justify-between space-x-2">
                <div className="space-y-0.5">
                  <Label>Enable Topics</Label>
                  <p className="text-xs text-muted-foreground">
                    Organize conversations by topics (like Telegram)
                  </p>
                </div>
                <Switch
                  checked={enableTopics}
                  onCheckedChange={setEnableTopics}
                />
              </div>

              {/* Select Members */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Add Members *</Label>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={handleSelectAll}
                  >
                    {selectAll ? 'Deselect All' : 'Select All'}
                  </Button>
                </div>
                <ScrollArea className="h-[200px] border rounded-lg p-4">
                  <div className="space-y-2">
                    {members.map((member) => (
                      <div
                        key={member.id}
                        className="flex items-center space-x-3 p-2 hover:bg-muted rounded-lg cursor-pointer"
                        onClick={() => toggleMember(member.id)}
                      >
                        <Checkbox
                          checked={selectedMembers.includes(member.id)}
                          onCheckedChange={() => toggleMember(member.id)}
                        />
                        <Avatar className="h-8 w-8">
                          <AvatarImage src={member.user.image || member.avatar || undefined} />
                          <AvatarFallback>{member.user.name?.[0] || 'U'}</AvatarFallback>
                        </Avatar>
                        <div className="flex-1">
                          <p className="text-sm font-medium">
                            {member.displayName || member.user.name}
                          </p>
                          {member.title && (
                            <p className="text-xs text-muted-foreground">{member.title}</p>
                          )}
                        </div>
                        <Badge variant="secondary">{member.role}</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
                <p className="text-xs text-muted-foreground">
                  {selectedMembers.length} member(s) selected
                </p>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="channel" className="space-y-4 mt-4">
            <div className="space-y-4">
              {/* Channel Avatar */}
              <div className="flex items-center gap-4">
                <Avatar className="h-16 w-16">
                  <AvatarImage src={avatar} />
                  <AvatarFallback>
                    <Radio className="w-8 h-8" />
                  </AvatarFallback>
                </Avatar>
                <div>
                  <input
                    type="file"
                    id="channel-avatar"
                    accept="image/*"
                    onChange={handleAvatarUpload}
                    className="hidden"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => document.getElementById('channel-avatar')?.click()}
                    disabled={uploading}
                  >
                    {uploading ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Upload className="w-4 h-4 mr-2" />
                    )}
                    Upload Picture
                  </Button>
                </div>
              </div>

              {/* Channel Name */}
              <div className="space-y-2">
                <Label htmlFor="channel-name">Channel Name *</Label>
                <Input
                  id="channel-name"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g., Announcements, Updates"
                />
              </div>

              {/* Channel Description */}
              <div className="space-y-2">
                <Label htmlFor="channel-description">Description</Label>
                <Textarea
                  id="channel-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What's this channel for?"
                  rows={2}
                />
              </div>

              {/* Info */}
              <div className="bg-muted p-4 rounded-lg">
                <p className="text-sm text-muted-foreground">
                  ℹ️ Channels are broadcast-style conversations where only admins can post messages. All members can read and react.
                </p>
              </div>

              {/* Select Members */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Add Subscribers</Label>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={handleSelectAll}
                  >
                    {selectAll ? 'Deselect All' : 'Select All'}
                  </Button>
                </div>
                <ScrollArea className="h-[200px] border rounded-lg p-4">
                  <div className="space-y-2">
                    {members.map((member) => (
                      <div
                        key={member.id}
                        className="flex items-center space-x-3 p-2 hover:bg-muted rounded-lg cursor-pointer"
                        onClick={() => toggleMember(member.id)}
                      >
                        <Checkbox
                          checked={selectedMembers.includes(member.id)}
                          onCheckedChange={() => toggleMember(member.id)}
                        />
                        <Avatar className="h-8 w-8">
                          <AvatarImage src={member.user.image || member.avatar || undefined} />
                          <AvatarFallback>{member.user.name?.[0] || 'U'}</AvatarFallback>
                        </Avatar>
                        <div className="flex-1">
                          <p className="text-sm font-medium">
                            {member.displayName || member.user.name}
                          </p>
                          {member.title && (
                            <p className="text-xs text-muted-foreground">{member.title}</p>
                          )}
                        </div>
                        <Badge variant="secondary">{member.role}</Badge>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
                <p className="text-xs text-muted-foreground">
                  {selectedMembers.length} subscriber(s) selected
                </p>
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={createConversation} disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Creating...
              </>
            ) : (
              'Create'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

