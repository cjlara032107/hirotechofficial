'use client';

import { useState, useEffect, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Plus, Edit2, Trash2, Tag as TagIcon, MessageSquare } from 'lucide-react';
import { toast } from 'sonner';
import { EmptyState } from '@/components/ui/empty-state';
import { useRouter } from 'next/navigation';

interface Tag {
  id: string;
  name: string;
  description?: string;
  color: string;
  contactCount: number;
}

const COLOR_OPTIONS = [
  { value: '#ef4444', label: 'Red' },
  { value: '#f97316', label: 'Orange' },
  { value: '#f59e0b', label: 'Amber' },
  { value: '#eab308', label: 'Yellow' },
  { value: '#84cc16', label: 'Lime' },
  { value: '#22c55e', label: 'Green' },
  { value: '#10b981', label: 'Emerald' },
  { value: '#14b8a6', label: 'Teal' },
  { value: '#06b6d4', label: 'Cyan' },
  { value: '#0ea5e9', label: 'Sky' },
  { value: '#3b82f6', label: 'Blue' },
  { value: '#6366f1', label: 'Indigo' },
  { value: '#8b5cf6', label: 'Violet' },
  { value: '#a855f7', label: 'Purple' },
  { value: '#d946ef', label: 'Fuchsia' },
  { value: '#ec4899', label: 'Pink' },
  { value: '#f43f5e', label: 'Rose' },
  { value: '#64748b', label: 'Slate' },
  { value: '#6b7280', label: 'Gray' },
  { value: '#71717a', label: 'Zinc' },
];

export default function TagsPage() {
  const router = useRouter();
  const [tags, setTags] = useState<Tag[]>([]);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingTag, setEditingTag] = useState<Tag | null>(null);
  const [selectedColor, setSelectedColor] = useState('#64748b');
  const [editColor, setEditColor] = useState('#64748b');

  const fetchTags = async () => {
    try {
      const response = await fetch('/api/tags');
      const data = await response.json();
      if (response.ok) {
        setTags(data);
      }
    } catch (error) {
      console.error('Error fetching tags:', error);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchTags().catch(console.error);
  }, []);

  // Synchronize edit color with editing tag
  // Using a ref to avoid setState in effect
  const prevEditingTagRef = useRef(editingTag);
  
  useEffect(() => {
    if (prevEditingTagRef.current !== editingTag) {
      prevEditingTagRef.current = editingTag;
      if (editingTag) {
        // Defer state update to avoid synchronous setState in effect
        queueMicrotask(() => {
          setEditColor(editingTag.color);
        });
      }
    }
  }, [editingTag]);

  const handleCreateTag = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);

    try {
      const response = await fetch('/api/tags', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.get('name'),
          description: formData.get('description'),
          color: selectedColor,
        }),
      });

      if (response.ok) {
        toast.success('Tag created successfully');
        setIsCreateOpen(false);
        setSelectedColor('#64748b'); // Reset to default
        fetchTags();
      } else {
        const data = await response.json();
        toast.error(data.error || 'Failed to create tag');
      }
    } catch (_error) {
      console.error('Error creating tag:', _error);
      toast.error('An error occurred');
    }
  };

  const handleEditTag = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!editingTag) return;

    const formData = new FormData(e.currentTarget);

    try {
      const response = await fetch(`/api/tags/${editingTag.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.get('name'),
          description: formData.get('description'),
          color: editColor,
        }),
      });

      if (response.ok) {
        toast.success('Tag updated successfully');
        setEditingTag(null);
        fetchTags();
      } else {
        const data = await response.json();
        toast.error(data.error || 'Failed to update tag');
      }
    } catch (_error) {
      console.error('Error updating tag:', _error);
      toast.error('An error occurred');
    }
  };

  const handleDeleteTag = async (id: string, name: string) => {
    if (!confirm(`Delete tag "${name}"? This won't delete the contacts.`)) return;

    try {
      const response = await fetch(`/api/tags/${id}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        toast.success('Tag deleted successfully');
        fetchTags();
      } else {
        toast.error('Failed to delete tag');
      }
    } catch (_error) {
      console.error('Error deleting tag:', _error);
      toast.error('An error occurred');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Tags</h1>
          <p className="text-muted-foreground mt-2">
            Organize and segment your contacts with tags
          </p>
        </div>

        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Create Tag
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Tag</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreateTag} className="space-y-4">
              <div>
                <Label htmlFor="name">Tag Name *</Label>
                <Input
                  id="name"
                  name="name"
                  placeholder="e.g., Hot Lead, VIP, Interested"
                  required
                />
              </div>

              <div>
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  name="description"
                  placeholder="Optional description..."
                  rows={3}
                />
              </div>

              <div>
                <Label htmlFor="color">Color</Label>
                <Select value={selectedColor} onValueChange={setSelectedColor}>
                  <SelectTrigger className="w-full">
                    <SelectValue>
                      <div className="flex items-center gap-2">
                        <div
                          className="w-4 h-4 rounded-full"
                          style={{ backgroundColor: selectedColor }}
                        />
                        <span>
                          {COLOR_OPTIONS.find((c) => c.value === selectedColor)?.label}
                        </span>
                      </div>
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    {COLOR_OPTIONS.map((color) => (
                      <SelectItem key={color.value} value={color.value}>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-4 h-4 rounded-full"
                            style={{ backgroundColor: color.value }}
                          />
                          <span>{color.label}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <Button type="submit" className="w-full">
                Create Tag
              </Button>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Edit Tag Dialog */}
      <Dialog 
        open={!!editingTag} 
        onOpenChange={(open) => !open && setEditingTag(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Tag</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditTag} className="space-y-4">
            <div>
              <Label htmlFor="edit-name">Tag Name *</Label>
              <Input
                id="edit-name"
                name="name"
                placeholder="e.g., Hot Lead, VIP, Interested"
                defaultValue={editingTag?.name || ''}
                required
              />
            </div>

            <div>
              <Label htmlFor="edit-description">Description</Label>
              <Textarea
                id="edit-description"
                name="description"
                placeholder="Optional description..."
                defaultValue={editingTag?.description || ''}
                rows={3}
              />
            </div>

            <div>
              <Label htmlFor="edit-color">Color</Label>
              <Select value={editColor} onValueChange={setEditColor}>
                <SelectTrigger className="w-full">
                  <SelectValue>
                    <div className="flex items-center gap-2">
                      <div
                        className="w-4 h-4 rounded-full"
                        style={{ backgroundColor: editColor }}
                      />
                      <span>
                        {COLOR_OPTIONS.find((c) => c.value === editColor)?.label}
                      </span>
                    </div>
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {COLOR_OPTIONS.map((color) => (
                    <SelectItem key={color.value} value={color.value}>
                      <div className="flex items-center gap-2">
                        <div
                          className="w-4 h-4 rounded-full"
                          style={{ backgroundColor: color.value }}
                        />
                        <span>{color.label}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Button type="submit" className="w-full">
              Update Tag
            </Button>
          </form>
        </DialogContent>
      </Dialog>

      {tags.length === 0 ? (
        <EmptyState
          icon={<TagIcon className="h-12 w-12" />}
          title="No tags yet"
          description="Create tags to organize and segment your contacts"
          action={{
            label: 'Create Tag',
            onClick: () => setIsCreateOpen(true),
          }}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {tags.map((tag) => (
            <Card key={tag.id} className="relative">
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: tag.color }}
                    />
                    <CardTitle className="text-lg">{tag.name}</CardTitle>
                  </div>
                  <div className="flex gap-1">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-8 w-8"
                      onClick={() => setEditingTag(tag)}
                    >
                      <Edit2 className="h-3 w-3" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-8 w-8"
                      onClick={() => handleDeleteTag(tag.id, tag.name)}
                    >
                      <Trash2 className="h-3 w-3 text-destructive" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {tag.description && (
                  <p className="text-sm text-muted-foreground">{tag.description}</p>
                )}

                <div className="flex items-center justify-between pt-2 border-t">
                  <Badge variant="secondary">{tag.contactCount} contacts</Badge>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      router.push(`/campaigns/new?targetType=tags&tags=${tag.name}`)
                    }
                  >
                    <MessageSquare className="h-3 w-3 mr-1" />
                    Campaign
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

