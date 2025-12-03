'use client';

import { useState, useTransition, useEffect } from 'react';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Edit2, Check, X } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';

interface EditableNotesProps {
  contactId: string;
  initialNotes: string | null;
}

export function EditableNotes({ contactId, initialNotes }: EditableNotesProps) {
  const [notes, setNotes] = useState(initialNotes || '');
  const [isEditing, setIsEditing] = useState(false);
  const [isPending, startTransition] = useTransition();
  const router = useRouter();

  // Sync local state when initialNotes changes (after server refresh)
  useEffect(() => {
    if (!isEditing) {
      setNotes(initialNotes || '');
    }
  }, [initialNotes, isEditing]);

  const handleSave = async () => {
    startTransition(async () => {
      try {
        const response = await fetch(`/api/contacts/${contactId}`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ notes: notes.trim() || null }),
        });

        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.error || 'Failed to update notes');
        }

        const updated = await response.json();
        setIsEditing(false);
        router.refresh();
        toast.success('Notes updated successfully');
      } catch (error) {
        console.error('Error updating notes:', error);
        toast.error(error instanceof Error ? error.message : 'Failed to update notes');
      }
    });
  };

  const handleCancel = () => {
    setNotes(initialNotes || '');
    setIsEditing(false);
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Notes</CardTitle>
          {!isEditing && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsEditing(true)}
              className="h-8 w-8 p-0"
            >
              <Edit2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {isEditing ? (
          <div className="space-y-3">
            <Textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Add notes about this contact..."
              className="min-h-[120px] resize-none"
              disabled={isPending}
            />
            <div className="flex gap-2 justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={handleCancel}
                disabled={isPending}
              >
                <X className="h-4 w-4 mr-2" />
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleSave}
                disabled={isPending}
              >
                {isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Check className="h-4 w-4 mr-2" />
                    Save
                  </>
                )}
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            {notes ? (
              <p className="text-sm whitespace-pre-wrap">{notes}</p>
            ) : (
              <p className="text-sm text-muted-foreground">No notes yet. Click the edit button to add notes.</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

