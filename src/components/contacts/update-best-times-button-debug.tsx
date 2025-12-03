'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { RefreshCw } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';

interface UpdateBestTimesButtonProps {
  contactId: string;
}

export function UpdateBestTimesButton({ contactId }: UpdateBestTimesButtonProps) {
  const [isUpdating, setIsUpdating] = useState(false);
  const router = useRouter();

  // Debug: Log when component renders
  console.log('[UpdateBestTimesButton] Rendering with contactId:', contactId);

  const handleUpdate = async () => {
    setIsUpdating(true);
    try {
      const response = await fetch(`/api/contacts/${contactId}/update-best-times`, {
        method: 'POST',
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || data.message || 'Failed to update best contact times');
      }

      toast.success('Best contact times updated successfully');
      
      // Refresh the page to show updated data
      router.refresh();
    } catch (error) {
      console.error('[UpdateBestTimes] Error:', error);
      toast.error(
        error instanceof Error ? error.message : 'Failed to update best contact times'
      );
    } finally {
      setIsUpdating(false);
    }
  };

  // Make button very visible for debugging
  return (
    <div className="border-2 border-red-500 p-1 rounded">
      <Button
        variant="default"
        size="sm"
        onClick={handleUpdate}
        disabled={isUpdating}
        className="gap-2 shrink-0 bg-blue-600 hover:bg-blue-700"
      >
        <RefreshCw className={`h-4 w-4 ${isUpdating ? 'animate-spin' : ''}`} />
        <span>{isUpdating ? 'Updating...' : 'Update Times'}</span>
      </Button>
    </div>
  );
}













