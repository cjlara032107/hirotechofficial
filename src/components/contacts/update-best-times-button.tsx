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

  const handleUpdate = async () => {
    setIsUpdating(true);
    try {
      console.log(`[UpdateBestTimesButton] Starting update for contact ${contactId}`);
      const response = await fetch(`/api/contacts/${contactId}/update-best-times`, {
        method: 'POST',
      });

      console.log(`[UpdateBestTimesButton] Response status: ${response.status}`);
      
      const contentType = response.headers.get('content-type');
      let data;
      
      if (contentType?.includes('application/json')) {
        data = await response.json();
      } else {
        const text = await response.text();
        console.error('[UpdateBestTimesButton] Non-JSON response:', text);
        throw new Error(`Server returned non-JSON response: ${text.substring(0, 200)}`);
      }

      console.log('[UpdateBestTimesButton] Response data:', data);

      if (!response.ok) {
        // Safely extract error message
        const errorMessage = data?.error || data?.message || `HTTP ${response.status}: Failed to update best contact times`;
        
        // Log error details - use JSON.stringify to ensure proper serialization
        console.error('[UpdateBestTimesButton] Error response:', JSON.stringify({
          status: response.status,
          statusText: response.statusText,
          error: errorMessage,
          hasError: !!data?.error,
          hasMessage: !!data?.message,
          hasGuidance: !!data?.guidance,
          messageCount: data?.messageCount,
          hasDataIntegrityIssue: data?.hasDataIntegrityIssue,
          messagesViaConversations: data?.messagesViaConversations,
          fullResponse: data,
        }, null, 2));
        
        // If there's guidance, include it in the error message for better UX
        if (data?.guidance) {
          throw new Error(`${errorMessage}\n\n${data.guidance}`);
        }
        
        throw new Error(errorMessage);
      }

      // Show appropriate success message based on whether times were borrowed or computed
      if (data.isBorrowed) {
        toast.success(data.message || 'Best contact times applied from similar contact', {
          description: data.guidance,
          duration: 6000,
        });
      } else {
        toast.success('Best contact times updated successfully');
      }
      
      // Refresh the page to show updated data
      router.refresh();
    } catch (error) {
      console.error('[UpdateBestTimes] Full error:', error);
      if (error instanceof Error) {
        console.error('[UpdateBestTimes] Error message:', error.message);
        console.error('[UpdateBestTimes] Error stack:', error.stack);
        
        // Split multi-line error messages for better toast display
        const errorMessage = error.message;
        const lines = errorMessage.split('\n\n');
        const title = lines[0];
        const description = lines.length > 1 ? lines.slice(1).join('\n') : undefined;
        
        toast.error(title, {
          description,
          duration: 8000,
        });
      } else {
        toast.error('Failed to update best contact times');
      }
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleUpdate}
      disabled={isUpdating}
      className="gap-2 shrink-0"
    >
      <RefreshCw className={`h-4 w-4 ${isUpdating ? 'animate-spin' : ''}`} />
      <span>{isUpdating ? 'Updating...' : 'Update Times'}</span>
    </Button>
  );
}

