'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { Sparkles, Loader2 } from 'lucide-react';
import { useRouter } from 'next/navigation';

interface ReAnalyzeContactButtonProps {
  contactId: string;
}

export function ReAnalyzeContactButton({ contactId }: ReAnalyzeContactButtonProps) {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const router = useRouter();

  async function handleReAnalyze() {
    setIsAnalyzing(true);
    try {
      const res = await fetch('/api/contacts/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'analyze',
          contactIds: [contactId],
        }),
      });

      if (!res.ok) {
        const error = await res.json().catch(() => ({ error: 'Failed to re-analyze contact' }));
        throw new Error(error.error || 'Failed to re-analyze contact');
      }

      const result = await res.json();

      // Check if this is a background job
      if (result.analyzing && result.jobId) {
        toast.info('Re-analysis started in background', {
          description: 'The contact will be analyzed with the comprehensive format. The page will refresh when complete.',
          duration: 5000,
        });

        // Store job ID and listen for completion
        if (typeof window !== 'undefined') {
          sessionStorage.setItem('activeAnalysisJobId', result.jobId);
          window.dispatchEvent(new CustomEvent('analysisStarted', { detail: { jobId: result.jobId } }));

          // Poll for completion (simple approach - could be improved with websockets)
          const checkCompletion = async () => {
            try {
              const statusRes = await fetch(`/api/contacts/analysis-status/${result.jobId}`);
              if (statusRes.ok) {
                const job = await statusRes.json();
                if (job.status === 'COMPLETED' || job.status === 'FAILED') {
                  // Refresh the page to show updated analysis
                  router.refresh();
                  toast.success('Analysis completed!', {
                    description: 'The contact has been re-analyzed with comprehensive data.',
                    duration: 3000,
                  });
                } else {
                  // Check again in 3 seconds
                  setTimeout(checkCompletion, 3000);
                }
              }
            } catch (error) {
              console.error('Error checking analysis status:', error);
            }
          };

          // Start polling after a short delay
          setTimeout(checkCompletion, 3000);
        }
      } else {
        // Legacy synchronous response
        toast.success('Contact re-analyzed successfully', {
          description: 'The comprehensive analysis has been generated.',
          duration: 3000,
        });
        router.refresh();
      }
    } catch (error) {
      toast.error('Failed to re-analyze contact', {
        description: error instanceof Error ? error.message : 'An error occurred while re-analyzing the contact.',
        duration: 5000,
      });
      console.error('Re-analysis error:', error);
    } finally {
      setIsAnalyzing(false);
    }
  }

  return (
    <Button
      onClick={handleReAnalyze}
      disabled={isAnalyzing}
      variant="outline"
      size="sm"
      className="mt-3"
    >
      {isAnalyzing ? (
        <>
          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          Re-analyzing...
        </>
      ) : (
        <>
          <Sparkles className="h-4 w-4 mr-2" />
          Re-analyze Contact
        </>
      )}
    </Button>
  );
}


