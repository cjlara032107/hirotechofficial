'use client';

import { useEffect, useState, useRef } from 'react';
import { Sparkles, X, CheckCircle2, AlertCircle, Loader2, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { cn } from '@/lib/utils';

interface AnalysisJob {
  id: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  totalContacts: number;
  analyzedContacts: number;
  failedContacts: number;
  startedAt: Date | null;
  completedAt: Date | null;
  errors?: Array<{ id?: string; error?: string; platform?: string; code?: number } | string>;
}

export interface AnalysisIndicatorProps {
  jobId: string;
  onComplete?: () => void;
  onError?: (error: Error) => void;
  onDismiss?: () => void;
}

export function AnalysisIndicator({ jobId, onComplete, onError, onDismiss }: AnalysisIndicatorProps) {
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [isPolling, setIsPolling] = useState(true);
  const [dismissed, setDismissed] = useState(false);
  const [isReanalyzing, setIsReanalyzing] = useState(false);
  const shouldPollRef = useRef(true);

  useEffect(() => {
    if (!jobId || dismissed) return;

    shouldPollRef.current = true;

    const pollStatus = async () => {
      // Check ref before polling
      if (!shouldPollRef.current) return;

      try {
        const response = await fetch(`/api/contacts/analysis-status/${jobId}`);
        if (!response || !response.ok) {
          throw new Error('Failed to fetch status');
        }

        const data = await response.json();
        setJob(data);

        // Check if job is complete
        if (data.status === 'COMPLETED' || data.status === 'FAILED' || data.status === 'CANCELLED') {
          shouldPollRef.current = false;
          setIsPolling(false);
          
          if (data.status === 'COMPLETED') {
            toast.success(
              `Analysis complete! ${data.analyzedContacts} contact(s) analyzed${data.failedContacts > 0 ? ` (${data.failedContacts} failed)` : ''}`,
              { duration: 5000 }
            );
            
            // CRITICAL: Dispatch event to trigger page refresh on contact detail pages
            if (typeof window !== 'undefined') {
              window.dispatchEvent(new CustomEvent('analysisCompleted', { 
                detail: { 
                  jobId,
                  analyzedContacts: data.analyzedContacts,
                  failedContacts: data.failedContacts
                } 
              }));
            }
          } else if (data.status === 'FAILED') {
            toast.error('Analysis failed. Please try again.', { duration: 5000 });
            
            // Log error details for debugging
            if (data.errors && Array.isArray(data.errors) && data.errors.length > 0) {
              console.error('[Analysis Indicator] Analysis failed with errors:', data.errors);
            }
          }

          if (onComplete) {
            onComplete();
          }
        }
      } catch (error) {
        console.error('Error polling analysis status:', error);
        if (onError && error instanceof Error) {
          onError(error);
        }
      }
    };

    // Poll immediately
    pollStatus();

    // Set up polling interval (every 2 seconds)
    const pollInterval = setInterval(() => {
      if (shouldPollRef.current && !document.hidden) {
        pollStatus();
      }
    }, 2000);

    // Check page visibility and resume polling when visible
    const handleVisibilityChange = () => {
      if (!document.hidden && shouldPollRef.current) {
        pollStatus();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    // Cleanup
    return () => {
      shouldPollRef.current = false;
      if (pollInterval) clearInterval(pollInterval);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [jobId, dismissed, onComplete, onError]);

  const handleDismiss = () => {
    shouldPollRef.current = false;
    setDismissed(true);
    setIsPolling(false);
    if (onDismiss) {
      onDismiss();
    }
  };

  const handleReanalyzeFailed = async () => {
    if (!job || job.failedContacts === 0) return;

    setIsReanalyzing(true);
    try {
      const response = await fetch(`/api/facebook/analyze-pipeline/reanalyze-failed/${jobId}`, {
        method: 'POST',
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to reanalyze contacts');
      }

      toast.success(
        `Reanalysis started! ${data.reanalyzed} contact(s) reanalyzed successfully${data.failed > 0 ? ` (${data.failed} still failed)` : ''}`,
        { duration: 5000 }
      );

      // Refresh job status to show updated counts
      if (shouldPollRef.current) {
        const statusResponse = await fetch(`/api/contacts/analysis-status/${jobId}`);
        if (statusResponse.ok) {
          const updatedJob = await statusResponse.json();
          setJob(updatedJob);
        }
      }
    } catch (error) {
      console.error('Error reanalyzing failed contacts:', error);
      toast.error(
        error instanceof Error ? error.message : 'Failed to reanalyze contacts',
        { duration: 5000 }
      );
    } finally {
      setIsReanalyzing(false);
    }
  };

  if (dismissed || !job) {
    return null;
  }

  const progress = job.totalContacts > 0 
    ? Math.round((job.analyzedContacts / job.totalContacts) * 100)
    : 0;

  const isComplete = job.status === 'COMPLETED' || job.status === 'FAILED' || job.status === 'CANCELLED';
  const isInProgress = job.status === 'IN_PROGRESS' || job.status === 'PENDING';
  const hasFailedContacts = job.failedContacts > 0;
  const canReanalyze = isComplete && hasFailedContacts && (job.status === 'COMPLETED' || job.status === 'FAILED');

  return (
    <Card className={cn(
      "fixed bottom-4 right-4 z-50 w-96 shadow-lg border-l-4",
      isComplete && job.status === 'COMPLETED' && "border-l-green-500",
      isComplete && job.status === 'FAILED' && "border-l-red-500",
      isInProgress && "border-l-blue-500"
    )}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1">
            {isInProgress && (
              <Loader2 className="h-5 w-5 text-blue-500 animate-spin mt-0.5" />
            )}
            {isComplete && job.status === 'COMPLETED' && (
              <CheckCircle2 className="h-5 w-5 text-green-500 mt-0.5" />
            )}
            {isComplete && job.status === 'FAILED' && (
              <AlertCircle className="h-5 w-5 text-red-500 mt-0.5" />
            )}
            {!isInProgress && !isComplete && (
              <Sparkles className="h-5 w-5 text-blue-500 mt-0.5" />
            )}

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h4 className="text-sm font-semibold">
                  {isInProgress && 'Analyzing Contacts'}
                  {isComplete && job.status === 'COMPLETED' && 'Analysis Complete'}
                  {isComplete && job.status === 'FAILED' && 'Analysis Failed'}
                  {isComplete && job.status === 'CANCELLED' && 'Analysis Cancelled'}
                </h4>
              </div>

              {isInProgress && (
                <>
                  <p className="text-xs text-muted-foreground mb-2">
                    {job.analyzedContacts} of {job.totalContacts} contacts analyzed
                    {job.failedContacts > 0 && ` • ${job.failedContacts} failed`}
                  </p>
                  <Progress value={progress} className="h-2" />
                </>
              )}

              {isComplete && job.status === 'COMPLETED' && (
                <>
                  <p className="text-xs text-muted-foreground mb-2">
                    Successfully analyzed {job.analyzedContacts} contact(s)
                    {hasFailedContacts && ` • ${job.failedContacts} failed`}
                  </p>
                  {canReanalyze && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full mt-2"
                      onClick={handleReanalyzeFailed}
                      disabled={isReanalyzing}
                    >
                      {isReanalyzing ? (
                        <>
                          <Loader2 className="h-3 w-3 mr-2 animate-spin" />
                          Reanalyzing...
                        </>
                      ) : (
                        <>
                          <RefreshCw className="h-3 w-3 mr-2" />
                          Reanalyze Failed ({job.failedContacts})
                        </>
                      )}
                    </Button>
                  )}
                </>
              )}

              {isComplete && job.status === 'FAILED' && (
                <>
                  <p className="text-xs text-muted-foreground mb-2">
                    Analysis encountered an error. Please try again.
                    {hasFailedContacts && ` ${job.failedContacts} contact(s) failed.`}
                  </p>
                  {canReanalyze && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full mt-2"
                      onClick={handleReanalyzeFailed}
                      disabled={isReanalyzing}
                    >
                      {isReanalyzing ? (
                        <>
                          <Loader2 className="h-3 w-3 mr-2 animate-spin" />
                          Reanalyzing...
                        </>
                      ) : (
                        <>
                          <RefreshCw className="h-3 w-3 mr-2" />
                          Reanalyze Failed ({job.failedContacts})
                        </>
                      )}
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>

          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 shrink-0"
            onClick={handleDismiss}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
