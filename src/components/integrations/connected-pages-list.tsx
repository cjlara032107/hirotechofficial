'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Facebook, Instagram, RefreshCw, Unplug, CheckCircle2, Users, ChevronLeft, ChevronRight, Settings, XCircle, Sparkles, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { formatDistanceToNow } from 'date-fns';
import Link from 'next/link';
import { formatUserFriendlyError, formatSyncError } from '@/lib/facebook/error-messages';

interface ConnectedPage {
  id: string;
  pageId: string;
  pageName: string;
  instagramAccountId: string | null;
  instagramUsername: string | null;
  isActive: boolean;
  lastSyncedAt: string | null;
  autoSync: boolean;
  autoPipelineId: string | null;
}

interface ConnectedPagesListProps {
  onRefresh?: () => void;
  onSyncComplete?: () => void;
}

interface SyncJob {
  id: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  syncedContacts: number;
  failedContacts: number;
  totalContacts: number;
  tokenExpired: boolean;
  startedAt: string | null;
  completedAt: string | null;
}

interface PageContactCount {
  [pageId: string]: number;
}

interface ActiveSyncJobs {
  [pageId: string]: SyncJob;
}

export function ConnectedPagesList({ onRefresh, onSyncComplete }: ConnectedPagesListProps) {
  const [pages, setPages] = useState<ConnectedPage[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [disconnectingPageId, setDisconnectingPageId] = useState<string | null>(null);
  const [pageToDisconnect, setPageToDisconnect] = useState<ConnectedPage | null>(null);
  const [contactCounts, setContactCounts] = useState<PageContactCount>({});
  const [activeSyncJobs, setActiveSyncJobs] = useState<ActiveSyncJobs>({});
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [isPageVisible, setIsPageVisible] = useState(true);
  const pollingInProgressRef = useRef<Set<string>>(new Set()); // Track in-flight requests
  const failedPollAttemptsRef = useRef<Map<string, number>>(new Map()); // Track failed polling attempts
  
  // Bulk operations state
  const [selectedPageIds, setSelectedPageIds] = useState<Set<string>>(new Set());
  const [isBulkSyncing, setIsBulkSyncing] = useState(false);
  const [isBulkDisconnecting, setIsBulkDisconnecting] = useState(false);
  const [showBulkDisconnectDialog, setShowBulkDisconnectDialog] = useState(false);

  // AI Pipeline Generation state
  const [showAIGenerator, setShowAIGenerator] = useState(false);
  const [aiGenerating, setAiGenerating] = useState(false);
  const [aiStageCount, setAiStageCount] = useState<string>('');
  const [useCustomStageCount, setUseCustomStageCount] = useState(false);
  const [aiDecideStages, setAiDecideStages] = useState(true);
  const [pipelineDetailLevel, setPipelineDetailLevel] = useState(5); // 1-10 scale, default 5
  interface PipelineSuggestion {
    name: string;
    description: string;
    stages: Array<{
      name: string;
      description: string;
      color: string;
      type: string;
      leadScoreMin?: number;
      leadScoreMax?: number;
      expectedContacts?: number;
    }>;
    totalContacts?: number;
    confidence?: number;
  }
  const [aiSuggestion, setAiSuggestion] = useState<PipelineSuggestion | null>(null);
  const [pageForAIGeneration, setPageForAIGeneration] = useState<ConnectedPage | null>(null);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const itemsPerPage = 5;
  // Format elapsed time
  const formatElapsedTime = (startedAt: string | null) => {
    if (!startedAt) return '';
    const start = new Date(startedAt);
    const now = new Date();
    const seconds = Math.floor((now.getTime() - start.getTime()) / 1000);
    
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  };

  // Fetch connected pages
  const fetchConnectedPages = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/facebook/pages/connected', {
        credentials: 'include', // Include cookies for authentication
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        // Try to get the response text for debugging
        const text = await response.text();
        console.error('Non-JSON response received:', text.substring(0, 500));
        throw new Error(`Server returned non-JSON response (${response.status} ${response.statusText}). This usually indicates a build error. Please restart the dev server.`);
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({ error: `HTTP ${response.status}: ${response.statusText}` }));
        
        // If unauthorized, redirect to login
        if (response.status === 401) {
          console.warn('[Connected Pages] Unauthorized - session may have expired');
          // Don't show error toast for auth errors, just log it
          // The middleware or auth system should handle redirect
          setIsLoading(false);
          return;
        }
        
        throw new Error(data.error || 'Failed to fetch connected pages');
      }

      const data = await response.json();
      const fetchedPages = data.pages || [];
      
      // Validate that all pages have required fields
      const validPages = fetchedPages.filter((page: any) => {
        if (!page.id || !page.pageId || !page.pageName) {
          console.warn('[Connected Pages] Invalid page data:', page);
          return false;
        }
        return true;
      });
      
      setPages(validPages);
      
      if (validPages.length !== fetchedPages.length) {
        console.warn(`[Connected Pages] Filtered out ${fetchedPages.length - validPages.length} invalid pages`);
      }
      
      // Show pages immediately - don't block on contact counts and sync jobs
      setIsLoading(false);

      // Fetch contact counts and latest sync jobs in the background (non-blocking)
      // This allows the UI to render immediately while data loads progressively
      Promise.all([
        ...fetchedPages.map((page: ConnectedPage) => fetchContactCount(page.id)),
        ...fetchedPages.map((page: ConnectedPage) => checkLatestSyncJob(page.id)),
      ]).catch((error) => {
        console.error('Error fetching page metadata:', error);
        // Don't show error toast for background loading failures
      });
    } catch (error) {
      const errorMessage = formatUserFriendlyError(error);
      console.error('Error fetching connected pages:', error);
      toast.error(errorMessage);
      setIsLoading(false);
    }
  }, []);

  // Fetch contact count for a specific page
  const fetchContactCount = async (pageId: string) => {
    try {
      const response = await fetch(`/api/facebook/pages/${pageId}/contacts-count`);
      if (response.ok) {
        const data = await response.json();
        setContactCounts(prev => ({ ...prev, [pageId]: data.count }));
      }
    } catch (error) {
      console.error(`Error fetching contact count for page ${pageId}:`, error);
    }
  };

  // Check for latest sync job and resume polling if in progress
  const checkLatestSyncJob = async (pageId: string) => {
    try {
      const response = await fetch(`/api/facebook/pages/${pageId}/latest-sync`);
      if (response.ok) {
        const data = await response.json();
        if (data.job && (data.job.status === 'PENDING' || data.job.status === 'IN_PROGRESS')) {
          setActiveSyncJobs(prev => ({ ...prev, [pageId]: data.job }));
        }
      }
    } catch (error) {
      console.error(`Error checking latest sync job for page ${pageId}:`, error);
    }
  };

  // Poll active sync jobs
  const pollSyncJobs = useCallback(async () => {
    const activeJobs = Object.entries(activeSyncJobs);
    if (activeJobs.length === 0) {
      console.log('[Sync Poll] No active jobs to poll');
      return;
    }

    console.log(`[Sync Poll] Polling ${activeJobs.length} active job(s)`, {
      jobIds: activeJobs.map(([, job]) => job.id),
      isPageVisible,
    });

    for (const [pageId, job] of activeJobs) {
      // Skip temporary job IDs (they'll be replaced with real ones)
      if (job.id.startsWith('temp-')) {
        console.log(`[Sync Poll] Skipping temporary job ID: ${job.id}`);
        continue;
      }

      // Prevent overlapping requests for the same job
      if (pollingInProgressRef.current.has(job.id)) {
        console.log(`[Sync Poll] Job ${job.id} already being polled, skipping`);
        continue;
      }

      pollingInProgressRef.current.add(job.id);

      try {
        // Validate job ID before making request
        if (!job.id || job.id.trim().length === 0) {
          console.warn(`[Sync Poll] Skipping invalid job ID for page ${pageId}`);
          // Remove invalid job from active jobs
          setActiveSyncJobs(prev => {
            const newJobs = { ...prev };
            delete newJobs[pageId];
            return newJobs;
          });
          return;
        }

        const startTime = Date.now();
        
        // Create abort controller for timeout
        // Increased timeout to 30 seconds since sync status API might be slow during heavy syncs
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
        
        let response: Response;
        try {
          response = await fetch(`/api/facebook/sync-status/${encodeURIComponent(job.id)}`, {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
            },
            signal: controller.signal,
            // Add cache control to prevent stale responses
            cache: 'no-store',
          });
        } catch (fetchError) {
          // If fetch itself fails (network error, abort, etc.), handle it
          if (fetchError instanceof Error && fetchError.name === 'AbortError') {
            throw new Error('Request timeout - sync status API took too long to respond');
          }
          throw fetchError;
        } finally {
          clearTimeout(timeoutId);
        }
        
        const fetchTime = Date.now() - startTime;
        console.log(`[Sync Poll] Fetched status for job ${job.id} in ${fetchTime}ms`, {
          status: response.status,
          ok: response.ok,
        });
        
        if (response.ok) {
          const data = await response.json();
          
          // Debug log to see what we're getting
          console.log(`[Sync Poll] Page ${pageId}, Job ${job.id}:`, {
            status: data.status,
            synced: data.syncedContacts,
            failed: data.failedContacts,
            total: data.totalContacts,
            startedAt: data.startedAt,
            completedAt: data.completedAt,
          });
          
          if (data.status === 'COMPLETED' || data.status === 'FAILED' || data.status === 'CANCELLED') {
            console.log(`[Sync Poll] Job ${job.id} finished with status: ${data.status}`);
            // Remove from active jobs
            setActiveSyncJobs(prev => {
              const newJobs = { ...prev };
              delete newJobs[pageId];
              return newJobs;
            });

            // Refresh contact count
            await fetchContactCount(pageId);
            await fetchConnectedPages();

            // Show notification
            if (data.status === 'COMPLETED') {
              const page = pages.find(p => p.id === pageId);
              toast.success(
                `Synced ${data.syncedContacts} contact${data.syncedContacts !== 1 ? 's' : ''} from ${page?.pageName || 'page'}`,
                { duration: 5000 }
              );
              // Call onSyncComplete callback to refresh total contacts
              onSyncComplete?.();
              
              // Dispatch event to refresh contacts page if it's open
              if (typeof window !== 'undefined') {
                window.dispatchEvent(new CustomEvent('syncCompleted', {
                  detail: {
                    pageId,
                    syncedContacts: data.syncedContacts,
                    pageName: page?.pageName,
                  }
                }));
                // Also dispatch a more specific event
                window.dispatchEvent(new CustomEvent('contactsSynced', {
                  detail: {
                    pageId,
                    syncedContacts: data.syncedContacts,
                  }
                }));
              }
            } else if (data.status === 'CANCELLED') {
              toast.info('Sync was cancelled');
            } else if (data.tokenExpired) {
              const page = pages.find(p => p.id === pageId);
              toast.error(
                `Access token expired for ${page?.pageName || 'page'}. Please reconnect.`,
                { duration: 8000 }
              );
            } else {
              toast.error('Sync failed. Please try again or check your connection.');
            }
          } else {
            // Update job status - ensure we're updating with the latest data
            setActiveSyncJobs(prev => {
              const current = prev[pageId];
              // Only update if data actually changed to avoid unnecessary re-renders
              if (current && 
                  current.syncedContacts === data.syncedContacts &&
                  current.failedContacts === data.failedContacts &&
                  current.totalContacts === data.totalContacts &&
                  current.status === data.status) {
                return prev; // No change, return same object
              }
              console.log(`[Sync Poll] Updating job ${job.id} status:`, {
                old: current,
                new: data,
              });
              return { ...prev, [pageId]: data };
            });
          }
          
          // Reset failed attempts on success
          failedPollAttemptsRef.current.delete(job.id);
        } else {
          // Try to get error message from response
          let errorMessage = response.statusText || 'Unknown error';
          try {
            const errorData = await response.json();
            errorMessage = errorData.error || errorMessage;
          } catch {
            // If JSON parsing fails, use status text
          }
          
          // Use JSON.stringify to ensure proper serialization
          console.error(`[Sync Poll] Failed to fetch status for job ${job.id}:`, JSON.stringify({
            status: response.status,
            statusText: response.statusText,
            error: errorMessage,
            url: `/api/facebook/sync-status/${job.id}`,
            fetchTime: `${fetchTime}ms`,
          }, null, 2));
          
          // If it's a 404, the job might have been deleted - remove from active jobs
          if (response.status === 404) {
            console.warn(`[Sync Poll] Job ${job.id} not found (404), removing from active jobs`);
            setActiveSyncJobs(prev => {
              const newJobs = { ...prev };
              delete newJobs[pageId];
              return newJobs;
            });
          }
          
          // If it's a 400, the job ID might be invalid - remove from active jobs after a few attempts
          if (response.status === 400) {
            // Track failed attempts
            const currentAttempts = failedPollAttemptsRef.current.get(job.id) || 0;
            const newAttempts = currentAttempts + 1;
            failedPollAttemptsRef.current.set(job.id, newAttempts);
            
            console.warn(`[Sync Poll] Job ${job.id} returned 400 (attempt ${newAttempts}/3)`);
            
            if (newAttempts >= 3) {
              console.warn(`[Sync Poll] Removing job ${job.id} after ${newAttempts} failed attempts (400 errors)`);
              failedPollAttemptsRef.current.delete(job.id);
              setActiveSyncJobs(prev => {
                const newJobs = { ...prev };
                delete newJobs[pageId];
                return newJobs;
              });
            }
          }
        }
      } catch (error) {
        // Handle timeout and network errors
        if (error instanceof Error && error.name === 'TimeoutError') {
          console.error(`[Sync Poll] Timeout polling job ${job.id} (took > 30s)`);
          // Don't remove job on timeout - it might still be running, just slow to respond
          // Continue polling next time
        } else if (error instanceof Error && error.name === 'AbortError') {
          console.error(`[Sync Poll] Request aborted for job ${job.id} - API took too long (>30s)`);
          // Don't remove job on abort - it might still be running, just slow to respond
          // Continue polling next time
        } else {
          // Use JSON.stringify to ensure proper serialization
          console.error(`[Sync Poll] Error polling sync job ${job.id}:`, JSON.stringify({
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
            jobId: job.id,
            pageId: pageId,
            errorName: error instanceof Error ? error.name : 'Unknown',
            errorType: error instanceof Error ? error.constructor.name : typeof error,
          }, null, 2));
        }
      } finally {
        pollingInProgressRef.current.delete(job.id);
      }
    }
  }, [activeSyncJobs, pages, fetchConnectedPages, onSyncComplete, isPageVisible]);

  // Start sync using background API
  const handleSync = async (page: ConnectedPage) => {
    // Validate page has required fields
    if (!page.id) {
      console.error('[Sync] Page missing database ID:', page);
      toast.error('Invalid page data. Please refresh the page list.');
      return;
    }

    // Optimistic UI: Show immediate feedback
    const tempJobId = `temp-${Date.now()}`;
    setActiveSyncJobs(prev => ({
      ...prev,
      [page.id]: {
        id: tempJobId,
        status: 'PENDING',
        syncedContacts: 0,
        failedContacts: 0,
        totalContacts: 0,
        tokenExpired: false,
        startedAt: null,
        completedAt: null,
      },
    }));

    toast.info(`Starting instant sync for ${page.pageName}...`, {
      description: 'Syncing contacts in the background',
      duration: 2000,
    });

    try {
      console.log('[Sync] Starting sync for page:', {
        databaseId: page.id,
        pageId: page.pageId,
        pageName: page.pageName,
      });

      const response = await fetch('/api/facebook/sync-instant', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          facebookPageId: page.id, // Database ID
        }),
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        const text = await response.text();
        console.error('[Sync] Non-JSON response:', text.substring(0, 200));
        throw new Error('Server returned non-JSON response');
      }

      if (!response.ok) {
        let errorData: any = {};
        try {
          errorData = await response.json();
        } catch (parseError) {
          const text = await response.text().catch(() => '');
          errorData = { 
            error: `HTTP ${response.status}: ${response.statusText}`,
            rawResponse: text.substring(0, 200)
          };
        }
        
        const errorMessage = errorData?.error || `Failed to start sync (${response.status})`;
        
        // Log error details properly (avoid empty object serialization)
        const errorDetails = {
          status: response.status,
          statusText: response.statusText,
          error: errorMessage,
          pageId: page.id,
          pageName: page.pageName,
          ...(errorData && typeof errorData === 'object' ? { errorData: JSON.stringify(errorData) } : { errorData: String(errorData) }),
        };
        
        console.error('[Sync] API error:', JSON.stringify(errorDetails, null, 2));
        
        // If 404, the page might not exist - refresh the list
        if (response.status === 404) {
          console.log('[Sync] Page not found (404), refreshing page list');
          await fetchConnectedPages();
          onRefresh?.();
          throw new Error('Page not found. The page may have been deleted or belongs to a different organization. The page list has been refreshed.');
        }
        
        throw new Error(errorMessage);
      }

      const data = await response.json();
      
      console.log('[Sync] Instant sync started:', {
        pageId: page.id,
        pageName: page.pageName,
        jobId: data.jobId,
        response: data,
      });
      
      // Update with real job ID
      setActiveSyncJobs(prev => {
        const updated: ActiveSyncJobs = {
          ...prev,
          [page.id]: {
            id: data.jobId,
            status: 'PENDING' as const,
            syncedContacts: 0,
            failedContacts: 0,
            totalContacts: 0,
            tokenExpired: false,
            startedAt: null,
            completedAt: null,
          },
        };
        console.log('[Sync] Updated activeSyncJobs:', {
          pageId: page.id,
          jobId: data.jobId,
          totalActiveJobs: Object.keys(updated).length,
        });
        return updated;
      });

      toast.success(`Instant sync started for ${page.pageName}`, {
        description: 'Syncing contacts in the background',
        duration: 3000,
      });
    } catch (error) {
      // Remove optimistic update on error
      setActiveSyncJobs(prev => {
        const updated = { ...prev };
        delete updated[page.id];
        return updated;
      });

      // Properly extract error message
      let errorMessage: string;
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === 'string') {
        errorMessage = error;
      } else {
        errorMessage = formatSyncError(error);
      }
      
      // Log error details properly (avoid empty object serialization)
      const errorDetails = {
        errorMessage,
        errorType: error instanceof Error ? error.constructor.name : typeof error,
        errorString: String(error),
        pageId: page.id,
        pageName: page.pageName,
      };
      
      console.error('[Sync] Error starting sync:', JSON.stringify(errorDetails, null, 2));
      
      // If page not found, suggest refreshing
      if (errorMessage.includes('not found') || errorMessage.includes('Facebook page not found')) {
        toast.error('Page not found. Please refresh the page list.', {
          action: {
            label: 'Refresh',
            onClick: () => fetchConnectedPages(),
          },
        });
      } else {
        toast.error(errorMessage || 'Failed to start sync. Please try again.');
      }
    }
  };

  // Start pipeline analysis or show AI generator
  const handleAnalyzePipeline = async (page: ConnectedPage) => {
    // If page has no pipeline, show AI generation dialog
    if (!page.autoPipelineId) {
      setPageForAIGeneration(page);
      setShowAIGenerator(true);
      setAiSuggestion(null);
      setAiStageCount('');
      setUseCustomStageCount(false);
      setAiDecideStages(true);
      setPipelineDetailLevel(5);
      return;
    }

    // If page has pipeline, do normal analysis
    toast.info(`Starting pipeline analysis for ${page.pageName}...`, {
      description: 'Re-analyzing all contacts',
      duration: 2000,
    });

    try {
      const response = await fetch('/api/facebook/analyze-pipeline', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          facebookPageId: page.id,
          forceUpdateExisting: true, // Force re-analysis of all contacts
        }),
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        // Try to get the response text for debugging
        const text = await response.text();
        console.error('Non-JSON response received:', text.substring(0, 500));
        throw new Error(`Server returned non-JSON response (${response.status} ${response.statusText}). This usually indicates a build error. Please restart the dev server.`);
      }

      if (!response.ok) {
        const data = await response.json().catch(() => ({ error: `HTTP ${response.status}: ${response.statusText}` }));
        throw new Error(data.error || 'Failed to start pipeline analysis');
      }

      const data = await response.json();
      
      // Add to active jobs for tracking
      setActiveSyncJobs(prev => ({
        ...prev,
        [page.id]: {
          id: data.jobId,
          status: 'PENDING',
          syncedContacts: 0,
          failedContacts: 0,
          totalContacts: 0,
          tokenExpired: false,
          startedAt: null,
          completedAt: null,
        },
      }));

      toast.success(`Pipeline analysis started for ${page.pageName}`, {
        description: 'Analyzing contacts in the background',
        duration: 3000,
      });
      } catch (error) {
        const errorMessage = formatUserFriendlyError(error);
        console.error('Error starting pipeline analysis:', error);
        toast.error(errorMessage);
    }
  };

  // Generate AI pipeline
  const handleGenerateAI = async () => {
    if (!pageForAIGeneration) return;

    setAiGenerating(true);
    try {
      const response = await fetch('/api/pipelines/generate-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          facebookPageId: pageForAIGeneration.id,
          stageCount: (!aiDecideStages && useCustomStageCount) ? parseInt(aiStageCount) || undefined : undefined,
          detailLevel: aiDecideStages ? pipelineDetailLevel : undefined,
        }),
      });

      if (response.ok) {
        const suggestion = await response.json();
        setAiSuggestion(suggestion);
        toast.success('AI pipeline generated successfully');
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to generate AI pipeline');
      }
    } catch (error) {
      console.error('Generate AI pipeline error:', error);
      toast.error('An error occurred while generating pipeline');
    } finally {
      setAiGenerating(false);
    }
  };

  // Create AI pipeline and assign to page
  const handleCreateAIPipeline = async () => {
    if (!aiSuggestion || !pageForAIGeneration) return;

    setAiGenerating(true);
    try {
      // Create the pipeline
      const createResponse = await fetch('/api/pipelines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: aiSuggestion.name,
          description: aiSuggestion.description,
          color: '#3b82f6',
          stages: aiSuggestion.stages.map((stage) => ({
            name: stage.name,
            description: stage.description,
            color: stage.color,
            type: stage.type,
          })),
        }),
      });

      if (!createResponse.ok) {
        throw new Error('Failed to create pipeline');
      }

      const pipelineData = await createResponse.json();

      // Assign pipeline to the Facebook page
      const assignResponse = await fetch(`/api/facebook/pages/${pageForAIGeneration.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          autoPipelineId: pipelineData.id,
        }),
      });

      if (!assignResponse.ok) {
        throw new Error('Failed to assign pipeline to page');
      }

      toast.success('AI pipeline created and assigned successfully');
      setShowAIGenerator(false);
      setAiSuggestion(null);
      setPageForAIGeneration(null);
      
      // Refresh pages list
      if (onRefresh) {
        onRefresh();
      } else {
        fetchConnectedPages();
      }
    } catch (error) {
      console.error('Create AI pipeline error:', error);
      toast.error('An error occurred while creating pipeline');
    } finally {
      setAiGenerating(false);
    }
  };

  // Cancel sync
  const handleCancelSync = async (page: ConnectedPage) => {
    const syncJob = activeSyncJobs[page.id];
    if (!syncJob) return;

    try {
      const response = await fetch('/api/facebook/sync-cancel', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          jobId: syncJob.id,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to cancel sync');
      }

      toast.success(`Sync cancelled for ${page.pageName}`);

      // Update local state
      setActiveSyncJobs(prev => {
        const updated = { ...prev };
        delete updated[page.id];
        return updated;
      });

      // Refresh page data
      await fetchConnectedPages();
      } catch (error) {
        const errorMessage = formatUserFriendlyError(error);
        console.error('Error cancelling sync:', error);
        toast.error(errorMessage);
    }
  };

  // Toggle auto-sync
  const handleToggleAutoSync = async (page: ConnectedPage, enabled: boolean) => {
    try {
      const response = await fetch(`/api/facebook/pages/${page.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          autoSync: enabled,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to update auto-sync setting');
      }

      // Update local state
      setPages(prev =>
        prev.map(p =>
          p.id === page.id ? { ...p, autoSync: enabled } : p
        )
      );

      toast.success(
        enabled
          ? `Auto-sync enabled for ${page.pageName}. Will sync daily at 12 AM.`
          : `Auto-sync disabled for ${page.pageName}`
      );
    } catch (error) {
      const errorMessage = formatUserFriendlyError(error);
      console.error('Error toggling auto-sync:', error);
      toast.error(errorMessage);
    }
  };

  // Handle disconnect
  const handleDisconnect = async (page: ConnectedPage) => {
    // Validate page has required fields
    if (!page.id) {
      console.error('[Disconnect] Page missing database ID:', page);
      toast.error('Invalid page data. Please refresh the page list.');
      return;
    }

    setDisconnectingPageId(page.id);
    try {
      console.log('[Disconnect] Disconnecting page:', {
        databaseId: page.id,
        pageId: page.pageId,
        pageName: page.pageName,
      });

      const response = await fetch(`/api/facebook/pages?pageId=${encodeURIComponent(page.id)}`, {
        method: 'DELETE',
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        const text = await response.text();
        console.error('[Disconnect] Non-JSON response:', text.substring(0, 200));
        throw new Error('Server returned non-JSON response');
      }

      if (!response.ok) {
        let errorData: any = {};
        try {
          errorData = await response.json();
        } catch (parseError) {
          const text = await response.text().catch(() => '');
          errorData = { 
            error: `HTTP ${response.status}: ${response.statusText}`,
            rawResponse: text.substring(0, 200)
          };
        }
        
        const errorMessage = errorData?.error || `Failed to disconnect page (${response.status})`;
        
        // Log error details properly (avoid empty object serialization)
        const errorDetails = {
          status: response.status,
          statusText: response.statusText,
          error: errorMessage,
          pageId: page.id,
          pageName: page.pageName,
          ...(errorData && typeof errorData === 'object' ? { errorData: JSON.stringify(errorData) } : { errorData: String(errorData) }),
        };
        
        console.error('[Disconnect] API error:', JSON.stringify(errorDetails, null, 2));
        
        // If 404, the page might already be deleted or belong to different org - refresh the list
        if (response.status === 404) {
          console.log('[Disconnect] Page not found (404), refreshing page list');
          await fetchConnectedPages();
          onRefresh?.();
          throw new Error('Page not found. The page may have already been deleted or belongs to a different organization. The page list has been refreshed.');
        }
        
        throw new Error(errorMessage);
      }

      toast.success(`Disconnected ${page.pageName}`);
      await fetchConnectedPages();
      onRefresh?.();
      } catch (error) {
        // Properly extract error message
        let errorMessage: string;
        if (error instanceof Error) {
          errorMessage = error.message;
        } else if (typeof error === 'string') {
          errorMessage = error;
        } else {
          errorMessage = formatUserFriendlyError(error);
        }
        
        // Log error details properly (avoid empty object serialization)
        const errorDetails = {
          errorMessage,
          errorType: error instanceof Error ? error.constructor.name : typeof error,
          errorString: String(error),
          pageId: page.id,
          pageName: page.pageName,
        };
        
        console.error('[Disconnect] Error disconnecting page:', JSON.stringify(errorDetails, null, 2));
        
        // If page not found, suggest refreshing
        if (errorMessage.includes('not found') || errorMessage.includes('access denied')) {
          toast.error('Page not found or access denied. Please refresh the page list.', {
            action: {
              label: 'Refresh',
              onClick: () => fetchConnectedPages(),
            },
          });
        } else {
          toast.error(errorMessage || 'Failed to disconnect page. Please try again.');
        }
    } finally {
      setDisconnectingPageId(null);
      setPageToDisconnect(null);
    }
  };
  
  // Bulk operations
  const togglePageSelection = (pageId: string) => {
    const newSelected = new Set(selectedPageIds);
    if (newSelected.has(pageId)) {
      newSelected.delete(pageId);
    } else {
      newSelected.add(pageId);
    }
    setSelectedPageIds(newSelected);
  };
  
  const toggleSelectAll = () => {
    if (selectedPageIds.size === filteredPages.length) {
      setSelectedPageIds(new Set());
    } else {
      setSelectedPageIds(new Set(filteredPages.map(p => p.id)));
    }
  };
  
  const handleBulkSync = async () => {
    if (selectedPageIds.size === 0) return;
    
    setIsBulkSyncing(true);
    const selectedPages = pages.filter(p => selectedPageIds.has(p.id));
    let successCount = 0;
    let failCount = 0;
    
    for (const page of selectedPages) {
      try {
        await handleSync(page);
        successCount++;
      } catch {
        failCount++;
      }
    }
    
    setIsBulkSyncing(false);
    setSelectedPageIds(new Set());
    
    if (successCount > 0) {
      toast.success(`Started syncing ${successCount} page${successCount !== 1 ? 's' : ''}`);
    }
    if (failCount > 0) {
      toast.error(`Failed to sync ${failCount} page${failCount !== 1 ? 's' : ''}`);
    }
  };
  
  const handleBulkDisconnect = async () => {
    if (selectedPageIds.size === 0) return;
    
    setIsBulkDisconnecting(true);
    const selectedPages = pages.filter(p => selectedPageIds.has(p.id));
    let successCount = 0;
    let failCount = 0;
    
    for (const page of selectedPages) {
      try {
        if (!page.id) {
          console.error('[Bulk Disconnect] Page missing database ID:', page);
          failCount++;
          continue;
        }

        console.log('[Bulk Disconnect] Disconnecting page:', {
          databaseId: page.id,
          pageId: page.pageId,
          pageName: page.pageName,
        });

        const response = await fetch(`/api/facebook/pages?pageId=${encodeURIComponent(page.id)}`, {
          method: 'DELETE',
        });
        
        if (response.ok) {
          successCount++;
        } else {
          const data = await response.json().catch(() => ({ error: 'Unknown error' }));
          console.error('[Bulk Disconnect] API error:', {
            status: response.status,
            error: data.error,
            pageId: page.id,
          });
          failCount++;
        }
      } catch (error) {
        console.error('[Bulk Disconnect] Error:', error);
        failCount++;
      }
    }
    
    setIsBulkDisconnecting(false);
    setSelectedPageIds(new Set());
    setShowBulkDisconnectDialog(false);
    
    await fetchConnectedPages();
    onRefresh?.();
    
    if (successCount > 0) {
      toast.success(`Disconnected ${successCount} page${successCount !== 1 ? 's' : ''}`);
    }
    if (failCount > 0) {
      toast.error(`Failed to disconnect ${failCount} page${failCount !== 1 ? 's' : ''}`);
    }
  };
  
  // Filter and paginate pages
  const filteredPages = searchQuery
    ? pages.filter(p => 
        p.pageName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.pageId.includes(searchQuery)
      )
    : pages;
  
  const totalPages = Math.ceil(filteredPages.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedPages = filteredPages.slice(startIndex, endIndex);
  
  // Reset to page 1 when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  // Setup polling for active sync jobs (only when page is visible)
  useEffect(() => {
    const activeJobCount = Object.keys(activeSyncJobs).length;
    
    if (activeJobCount > 0 && isPageVisible) {
      // Poll immediately, then set up interval
      console.log('[Sync Poll] Setting up polling:', {
        activeJobCount,
        isPageVisible,
        jobIds: Object.keys(activeSyncJobs).map(id => activeSyncJobs[id]?.id),
      });
      
      // Poll immediately
      pollSyncJobs().catch(error => {
        console.error('[Sync Poll] Error in initial poll:', error);
      });
      
      // Set up interval - poll every 2 seconds
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      pollingIntervalRef.current = setInterval(() => {
        console.log('[Sync Poll] Interval tick - polling jobs');
        pollSyncJobs().catch(error => {
          console.error('[Sync Poll] Error in interval poll:', error);
        });
      }, 2000);
      
      console.log('[Sync Poll] Started polling for', activeJobCount, 'active sync job(s)');
    } else {
      if (pollingIntervalRef.current) {
        console.log('[Sync Poll] Stopping polling:', {
          activeJobCount,
          isPageVisible,
          reason: activeJobCount === 0 ? 'no active jobs' : 'page not visible',
        });
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    }

    return () => {
      if (pollingIntervalRef.current) {
        console.log('[Sync Poll] Cleanup: clearing interval');
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    };
  }, [activeSyncJobs, pollSyncJobs, isPageVisible]);

  // Page Visibility API - pause/resume polling when tab is inactive/active
  useEffect(() => {
    const handleVisibilityChange = () => {
      const isVisible = !document.hidden;
      setIsPageVisible(isVisible);
      
      // When page becomes visible again, immediately check sync status
      if (isVisible && Object.keys(activeSyncJobs).length > 0) {
        console.log('Page became visible, checking sync status...');
        pollSyncJobs();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [activeSyncJobs, pollSyncJobs]);

  // Initial fetch
  useEffect(() => {
    fetchConnectedPages();
  }, [fetchConnectedPages]);

  // Auto-refresh pages every 30 seconds to show pages added by other users in the same organization
  useEffect(() => {
    const interval = setInterval(() => {
      fetchConnectedPages();
    }, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, [fetchConnectedPages]);

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Connected Pages</CardTitle>
          <CardDescription>Manage your connected Facebook pages</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner className="h-8 w-8" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (pages.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Connected Pages</CardTitle>
          <CardDescription>Manage your connected Facebook pages</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <Facebook className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No Facebook pages connected yet</p>
            <p className="text-sm mt-2">Click &quot;Connect with Facebook&quot; above to get started</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Connected Pages ({filteredPages.length})</CardTitle>
          <CardDescription>
            Manage your connected Facebook pages and sync contacts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Search and Bulk Actions */}
            <div className="space-y-3">
              <Input
                type="text"
                placeholder="Search pages by name or ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full"
              />
              
              {filteredPages.length > 0 && (
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <Checkbox
                      id="select-all"
                      checked={selectedPageIds.size === filteredPages.length && filteredPages.length > 0}
                      onCheckedChange={toggleSelectAll}
                    />
                    <label
                      htmlFor="select-all"
                      className="text-sm font-medium cursor-pointer"
                    >
                      Select All ({selectedPageIds.size} selected)
                    </label>
                  </div>
                  
                  {selectedPageIds.size > 0 && (
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleBulkSync}
                        disabled={isBulkSyncing || isBulkDisconnecting}
                      >
                        {isBulkSyncing ? (
                          <>
                            <LoadingSpinner className="mr-2 h-4 w-4" />
                            Syncing...
                          </>
                        ) : (
                          <>
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Sync Selected ({selectedPageIds.size})
                          </>
                        )}
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setShowBulkDisconnectDialog(true)}
                        disabled={isBulkSyncing || isBulkDisconnecting}
                      >
                        {isBulkDisconnecting ? (
                          <>
                            <LoadingSpinner className="mr-2 h-4 w-4" />
                            Disconnecting...
                          </>
                        ) : (
                          <>
                            <Unplug className="mr-2 h-4 w-4" />
                            Disconnect Selected ({selectedPageIds.size})
                          </>
                        )}
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
            
            {/* Pages List */}
            {paginatedPages.map((page) => {
              const syncJob = activeSyncJobs[page.id];
              const isSyncing = !!syncJob && (syncJob.status === 'PENDING' || syncJob.status === 'IN_PROGRESS');
              const contactCount = contactCounts[page.id] ?? 0;
              const syncProgress = syncJob?.totalContacts > 0 
                ? (syncJob.syncedContacts / syncJob.totalContacts) * 100 
                : 0;

              return (
                <div
                  key={page.id}
                  className={`flex flex-col gap-3 rounded-lg border p-4 transition-all ${
                    selectedPageIds.has(page.id)
                      ? 'bg-primary/5 border-primary'
                      : 'hover:bg-muted/50'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <Checkbox
                        id={`page-${page.id}`}
                        checked={selectedPageIds.has(page.id)}
                        onCheckedChange={() => togglePageSelection(page.id)}
                        className="mt-1"
                      />
                      <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Facebook className="h-5 w-5 text-blue-600" />
                        <h4 className="font-semibold">{page.pageName}</h4>
                        {page.isActive ? (
                          <Badge variant="default" className="bg-green-600">
                            <CheckCircle2 className="mr-1 h-3 w-3" />
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="secondary">Inactive</Badge>
                        )}
                        <Badge variant="outline" className="gap-1">
                          <Users className="h-3 w-3" />
                          {contactCount} {contactCount === 1 ? 'contact' : 'contacts'}
                        </Badge>
                      </div>

                      <div className="space-y-1 text-sm text-muted-foreground">
                        <p>Page ID: {page.pageId}</p>
                        {page.instagramAccountId && (
                          <div className="flex items-center gap-1">
                            <Instagram className="h-4 w-4 text-pink-600" />
                            <span>
                              Instagram: @{page.instagramUsername || 'Connected'}
                            </span>
                          </div>
                        )}
                        {page.lastSyncedAt && (
                          <p>
                            Last synced:{' '}
                            {formatDistanceToNow(new Date(page.lastSyncedAt), {
                              addSuffix: true,
                            })}
                          </p>
                        )}
                        <div className="flex items-center gap-2 pt-1">
                          <Switch
                            id={`auto-sync-${page.id}`}
                            checked={page.autoSync}
                            onCheckedChange={(checked) => handleToggleAutoSync(page, checked)}
                            disabled={disconnectingPageId === page.id}
                          />
                          <label
                            htmlFor={`auto-sync-${page.id}`}
                            className="text-sm font-medium cursor-pointer"
                          >
                            Auto-sync daily at 12 AM
                          </label>
                        </div>
                      </div>
                    </div>
                    </div>

                    <div className="flex gap-2">
                      <Link href={`/facebook-pages/${page.id}/settings`}>
                        <Button
                          variant="outline"
                          size="sm"
                        >
                          <Settings className="mr-2 h-4 w-4" />
                          Settings
                        </Button>
                      </Link>
                      {isSyncing ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleCancelSync(page)}
                          className="text-destructive hover:text-destructive"
                        >
                          <XCircle className="mr-2 h-4 w-4" />
                          Stop Sync
                        </Button>
                      ) : (
                        <>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleSync(page)}
                            disabled={disconnectingPageId === page.id}
                          >
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Sync
                          </Button>
                          {page.autoPipelineId && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleAnalyzePipeline(page)}
                              disabled={disconnectingPageId === page.id}
                              className="bg-purple-50 hover:bg-purple-100 dark:bg-purple-950/20 dark:hover:bg-purple-950/40"
                            >
                              <Sparkles className="mr-2 h-4 w-4" />
                              Analyze
                            </Button>
                          )}
                        </>
                      )}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setPageToDisconnect(page)}
                        disabled={disconnectingPageId === page.id || isSyncing}
                      >
                        {disconnectingPageId === page.id ? (
                          <>
                            <LoadingSpinner className="mr-2 h-4 w-4" />
                            Disconnecting...
                          </>
                        ) : (
                          <>
                            <Unplug className="mr-2 h-4 w-4" />
                            Disconnect
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                  {isSyncing && syncJob && (
                    <div className="space-y-3 p-4 bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-950/20 dark:to-indigo-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <RefreshCw className="h-4 w-4 text-blue-600 animate-spin" />
                          <span className="text-blue-700 dark:text-blue-300 font-semibold text-sm">
                            {syncJob.status === 'PENDING' ? 'Starting sync...' : 'Sync in Progress'}
                          </span>
                        </div>
                        {syncJob.startedAt && (
                          <span className="text-xs text-blue-600 dark:text-blue-400">
                            {formatElapsedTime(syncJob.startedAt)}
                          </span>
                        )}
                      </div>
                      
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Processed Contacts</span>
                          <span className="font-bold text-blue-600 dark:text-blue-400 text-base">
                            {syncJob.syncedContacts > 0 
                              ? syncJob.syncedContacts.toLocaleString()
                              : '0'}
                          </span>
                        </div>
                        {syncJob.totalContacts > 0 ? (
                          <>
                            <Progress value={syncProgress} className="h-2 bg-blue-100 dark:bg-blue-900" />
                            <div className="flex items-center justify-between text-xs text-muted-foreground">
                              <span>{Math.round(syncProgress)}% complete</span>
                              {syncJob.failedContacts > 0 && (
                                <span className="text-destructive">
                                  {syncJob.failedContacts} failed
                                </span>
                              )}
                            </div>
                          </>
                        ) : (
                          <div className="text-xs text-muted-foreground">
                            Initializing sync and counting contacts...
                          </div>
                        )}
                      </div>

                      <div className="flex items-start gap-2 text-xs text-blue-600 dark:text-blue-400">
                        <CheckCircle2 className="h-3 w-3 mt-0.5 shrink-0" />
                        <p>
                          Syncing in background - safe to navigate away, refresh, or close this page. 
                          Progress will be saved automatically.
                        </p>
                      </div>
                      {!isPageVisible && (
                        <p className="text-xs text-amber-600 dark:text-amber-400 flex items-center gap-1">
                          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-500"></span>
                          Tab inactive - polling paused (sync continues on server)
                        </p>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            
            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between border-t pt-4 mt-4">
                <p className="text-sm text-muted-foreground">
                  Page {currentPage} of {totalPages} • Showing {startIndex + 1}-{Math.min(endIndex, filteredPages.length)} of {filteredPages.length}
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                  >
                    Next
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Single Page Disconnect Dialog */}
      <AlertDialog
        open={!!pageToDisconnect}
        onOpenChange={(open) => !open && setPageToDisconnect(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Disconnect Facebook Page?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to disconnect <strong>{pageToDisconnect?.pageName}</strong>? This will remove all associated contacts and campaigns.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => pageToDisconnect && handleDisconnect(pageToDisconnect)}
              className="bg-destructive hover:bg-destructive/90"
            >
              Disconnect
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* Bulk Disconnect Dialog */}
      <AlertDialog
        open={showBulkDisconnectDialog}
        onOpenChange={setShowBulkDisconnectDialog}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Disconnect Multiple Pages?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to disconnect <strong>{selectedPageIds.size} page{selectedPageIds.size !== 1 ? 's' : ''}</strong>? 
              This will remove all associated contacts and campaigns from these pages.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isBulkDisconnecting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleBulkDisconnect}
              disabled={isBulkDisconnecting}
              className="bg-destructive hover:bg-destructive/90"
            >
              {isBulkDisconnecting ? (
                <>
                  <LoadingSpinner className="mr-2 h-4 w-4" />
                  Disconnecting...
                </>
              ) : (
                `Disconnect ${selectedPageIds.size} Page${selectedPageIds.size !== 1 ? 's' : ''}`
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* AI Pipeline Generator Dialog */}
      <Dialog open={showAIGenerator} onOpenChange={setShowAIGenerator}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5" />
              AI Pipeline Generator
            </DialogTitle>
            <DialogDescription>
              {pageForAIGeneration && (
                <>AI will analyze contacts from <strong>{pageForAIGeneration.pageName}</strong> to create an optimal pipeline structure</>
              )}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="ai-decide-stages">Let AI Decide Number of Stages</Label>
              <Switch
                id="ai-decide-stages"
                checked={aiDecideStages}
                onCheckedChange={(checked) => {
                  setAiDecideStages(checked);
                  if (checked) {
                    setUseCustomStageCount(false);
                  }
                }}
              />
            </div>

            {!aiDecideStages && (
              <div className="flex items-center justify-between">
                <Label htmlFor="custom-stage-count">Custom Stage Count</Label>
                <Switch
                  id="custom-stage-count"
                  checked={useCustomStageCount}
                  onCheckedChange={setUseCustomStageCount}
                />
              </div>
            )}

            {!aiDecideStages && useCustomStageCount && (
              <div>
                <Label htmlFor="stage-count">Number of Stages (minimum 3)</Label>
                <Input
                  id="stage-count"
                  type="text"
                  inputMode="numeric"
                  value={aiStageCount}
                  onChange={(e) => {
                    const value = e.target.value;
                    // Allow typing any number, including starting with 1
                    if (value === '' || /^\d+$/.test(value)) {
                      setAiStageCount(value);
                    }
                  }}
                  onBlur={(e) => {
                    // Validate on blur - ensure minimum 3
                    const numValue = parseInt(e.target.value);
                    if (isNaN(numValue) || numValue < 3) {
                      setAiStageCount('');
                    } else {
                      setAiStageCount(numValue.toString());
                    }
                  }}
                  className="mt-2"
                  placeholder="e.g., 3, 5, 7, 12..."
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Specify the exact number of stages you want (minimum 3)
                </p>
              </div>
            )}

            {aiDecideStages && (
              <div className="space-y-2">
                <Label htmlFor="detail-level">Pipeline Detail Level (1 = Simple, 10 = Very Detailed)</Label>
                <div className="flex items-center gap-4">
                  <span className="text-xs text-muted-foreground min-w-[60px]">Simple</span>
                  <input
                    id="detail-level"
                    type="range"
                    min="1"
                    max="10"
                    value={pipelineDetailLevel}
                    onChange={(e) => setPipelineDetailLevel(parseInt(e.target.value))}
                    className="flex-1 h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer accent-primary"
                  />
                  <span className="text-xs text-muted-foreground min-w-[80px]">Very Detailed</span>
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Current: {pipelineDetailLevel}/10</span>
                  <span>
                    {pipelineDetailLevel <= 3 && 'Simple (3-5 stages)'}
                    {pipelineDetailLevel > 3 && pipelineDetailLevel <= 6 && 'Moderate (5-8 stages)'}
                    {pipelineDetailLevel > 6 && pipelineDetailLevel <= 8 && 'Detailed (8-12 stages)'}
                    {pipelineDetailLevel > 8 && 'Very Detailed (12-15+ stages)'}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  AI will create {pipelineDetailLevel <= 3 ? '3-5' : pipelineDetailLevel <= 6 ? '5-8' : pipelineDetailLevel <= 8 ? '8-12' : '12-15+'} stages based on your contact data
                </p>
              </div>
            )}

            {!aiDecideStages && !useCustomStageCount && (
              <p className="text-sm text-muted-foreground">
                Enable &quot;Custom Stage Count&quot; to specify an exact number, or enable &quot;Let AI Decide&quot; for automatic optimization
              </p>
            )}

            {aiSuggestion && (
              <div className="space-y-4 pt-4 border-t">
                <div>
                  <h3 className="font-semibold mb-2">{aiSuggestion.name}</h3>
                  <p className="text-sm text-muted-foreground mb-4">{aiSuggestion.description}</p>
                  {aiSuggestion.confidence && aiSuggestion.confidence > 0 && (
                    <p className="text-xs text-muted-foreground">
                      Confidence: {aiSuggestion.confidence}% • Based on {aiSuggestion.totalContacts || 0} contacts
                    </p>
                  )}
                </div>

                {aiSuggestion.stages && aiSuggestion.stages.length > 0 ? (
                  <div className="space-y-2">
                    <h4 className="font-medium text-sm">Suggested Stages:</h4>
                    {aiSuggestion.stages.map((stage, index: number) => (
                    <Card key={index} className="p-3">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <div
                              className="w-3 h-3 rounded-full"
                              style={{ backgroundColor: stage.color }}
                            />
                            <span className="font-medium">{stage.name}</span>
                            <span className="text-xs text-muted-foreground">
                              ({stage.leadScoreMin}-{stage.leadScoreMax})
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">{stage.description}</p>
                          {stage.expectedContacts && stage.expectedContacts > 0 && (
                            <p className="text-xs text-muted-foreground">
                              Expected: ~{stage.expectedContacts} contacts
                            </p>
                          )}
                        </div>
                      </div>
                    </Card>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                    <p className="text-sm text-amber-900 dark:text-amber-200">
                      ⚠️ {aiSuggestion.description || 'No stages can be generated. Contacts need to be analyzed first.'}
                    </p>
                    <p className="text-xs text-amber-700 dark:text-amber-300 mt-2">
                      Please run pipeline analysis on your contacts first, then try generating the pipeline again.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowAIGenerator(false);
                setAiSuggestion(null);
                setPageForAIGeneration(null);
                setAiStageCount('');
                setAiDecideStages(true);
                setPipelineDetailLevel(5);
                setUseCustomStageCount(false);
              }}
            >
              Cancel
            </Button>
            {!aiSuggestion ? (
              <Button onClick={handleGenerateAI} disabled={aiGenerating}>
                {aiGenerating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4 mr-2" />
                    Generate Pipeline
                  </>
                )}
              </Button>
            ) : (
              <Button onClick={handleCreateAIPipeline} disabled={aiGenerating}>
                {aiGenerating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Creating...
                  </>
                ) : (
                  'Create & Assign Pipeline'
                )}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
