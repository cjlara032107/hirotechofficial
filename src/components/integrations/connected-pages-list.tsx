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
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Facebook, Instagram, RefreshCw, Unplug, CheckCircle2, Users, ChevronLeft, ChevronRight, Settings, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import { formatDistanceToNow } from 'date-fns';
import Link from 'next/link';

interface ConnectedPage {
  id: string;
  pageId: string;
  pageName: string;
  instagramAccountId: string | null;
  instagramUsername: string | null;
  isActive: boolean;
  lastSyncedAt: string | null;
  autoSync: boolean;
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
  
  // Bulk operations state
  const [selectedPageIds, setSelectedPageIds] = useState<Set<string>>(new Set());
  const [isBulkSyncing, setIsBulkSyncing] = useState(false);
  const [isBulkDisconnecting, setIsBulkDisconnecting] = useState(false);
  const [showBulkDisconnectDialog, setShowBulkDisconnectDialog] = useState(false);
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const itemsPerPage = 5;

  // Fetch connected pages
  const fetchConnectedPages = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/facebook/pages/connected');

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to fetch connected pages');
      }

      const data = await response.json();
      const fetchedPages = data.pages || [];
      setPages(fetchedPages);

      // Fetch contact counts and latest sync jobs for all pages
      await Promise.all([
        ...fetchedPages.map((page: ConnectedPage) => fetchContactCount(page.id)),
        ...fetchedPages.map((page: ConnectedPage) => checkLatestSyncJob(page.id)),
      ]);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to load connected pages';
      console.error('Error fetching connected pages:', error);
      toast.error(errorMessage);
    } finally {
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
    if (activeJobs.length === 0) return;

    for (const [pageId, job] of activeJobs) {
      try {
        const response = await fetch(`/api/facebook/sync-status/${job.id}`);
        if (response.ok) {
          const data = await response.json();
          
          if (data.status === 'COMPLETED' || data.status === 'FAILED') {
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
            } else if (data.tokenExpired) {
              const page = pages.find(p => p.id === pageId);
              toast.error(
                `Access token expired for ${page?.pageName || 'page'}. Please reconnect.`,
                { duration: 8000 }
              );
            } else {
              toast.error('Sync failed. Please try again.');
            }
          } else {
            // Update job status
            setActiveSyncJobs(prev => ({ ...prev, [pageId]: data }));
          }
        }
      } catch (error) {
        console.error(`Error polling sync job ${job.id}:`, error);
      }
    }
  }, [activeSyncJobs, pages, fetchConnectedPages, onSyncComplete]);

  // Start sync using background API
  const handleSync = async (page: ConnectedPage) => {
    try {
      const response = await fetch('/api/facebook/sync-background', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          facebookPageId: page.id,
        }),
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to start sync');
      }

      const data = await response.json();
      
      toast.info(`Started syncing contacts for ${page.pageName}`, {
        description: 'Sync will continue in the background',
        duration: 3000,
      });

      // Add to active jobs
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
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to start sync';
      console.error('Error starting sync:', error);
      toast.error(errorMessage);
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
      const errorMessage = error instanceof Error ? error.message : 'Failed to cancel sync';
      console.error('Error cancelling sync:', error);
      toast.error(errorMessage);
    }
  };

  // Handle disconnect
  const handleDisconnect = async (page: ConnectedPage) => {
    setDisconnectingPageId(page.id);
    try {
      const response = await fetch(`/api/facebook/pages?pageId=${page.id}`, {
        method: 'DELETE',
      });

      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to disconnect page');
      }

      toast.success(`Disconnected ${page.pageName}`);
      await fetchConnectedPages();
      onRefresh?.();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to disconnect page';
      console.error('Error disconnecting page:', error);
      toast.error(errorMessage);
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
      } catch (error) {
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
        const response = await fetch(`/api/facebook/pages?pageId=${page.id}`, {
          method: 'DELETE',
        });
        
        if (response.ok) {
          successCount++;
        } else {
          failCount++;
        }
      } catch (error) {
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
    if (Object.keys(activeSyncJobs).length > 0 && isPageVisible) {
      pollingIntervalRef.current = setInterval(pollSyncJobs, 2000); // Poll every 2 seconds
    } else if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }

    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
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
            <p className="text-sm mt-2">Click "Connect with Facebook" above to get started</p>
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
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleSync(page)}
                          disabled={disconnectingPageId === page.id}
                        >
                          <RefreshCw className="mr-2 h-4 w-4" />
                          Sync
                        </Button>
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
                    <div className="space-y-2 p-3 bg-blue-50 dark:bg-blue-950/20 rounded-lg border border-blue-200 dark:border-blue-800">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-blue-700 dark:text-blue-300 font-medium flex items-center gap-2">
                          <span className="relative flex h-2 w-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
                          </span>
                          {syncJob.status === 'PENDING' ? 'Starting sync...' : 'Syncing contacts...'}
                        </span>
                        {syncJob.totalContacts > 0 && (
                          <span className="font-medium text-blue-700 dark:text-blue-300">
                            {syncJob.syncedContacts} / {syncJob.totalContacts}
                          </span>
                        )}
                      </div>
                      {syncJob.totalContacts > 0 && (
                        <Progress value={syncProgress} className="h-2 bg-blue-100 dark:bg-blue-900" />
                      )}
                      <div className="flex items-start gap-2 text-xs text-blue-600 dark:text-blue-400">
                        <CheckCircle2 className="h-3 w-3 mt-0.5 flex-shrink-0" />
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
    </>
  );
}
