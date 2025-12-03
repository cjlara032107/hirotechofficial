'use client';

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { LoadingSpinner } from '@/components/ui/loading-spinner';
import { Facebook, CheckCircle2, ChevronLeft, ChevronRight } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';

interface FacebookPage {
  id: string;
  name: string;
  accessToken: string;
  isConnected: boolean;
}

interface FacebookPageSelectorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  userAccessToken: string;
  onPagesConnected: () => void;
}

export function FacebookPageSelectorDialog({
  open,
  onOpenChange,
  userAccessToken,
  onPagesConnected,
}: FacebookPageSelectorDialogProps) {
  const [pages, setPages] = useState<FacebookPage[]>([]);
  const [selectedPageIds, setSelectedPageIds] = useState<Set<string>>(new Set());
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  
  // Pagination states for available pages
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const itemsPerPage = 10;
  
  // Pagination states for connected pages
  const [connectedCurrentPage, setConnectedCurrentPage] = useState(1);
  const [connectedSearchQuery, setConnectedSearchQuery] = useState('');
  const connectedItemsPerPage = 5;

  // Fetch pages when dialog opens
  useEffect(() => {
    if (open && userAccessToken) {
      fetchPages();
    }
  }, [open, userAccessToken]);

  async function fetchPages() {
    setIsLoading(true);
    try {
      const response = await fetch(
        `/api/facebook/pages?token=${encodeURIComponent(userAccessToken)}`
      );

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to fetch pages');
      }

      const data = await response.json();
      console.log('[Page Selector] Fetched pages:', {
        total: data.pages?.length || 0,
        connected: data.pages?.filter((p: any) => p.isConnected).length || 0,
        available: data.pages?.filter((p: any) => !p.isConnected).length || 0,
        pages: data.pages,
      });
      setPages(data.pages || []);
    } catch (error) {
      console.error('Error fetching pages:', error);
      const message = error instanceof Error ? error.message : 'Failed to fetch Facebook pages';
      toast.error(message);
      onOpenChange(false);
    } finally {
      setIsLoading(false);
    }
  }

  function togglePage(pageId: string) {
    const newSelected = new Set(selectedPageIds);
    if (newSelected.has(pageId)) {
      newSelected.delete(pageId);
    } else {
      newSelected.add(pageId);
    }
    setSelectedPageIds(newSelected);
  }

  // Select all unconnected pages across all pagination pages
  function toggleAllPages() {
    const allUnconnectedIds = pages.filter(p => !p.isConnected).map(p => p.id);
    if (selectedPageIds.size === allUnconnectedIds.length) {
      // Unselect all
      setSelectedPageIds(new Set());
    } else {
      // Select all unconnected pages across all pages
      setSelectedPageIds(new Set(allUnconnectedIds));
    }
  }

  // Select only pages visible on current page
  function toggleCurrentPage() {
    const currentPageIds = paginatedPages.map(p => p.id);
    const allSelected = currentPageIds.every(id => selectedPageIds.has(id));
    
    const newSelected = new Set(selectedPageIds);
    if (allSelected) {
      // Deselect current page items
      currentPageIds.forEach(id => newSelected.delete(id));
    } else {
      // Select current page items
      currentPageIds.forEach(id => newSelected.add(id));
    }
    setSelectedPageIds(newSelected);
  }

  async function handleSave() {
    if (selectedPageIds.size === 0) {
      toast.error('Please select at least one page');
      return;
    }

    setIsSaving(true);
    try {
      const selectedPages = pages.filter(p => selectedPageIds.has(p.id));

      const response = await fetch('/api/facebook/pages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          selectedPages: selectedPages.map(p => ({ id: p.id, name: p.name })),
          userAccessToken,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        console.error('[Page Selector] Save failed:', {
          status: response.status,
          error: data.error,
          errors: data.errors,
          details: data.details,
        });
        
        // Show specific error message
        let errorMessage = data.error || 'Failed to save pages';
        if (data.errors && data.errors.length > 0) {
          errorMessage += `: ${data.errors.map((e: any) => e.error || e.pageName).join(', ')}`;
        }
        throw new Error(errorMessage);
      }

      console.log('[Page Selector] Save successful:', {
        savedPages: data.savedPages,
        errors: data.errors?.length || 0,
      });

      toast.success(
        `Successfully connected ${data.savedPages} page${data.savedPages > 1 ? 's' : ''}`
      );

      if (data.errors && data.errors.length > 0) {
        const errorDetails = data.errors.map((e: any) => `${e.pageName || e.pageId}: ${e.error || 'Unknown error'}`).join('; ');
        toast.error(
          `Failed to connect ${data.errors.length} page${data.errors.length > 1 ? 's' : ''}: ${errorDetails}`
        );
      }

      onOpenChange(false);
      onPagesConnected();
    } catch (error) {
      console.error('Error saving pages:', error);
      const message = error instanceof Error ? error.message : 'Failed to connect pages';
      toast.error(message);
    } finally {
      setIsSaving(false);
    }
  }

  // Filter and paginate available pages
  const availablePages = pages.filter(p => !p.isConnected);
  const connectedPages = pages.filter(p => p.isConnected);
  
  // Filter by search query (available pages)
  const filteredPages = searchQuery
    ? availablePages.filter(p => 
        p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.id.includes(searchQuery)
      )
    : availablePages;
  
  // Pagination logic (available pages)
  const totalPages = Math.ceil(filteredPages.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedPages = filteredPages.slice(startIndex, endIndex);
  
  // Filter by search query (connected pages)
  const filteredConnectedPages = connectedSearchQuery
    ? connectedPages.filter(p => 
        p.name.toLowerCase().includes(connectedSearchQuery.toLowerCase()) ||
        p.id.includes(connectedSearchQuery)
      )
    : connectedPages;
  
  // Pagination logic (connected pages)
  const totalConnectedPages = Math.ceil(filteredConnectedPages.length / connectedItemsPerPage);
  const connectedStartIndex = (connectedCurrentPage - 1) * connectedItemsPerPage;
  const connectedEndIndex = connectedStartIndex + connectedItemsPerPage;
  const paginatedConnectedPages = filteredConnectedPages.slice(connectedStartIndex, connectedEndIndex);
  
  // Reset to page 1 when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);
  
  useEffect(() => {
    setConnectedCurrentPage(1);
  }, [connectedSearchQuery]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px] max-h-[90vh] flex flex-col p-0">
        <DialogHeader className="px-6 pt-6 pb-4">
          <DialogTitle className="flex items-center gap-2 text-lg">
            <Facebook className="h-4 w-4" />
            Select Facebook Pages
          </DialogTitle>
          <DialogDescription className="text-xs">
            Choose which Facebook pages you want to connect for messaging
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner className="h-8 w-8" />
          </div>
        ) : (
          <div className="space-y-3 overflow-y-auto flex-1 px-6 min-h-0">
            {availablePages.length > 0 && (
              <>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs font-medium">
                      Available Pages ({filteredPages.length})
                      {selectedPageIds.size > 0 && (
                        <span className="ml-2 text-primary">
                          • {selectedPageIds.size} selected
                        </span>
                      )}
                    </Label>
                    <div className="flex gap-1">
                      {totalPages > 1 && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={toggleCurrentPage}
                          className="text-xs h-6 px-2"
                        >
                          {paginatedPages.every(p => selectedPageIds.has(p.id))
                            ? 'Deselect Page'
                            : 'Select Page'}
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={toggleAllPages}
                        className="text-xs font-semibold h-6 px-2"
                      >
                        {selectedPageIds.size === availablePages.length
                          ? 'Deselect All'
                          : 'Select All'}
                      </Button>
                    </div>
                  </div>
                  
                  {/* Search bar */}
                  <Input
                    type="text"
                    placeholder="Search pages by name or ID..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full h-8 text-xs"
                  />
                </div>

                <div className="rounded-md border">
                  <ScrollArea className="h-[180px] p-2">
                    <div className="space-y-1.5">
                      {paginatedPages.map((page) => (
                        <div
                          key={page.id}
                          className={`flex items-start space-x-2 rounded-lg border p-2 transition-all cursor-pointer ${
                            selectedPageIds.has(page.id)
                              ? 'bg-primary/10 border-primary shadow-sm'
                              : 'hover:bg-muted/50 hover:border-muted-foreground/20'
                          }`}
                          onClick={() => togglePage(page.id)}
                        >
                          <Checkbox
                            id={`page-${page.id}`}
                            checked={selectedPageIds.has(page.id)}
                            onCheckedChange={() => togglePage(page.id)}
                            className="mt-0.5 h-4 w-4"
                          />
                          <div className="flex-1 space-y-0">
                            <Label
                              htmlFor={`page-${page.id}`}
                              className="flex items-center gap-1.5 font-medium cursor-pointer text-xs leading-tight"
                            >
                              {page.name}
                              <Facebook className="h-3 w-3 text-blue-600" />
                            </Label>
                            <p className="text-[10px] text-muted-foreground">
                              ID: {page.id}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
                
                {/* Pagination Controls */}
                {totalPages > 1 && (
                  <div className="flex items-center justify-between gap-2 text-[10px] bg-muted/30 px-2 py-1.5 rounded-lg">
                    <p className="text-muted-foreground">
                      {startIndex + 1}-{Math.min(endIndex, filteredPages.length)} of {filteredPages.length}
                    </p>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                        disabled={currentPage === 1}
                        className="h-6 w-6 p-0"
                      >
                        <ChevronLeft className="h-3 w-3" />
                      </Button>
                      <span className="font-semibold min-w-[40px] text-center text-xs">
                        {currentPage} / {totalPages}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                        disabled={currentPage === totalPages}
                        className="h-6 w-6 p-0"
                      >
                        <ChevronRight className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}

            {connectedPages.length > 0 && (
              <div className="space-y-2 pt-2 border-t">
                <Label className="text-xs font-medium text-muted-foreground">
                  Already Connected ({filteredConnectedPages.length})
                </Label>
                
                {/* Search bar for connected pages */}
                <Input
                  type="text"
                  placeholder="Search connected pages..."
                  value={connectedSearchQuery}
                  onChange={(e) => setConnectedSearchQuery(e.target.value)}
                  className="w-full h-8 text-xs"
                />
                
                {/* Connected pages list with scroll */}
                <div className="max-h-[120px] overflow-y-auto space-y-1.5 rounded-lg border p-2 bg-muted/20">
                  {paginatedConnectedPages.length > 0 ? (
                    paginatedConnectedPages.map((page) => (
                      <div
                        key={page.id}
                        className="flex items-center justify-between rounded-lg border p-1.5 bg-background"
                      >
                        <div className="flex items-center gap-2 min-w-0 flex-1">
                          <CheckCircle2 className="h-3 w-3 text-green-600 flex-shrink-0" />
                          <div className="min-w-0 flex-1">
                            <span className="text-xs font-medium truncate block">{page.name}</span>
                            <span className="text-[10px] text-muted-foreground">ID: {page.id}</span>
                          </div>
                        </div>
                        <Badge variant="secondary" className="flex-shrink-0 text-[10px] py-0 h-5">Connected</Badge>
                      </div>
                    ))
                  ) : (
                    <p className="text-center text-xs text-muted-foreground py-2">
                      No connected pages match your search
                    </p>
                  )}
                </div>
                
                {/* Pagination Controls for Connected Pages */}
                {totalConnectedPages > 1 && (
                  <div className="flex items-center justify-between gap-2 text-[10px] bg-muted/20 px-2 py-1.5 rounded-lg">
                    <p className="text-muted-foreground">
                      {connectedStartIndex + 1}-{Math.min(connectedEndIndex, filteredConnectedPages.length)} of {filteredConnectedPages.length}
                    </p>
                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setConnectedCurrentPage(p => Math.max(1, p - 1))}
                        disabled={connectedCurrentPage === 1}
                        className="h-5 w-5 p-0"
                      >
                        <ChevronLeft className="h-2.5 w-2.5" />
                      </Button>
                      <span className="font-semibold min-w-[35px] text-center text-xs">
                        {connectedCurrentPage} / {totalConnectedPages}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setConnectedCurrentPage(p => Math.min(totalConnectedPages, p + 1))}
                        disabled={connectedCurrentPage === totalConnectedPages}
                        className="h-5 w-5 p-0"
                      >
                        <ChevronRight className="h-2.5 w-2.5" />
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {pages.length === 0 && !isLoading && (
              <div className="text-center py-6 text-sm text-muted-foreground">
                No Facebook pages found. Make sure you have pages you manage.
              </div>
            )}
          </div>
        )}

        <DialogFooter className="px-6 py-4 border-t">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isSaving}
            className="h-9"
          >
            Cancel
          </Button>
          <Button
            onClick={handleSave}
            disabled={selectedPageIds.size === 0 || isSaving || isLoading}
            className="h-9"
          >
            {isSaving ? (
              <>
                <LoadingSpinner className="mr-2 h-4 w-4" />
                Connecting...
              </>
            ) : (
              `Connect ${selectedPageIds.size} Page${selectedPageIds.size !== 1 ? 's' : ''}`
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

