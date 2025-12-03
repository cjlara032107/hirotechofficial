'use client';

import { useState, useTransition, useMemo, memo, useRef, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
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
  MoreHorizontal,
  Tag,
  Trash2,
  MoveRight,
  ArrowUpDown,
  AlertCircle,
  Sparkles,
  Plus,
  RefreshCw,
  MessageSquare,
} from 'lucide-react';
import { toast } from 'sonner';
import { useQueryState } from 'nuqs';
import { BulkMessageDialog } from './bulk-message-dialog';
import { useRouter } from 'next/navigation';

interface Contact {
  id: string;
  firstName: string;
  lastName: string | null;
  profilePicUrl: string | null;
  hasMessenger: boolean;
  hasInstagram: boolean;
  leadScore: number;
  tags: string[];
  lastInteraction: Date | null;
  stage: {
    id: string;
    name: string;
    color: string;
  } | null;
  facebookPage: {
    id: string;
    pageName: string;
    instagramUsername: string | null;
  };
  createdAt: Date | string;
  conversionProbability?: number | null;
  buyerIntent?: string | null;
  sentiment?: string | null;
  nextBestAction?: string | null;
}

interface Tag {
  id: string;
  name: string;
  color: string;
}

interface Pipeline {
  id: string;
  name: string;
  stages: {
    id: string;
    name: string;
    color: string;
  }[];
}

interface ContactsTableProps {
  contacts: Contact[];
  tags: Tag[];
  pipelines: Pipeline[];
  isLoading?: boolean;
}

// Component for updating best contact times from dropdown menu
function UpdateBestTimesMenuItem({ contactId }: { contactId: string }) {
  const [isUpdating, setIsUpdating] = useState(false);
  const router = useRouter();
  const queryClient = useQueryClient();

  const handleUpdate = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    setIsUpdating(true);
    try {
      console.log(`[UpdateBestTimesMenuItem] Starting update for contact ${contactId}`);
      const response = await fetch(`/api/contacts/${contactId}/update-best-times`, {
        method: 'POST',
      });

      console.log(`[UpdateBestTimesMenuItem] Response status: ${response.status}`);
      
      const contentType = response.headers.get('content-type');
      let data;
      
      if (contentType?.includes('application/json')) {
        data = await response.json();
      } else {
        const text = await response.text();
        console.error('[UpdateBestTimesMenuItem] Non-JSON response:', text);
        throw new Error(`Server returned non-JSON response: ${text.substring(0, 200)}`);
      }

      console.log('[UpdateBestTimesMenuItem] Response data:', data);

      if (!response.ok) {
        // Safely extract error message
        const errorMessage = data?.error || data?.message || `HTTP ${response.status}: Failed to update best contact times`;
        
        // Log error details - use JSON.stringify to ensure proper serialization
        console.error('[UpdateBestTimesMenuItem] Error response:', JSON.stringify({
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
      
      // Invalidate contacts query to refresh data
      queryClient.invalidateQueries({ queryKey: ['contacts'] });
      
      // Also refresh the page
      router.refresh();
    } catch (error) {
      console.error('[UpdateBestTimesMenuItem] Full error:', error);
      if (error instanceof Error) {
        console.error('[UpdateBestTimesMenuItem] Error message:', error.message);
        console.error('[UpdateBestTimesMenuItem] Error stack:', error.stack);
        
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
    <DropdownMenuItem onClick={handleUpdate} disabled={isUpdating}>
      <RefreshCw className={`mr-2 h-4 w-4 ${isUpdating ? 'animate-spin' : ''}`} />
      {isUpdating ? 'Updating...' : 'Update Best Times'}
    </DropdownMenuItem>
  );
}

// Memoized contact row component to prevent unnecessary re-renders
const ContactRow = memo(function ContactRow({
  contact,
  isSelected,
  onSelect,
  onDelete,
}: {
  contact: Contact;
  isSelected: boolean;
  onSelect: (id: string, checked: boolean) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <TableRow
      data-state={isSelected ? 'selected' : undefined}
      data-contact-id={contact.id}
    >
      <TableCell>
        <Checkbox
          checked={isSelected}
          onCheckedChange={(checked) => onSelect(contact.id, checked as boolean)}
          aria-label={`Select ${contact.firstName}`}
          data-contact-id={contact.id}
        />
      </TableCell>
      <TableCell>
        <Link
          href={`/contacts/${contact.id}`}
          className="flex items-center gap-3 hover:underline"
        >
          <Avatar className="h-8 w-8">
            <AvatarImage src={contact.profilePicUrl || undefined} />
            <AvatarFallback className="text-xs">
              {contact.firstName[0]}
              {contact.lastName?.[0] || ''}
            </AvatarFallback>
          </Avatar>
          <div>
            <div className="font-medium">
              {contact.firstName} {contact.lastName || ''}
            </div>
          </div>
        </Link>
      </TableCell>
      <TableCell>
        <div className="flex flex-col">
          <span className="text-sm font-medium">
            {contact.facebookPage.pageName}
          </span>
          {contact.facebookPage.instagramUsername && (
            <span className="text-xs text-muted-foreground">
              @{contact.facebookPage.instagramUsername}
            </span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1">
          {contact.hasMessenger && (
            <Badge variant="secondary" className="text-xs">
              Messenger
            </Badge>
          )}
          {contact.hasInstagram && (
            <Badge variant="secondary" className="text-xs">
              Instagram
            </Badge>
          )}
        </div>
      </TableCell>
      <TableCell>
        <Badge variant="outline">{contact.leadScore}</Badge>
      </TableCell>
      <TableCell>
        {contact.stage && (
          <Badge
            variant="outline"
            style={{
              backgroundColor: `${contact.stage.color}20`,
              color: contact.stage.color,
              borderColor: contact.stage.color,
            }}
          >
            {contact.stage.name}
          </Badge>
        )}
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap gap-1 max-w-xs">
          {contact.tags.slice(0, 2).map((tag) => (
            <Badge key={tag} variant="secondary" className="text-xs">
              {tag}
            </Badge>
          ))}
          {contact.tags.length > 2 && (
            <Badge variant="secondary" className="text-xs">
              +{contact.tags.length - 2}
            </Badge>
          )}
        </div>
      </TableCell>
      <TableCell className="text-sm text-muted-foreground">
        {contact.createdAt instanceof Date 
          ? contact.createdAt.toLocaleDateString() 
          : new Date(contact.createdAt).toLocaleDateString()}
      </TableCell>
      <TableCell>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreHorizontal className="h-4 w-4" />
              <span className="sr-only">Open menu</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link href={`/contacts/${contact.id}`}>View details</Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <UpdateBestTimesMenuItem contactId={contact.id} />
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive"
              onClick={() => onDelete(contact.id)}
            >
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );
});

export function ContactsTable({ contacts, tags, pipelines }: ContactsTableProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const [isPending, startTransition] = useTransition();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectAllPages, setSelectAllPages] = useState(false);
  const [totalContactsCount, setTotalContactsCount] = useState(0);
  const [allContactIds, setAllContactIds] = useState<string[]>([]);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const [loadingAllIds, setLoadingAllIds] = useState(false);
  const [bulkMessageOpen, setBulkMessageOpen] = useState(false);
  
  // CRITICAL: Use ref to track current selection to avoid stale closures
  const selectedIdsRef = useRef<Set<string>>(new Set());
  
  // Keep ref in sync with state
  useEffect(() => {
    selectedIdsRef.current = selectedIds;
    console.log('[ContactsTable] selectedIds state updated:', selectedIds.size, 'contact(s)');
  }, [selectedIds]);

  const [sortBy, setSortBy] = useQueryState('sortBy', {
    defaultValue: 'date',
    shallow: true,
  });
  const [sortOrder, setSortOrder] = useQueryState('sortOrder', {
    defaultValue: 'desc',
    shallow: true,
  });

  function handleSort(column: 'name' | 'score' | 'date' | 'priority') {
    startTransition(() => {
      if (sortBy === column) {
        // Priority is always descending, don't toggle
        if (column === 'priority') {
          return;
        }
        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
      } else {
        setSortBy(column);
        setSortOrder(column === 'priority' ? 'desc' : 'asc');
      }
    });
  }

  async function fetchAllContactIds() {
    try {
      setLoadingAllIds(true);
      
      // Build query string from current search params
      const params = new URLSearchParams();
      searchParams.forEach((value, key) => {
        if (key !== 'page') { // Exclude page parameter
          params.set(key, value);
        }
      });

      const response = await fetch(`/api/contacts/ids?${params.toString()}`);
      if (!response.ok) {
        throw new Error('Failed to fetch contact IDs');
      }

      const data = await response.json();
      setAllContactIds(data.contactIds);
      setTotalContactsCount(data.total);
      return data.contactIds;
    } catch (error) {
      console.error('Error fetching contact IDs:', error);
      toast.error('Failed to load all contacts');
      return [];
    } finally {
      setLoadingAllIds(false);
    }
  }

  async function handleSelectAllPages() {
    const ids = await fetchAllContactIds();
    if (ids.length > 0) {
      const newSelected = new Set<string>(ids);
      setSelectedIds(newSelected);
      selectedIdsRef.current = newSelected; // Update ref immediately
      setSelectAllPages(true);
    }
  }

  function handleDeselectAllPages() {
    const newSelected = new Set<string>();
    setSelectedIds(newSelected);
    selectedIdsRef.current = newSelected; // Update ref immediately
    setSelectAllPages(false);
    setAllContactIds([]);
    setTotalContactsCount(0);
  }

  function handleSelectAll(checked: boolean) {
    if (checked) {
      const newSelected = new Set<string>(contacts.map((c) => c.id));
      setSelectedIds(newSelected);
      selectedIdsRef.current = newSelected; // Update ref immediately
      setSelectAllPages(false);
    } else {
      const newSelected = new Set<string>();
      setSelectedIds(newSelected);
      selectedIdsRef.current = newSelected; // Update ref immediately
      setSelectAllPages(false);
    }
  }

  function handleSelectOne(id: string, checked: boolean) {
    // Use functional update to avoid stale closures
    setSelectedIds((prevSelected) => {
      const newSelected = new Set(prevSelected);
      if (checked) {
        newSelected.add(id);
      } else {
        newSelected.delete(id);
      }
      
      // CRITICAL: Update ref immediately (before state update completes)
      selectedIdsRef.current = newSelected;
      
      // CRITICAL FIX: Reset "select all pages" if user manually changes selection
      // This ensures that if selectAllPages was true, any manual selection change resets it
      const newSelectedArray = Array.from(newSelected);
      
      if (selectAllPages) {
        // Check if the new selection matches allContactIds
        const matchesAllPages = 
          newSelectedArray.length === allContactIds.length &&
          newSelectedArray.every(contactId => allContactIds.includes(contactId));
        
        // If selection doesn't match "all pages" anymore, reset the flag
        if (!matchesAllPages) {
          console.log('[ContactsTable] 🔄 Manual selection change detected, resetting selectAllPages');
          console.log(`  Previous: ${allContactIds.length} contacts (selectAllPages=true)`);
          console.log(`  New: ${newSelectedArray.length} contact(s) selected`);
          console.log(`  Selected IDs:`, newSelectedArray);
          setSelectAllPages(false);
          setAllContactIds([]);
          setTotalContactsCount(0);
        }
      }
      
      // ADDITIONAL SAFETY: If only 1 contact is selected, ensure selectAllPages is false
      // This prevents any edge cases where the flag might be incorrectly set
      if (newSelectedArray.length === 1 && selectAllPages) {
        console.warn('[ContactsTable] 🚨 SAFETY CHECK: Only 1 contact selected but selectAllPages=true!');
        console.warn('  Forcing reset of selectAllPages flag');
        setSelectAllPages(false);
        setAllContactIds([]);
        setTotalContactsCount(0);
      }
      
      console.log(`[ContactsTable] Selection updated: ${newSelected.size} contact(s) selected`, newSelectedArray);
      return newSelected;
    });
  }

  async function handleBulkAction(
    action: string,
    data?: { tags?: string[]; stageId?: string },
    overrideContactIds?: string[] // Allow passing contact IDs directly to bypass state
  ) {
    // CRITICAL: If overrideContactIds is provided, use it directly (bypasses all state checks)
    // This MUST be checked FIRST, before any other logic, to prevent state corruption
    console.log('[ContactsTable] 🔍 handleBulkAction called:', { action, overrideContactIds: overrideContactIds?.length, hasOverride: !!overrideContactIds });
    if (overrideContactIds && overrideContactIds.length > 0) {
      console.log('[ContactsTable] 🔒 OVERRIDE MODE: Using provided contact IDs directly');
      console.log('  Override contact IDs:', overrideContactIds);
      console.log('  Count:', overrideContactIds.length);
      
      // If only 1 contact, force clear all flags
      if (overrideContactIds.length === 1) {
        setSelectAllPages(false);
        setAllContactIds([]);
        setTotalContactsCount(0);
        console.log('[ContactsTable] 🔒 OVERRIDE MODE: Cleared all "select all" flags for single contact');
      }
      
      // Use override directly - no validation needed, caller is responsible
      const contactIdsToSend = overrideContactIds;
      
      console.log(`[ContactsTable] 🚀 FINAL: Sending bulk action "${action}" for ${contactIdsToSend.length} contact(s) (OVERRIDE MODE)`);
      console.log(`[ContactsTable] Contact IDs being sent:`, contactIdsToSend);
      
      try {
        // ABSOLUTE SAFETY: Double-check that we're not accidentally using allContactIds
        if (contactIdsToSend.length === 1 && allContactIds.length > 1) {
          console.error('[ContactsTable] 🚨 CRITICAL: Override mode with 1 contact but allContactIds has more!');
          console.error('  This should never happen in override mode - forcing to use only the override contact');
          // This is a safety check - in override mode, contactIdsToSend should already be correct
          // But we double-check to be absolutely sure
        }
        
        setBulkActionLoading(true);
        const response = await fetch('/api/contacts/bulk', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action,
            contactIds: contactIdsToSend,
            data,
          }),
        });

        const contentType = response.headers.get('content-type');
        if (!contentType?.includes('application/json')) {
          throw new Error('Server returned non-JSON response');
        }

        const result = await response.json();
        // Handle response (same as below)
        if (response.ok) {
          if (action === 'analyze') {
            if (result.analyzing && result.jobId) {
              // Show notification about cancelled jobs if any
              if (result.cancelledJobs && result.cancelledJobs.length > 0) {
                toast.info('Analysis started in background', {
                  description: `${result.cancelledJobs.length} previous analysis job(s) were cancelled to prevent conflicts. You can continue working while contacts are analyzed.`,
                  duration: 5000,
                });
              } else {
                toast.info('Analysis started in background', {
                  description: 'You can continue working while contacts are analyzed',
                  duration: 3000,
                });
              }
              if (typeof window !== 'undefined') {
                sessionStorage.setItem('activeAnalysisJobId', result.jobId);
                window.dispatchEvent(new CustomEvent('analysisStarted', { detail: { jobId: result.jobId } }));
              }
            } else {
              const analyzed = result.analyzed || 0;
              const failed = result.failed || 0;
              if (analyzed > 0) {
                toast.success(
                  `Successfully analyzed ${analyzed} contact(s)${failed > 0 ? `, ${failed} failed` : ''}`
                );
              }
            }
        } else {
          // For delete action, show detailed results if available
          if (action === 'delete' && result.deleted !== undefined) {
            const deleted = result.deleted || 0;
            const failed = result.failed || 0;
            if (deleted > 0 && failed === 0) {
              toast.success(`Successfully deleted ${deleted} contact(s)`);
            } else if (deleted > 0 && failed > 0) {
              toast.warning(`Deleted ${deleted} contact(s), ${failed} failed`);
            } else {
              toast.error(`Failed to delete contacts`);
            }
          } else {
            toast.success(
              `Successfully ${action === 'delete' ? 'deleted' : 'updated'} ${
                contactIdsToSend.length
              } contact(s)`
            );
          }
        }
        setSelectedIds(new Set());
        queryClient.invalidateQueries({ queryKey: ['contacts'] });
      } else {
        // Extract detailed error information
        const errorMessage = result.error || 'Failed to perform action';
        const errorDetails = result.details || '';
        const found = result.found;
        const requested = result.requested;
        const missing = result.missing;
        
        console.error('[Bulk Action] API error:', {
          status: response.status,
          error: errorMessage,
          details: errorDetails,
          found,
          requested,
          missing,
        });
        
        // Show detailed error message
        if (action === 'delete' && found !== undefined && requested !== undefined) {
          toast.error(
            `${errorMessage}${errorDetails ? ` ${errorDetails}` : ''}`,
            {
              description: `Found ${found} of ${requested} contacts. ${missing || 0} contact(s) could not be found or are unauthorized.`,
              duration: 5000,
            }
          );
        } else {
          toast.error(errorMessage + (errorDetails ? `: ${errorDetails}` : ''));
        }
      }
      } catch (error) {
        console.error('Bulk action error:', error);
        toast.error(error instanceof Error ? error.message : 'Failed to perform bulk action');
      } finally {
        setBulkActionLoading(false);
      }
      
      return; // Exit early, we've handled the request
    }
    
    // CRITICAL: If we reach here, override mode was NOT used
    // This means we need to be extra careful about state corruption
    console.log('[ContactsTable] ⚠️ NON-OVERRIDE MODE: Using state-based selection (overrideContactIds not provided)');
    // CRITICAL: Read selection DIRECTLY from ref (updated synchronously) at the moment of click
    // This avoids any React state batching or closure issues
    const currentSelection = new Set(selectedIdsRef.current);
    const currentSelectionArray = Array.from(currentSelection);
    
    console.log('[ContactsTable] 🔍 DEBUG: Selection check before bulk action');
    console.log('  Current selection size (from ref):', currentSelection.size);
    console.log('  Current selection IDs:', currentSelectionArray);
    console.log('  State selectedIds size:', selectedIds.size);
    console.log('  selectAllPages:', selectAllPages);
    console.log('  totalContactsCount:', totalContactsCount);
    console.log('  allContactIds length:', allContactIds.length);
    
    // CRITICAL: Use ONLY the ref selection - it's the most up-to-date
    let contactIdsToSend = currentSelectionArray;
    
    // CRITICAL SAFETY: If user only selected 1 contact, ensure we ONLY send that 1 contact
    // This is a hard stop - no exceptions
    if (currentSelection.size === 1) {
      const singleId = currentSelectionArray[0];
      console.log('[ContactsTable] 🔒 SINGLE SELECTION MODE: User selected exactly 1 contact');
      console.log(`  Contact ID: ${singleId}`);
      console.log(`  IGNORING allContactIds (${allContactIds.length} contacts) and selectAllPages flag`);
      
      // Force reset any "select all" state immediately
      if (selectAllPages || allContactIds.length > 0) {
        console.warn('[ContactsTable] 🚨 Clearing stale selectAllPages state for single selection');
        setSelectAllPages(false);
        setAllContactIds([]);
        setTotalContactsCount(0);
      }
      
      // HARD LIMIT: Only send the single selected contact, nothing else
      contactIdsToSend = [singleId];
      
      // Double-check: if somehow we have more than 1, force it to 1
      if (contactIdsToSend.length !== 1) {
        console.error('[ContactsTable] 🚨 CRITICAL: Single selection but contactIdsToSend has wrong count!');
        console.error(`  Expected 1, got ${contactIdsToSend.length}`);
        contactIdsToSend = [singleId];
      }
    }
    
    // CRITICAL FIX: If selectAllPages is true, we MUST verify the selection matches
    // If it doesn't match, force reset and use only what's actually selected
    if (selectAllPages) {
      // CRITICAL: Always verify that selectedIds actually matches allContactIds
      // If they don't match, it means the user manually changed the selection
      const selectedArray = Array.from(contactIdsToSend).sort();
      const allIdsArray = [...allContactIds].sort();
      const matchesAllIds = selectedArray.length === allIdsArray.length && 
        selectedArray.every((id, idx) => id === allIdsArray[idx]);
      
      if (!matchesAllIds || contactIdsToSend.length !== totalContactsCount) {
        console.warn('[ContactsTable] ⚠️ CRITICAL: selectAllPages=true but selection mismatch!');
        console.warn(`  Expected ${totalContactsCount} contacts (from allContactIds), got ${contactIdsToSend.length}`);
        console.warn(`  Selected IDs match allContactIds: ${matchesAllIds}`);
        console.warn('  FORCING RESET of selectAllPages flag - user manually changed selection');
        setSelectAllPages(false);
        setAllContactIds([]);
        setTotalContactsCount(0);
        // CRITICAL: Don't re-read from state (it's async), use the value we already have
        // contactIdsToSend already has the correct value from stateSelectedIds above
      } else {
        // If selectAllPages is true AND everything matches, this is a legitimate "select all" action
        console.log('[ContactsTable] ✅ Valid "select all pages" action confirmed');
        console.log(`  Processing ${contactIdsToSend.length} contacts from "select all pages"`);
      }
    }
    
    // ADDITIONAL SAFETY CHECK: If selectAllPages is false but allContactIds is populated,
    // make sure we're not accidentally using allContactIds instead of selectedIds
    if (!selectAllPages && allContactIds.length > 0) {
          const selectedArray = Array.from(contactIdsToSend).sort();
          const allIdsArray = [...allContactIds].sort();
          const matchesAllIds = selectedArray.length === allIdsArray.length && 
            selectedArray.every((id, idx) => id === allIdsArray[idx]);
          
      if (matchesAllIds && contactIdsToSend.length > 1) {
        console.error('[ContactsTable] 🚨 CRITICAL BUG: selectAllPages=false but selectedIds matches allContactIds!');
        console.error('  This should NEVER happen - clearing allContactIds to prevent incorrect analysis');
        console.error(`  Selected: ${contactIdsToSend.length} contacts`);
        console.error(`  All IDs: ${allContactIds.length} contacts`);
        // Clear the stale allContactIds to prevent future issues
        setAllContactIds([]);
        setTotalContactsCount(0);
        // Continue with the actual selectedIds (which should be correct)
      }
    }
    
    if (contactIdsToSend.length === 0) {
      console.warn('[ContactsTable] ❌ No contacts selected, aborting bulk action');
      toast.error('Please select at least one contact');
      return;
    }
    
    // FINAL VALIDATION: Ensure we're not accidentally sending all contacts
    if (contactIdsToSend.length > 20) {
      console.error('[ContactsTable] 🚨 WARNING: Sending more than 20 contacts! This might be an error.');
      console.error('  Contact IDs being sent:', contactIdsToSend);
      // If user only selected 1 but we're sending many, something is wrong
      if (currentSelection.size === 1 && contactIdsToSend.length > 1) {
        console.error('[ContactsTable] 🚨 CRITICAL BUG: User selected 1 but sending multiple!');
        console.error('  Forcing to send only the selected contact');
        contactIdsToSend = currentSelectionArray;
      }
    }
    
    // FINAL HARD LIMIT: If currentSelection says 1, we MUST only send 1
    if (currentSelection.size === 1 && contactIdsToSend.length !== 1) {
      console.error('[ContactsTable] 🚨 CRITICAL: Current selection says 1 but contactIdsToSend has different count!');
      console.error(`  currentSelection.size: ${currentSelection.size}`);
      console.error(`  contactIdsToSend.length: ${contactIdsToSend.length}`);
      console.error('  FORCING to use only the selected contact');
      contactIdsToSend = currentSelectionArray;
    }
    
    // ABSOLUTE FINAL CHECK: Never send more contacts than what's actually selected
    if (contactIdsToSend.length > currentSelection.size) {
      console.error('[ContactsTable] 🚨 CRITICAL BUG: contactIdsToSend has more contacts than selected!');
      console.error(`  Selected: ${currentSelection.size}, Sending: ${contactIdsToSend.length}`);
      console.error('  FORCING to match selection exactly');
      contactIdsToSend = currentSelectionArray;
    }
    
    console.log(`[ContactsTable] 🚀 FINAL: Sending bulk action "${action}" for ${contactIdsToSend.length} contact(s)`);
    console.log(`[ContactsTable] Contact IDs being sent:`, contactIdsToSend);
    console.log(`[ContactsTable] Current selection size (ref): ${currentSelection.size}`);
    console.log(`[ContactsTable] State selectedIds size: ${selectedIds.size}`);
    console.log(`[ContactsTable] selectAllPages: ${selectAllPages}`);
    console.log(`[ContactsTable] allContactIds length: ${allContactIds.length}`);

    try {
      setBulkActionLoading(true);
      const response = await fetch('/api/contacts/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          contactIds: contactIdsToSend,
          data,
        }),
      });

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (!contentType?.includes('application/json')) {
        throw new Error('Server returned non-JSON response');
      }

      const result = await response.json();

      if (response.ok) {
        if (action === 'analyze') {
          // Check if this is a background job
          if (result.analyzing && result.jobId) {
            // Show notification about cancelled jobs if any
            if (result.cancelledJobs && result.cancelledJobs.length > 0) {
              toast.info('Analysis started in background', {
                description: `${result.cancelledJobs.length} previous analysis job(s) were cancelled to prevent conflicts. You can continue working while contacts are analyzed.`,
                duration: 5000,
              });
            } else {
            toast.info('Analysis started in background', {
              description: 'You can continue working while contacts are analyzed',
              duration: 3000,
            });
            }
            // Store job ID for indicator
            if (typeof window !== 'undefined') {
              sessionStorage.setItem('activeAnalysisJobId', result.jobId);
              // Trigger custom event to show indicator
              window.dispatchEvent(new CustomEvent('analysisStarted', { detail: { jobId: result.jobId } }));
            }
          } else {
            // Legacy synchronous response
            const analyzed = result.analyzed || 0;
            const failed = result.failed || 0;
            if (analyzed > 0) {
              toast.success(
                `Successfully analyzed ${analyzed} contact(s)${failed > 0 ? ` (${failed} failed)` : ''}`
              );
            } else {
              toast.error(`Failed to analyze contacts${failed > 0 ? `: ${failed} failed` : ''}`);
            }
          }
        } else {
          // For delete action, show detailed results if available
          if (action === 'delete' && result.deleted !== undefined) {
            const deleted = result.deleted || 0;
            const failed = result.failed || 0;
            if (deleted > 0 && failed === 0) {
              toast.success(`Successfully deleted ${deleted} contact(s)`);
            } else if (deleted > 0 && failed > 0) {
              toast.warning(`Deleted ${deleted} contact(s), ${failed} failed`);
            } else {
              toast.error(`Failed to delete contacts`);
            }
          } else {
            toast.success(
              `Successfully ${action === 'delete' ? 'deleted' : 'updated'} ${
                selectedIds.size
              } contact(s)`
            );
          }
        }
        setSelectedIds(new Set());
        // Invalidate contacts queries to refetch data
        queryClient.invalidateQueries({ queryKey: ['contacts'] });
      } else {
        // Extract detailed error information
        const errorMessage = result.error || 'Failed to perform action';
        const errorDetails = result.details || '';
        const found = result.found;
        const requested = result.requested;
        const missing = result.missing;
        
        console.error('[Bulk Action] API error:', {
          status: response.status,
          error: errorMessage,
          details: errorDetails,
          found,
          requested,
          missing,
        });
        
        // Show detailed error message
        if (action === 'delete' && found !== undefined && requested !== undefined) {
          toast.error(
            `${errorMessage}${errorDetails ? ` ${errorDetails}` : ''}`,
            {
              description: `Found ${found} of ${requested} contacts. ${missing || 0} contact(s) could not be found or are unauthorized.`,
              duration: 5000,
            }
          );
        } else {
          toast.error(errorMessage + (errorDetails ? `: ${errorDetails}` : ''));
        }
      }
    } catch (error) {
      // Improved error logging with proper serialization
      const errorDetails = error instanceof Error 
        ? {
            message: error.message,
            name: error.name,
            stack: error.stack,
          }
        : { error: String(error) };
      
      console.error('[Bulk Action] Error:', JSON.stringify(errorDetails, null, 2));
      console.error('[Bulk Action] Raw error:', error);
      
      toast.error(
        error instanceof Error 
          ? error.message 
          : 'Failed to perform bulk action. Please check the console for details.'
      );
    } finally {
      setBulkActionLoading(false);
    }
  }

  async function handleDeleteContact(contactId: string) {
    if (!confirm('Are you sure you want to delete this contact?')) return;

    try {
      const response = await fetch(`/api/contacts/${contactId}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        toast.success('Contact deleted');
        // Invalidate contacts queries to refetch data
        queryClient.invalidateQueries({ queryKey: ['contacts'] });
      } else {
        let errorMessage = 'Failed to delete contact';
        try {
          const data = await response.json();
          errorMessage = data.error || errorMessage;
        } catch {
          // If JSON parsing fails, use default message
        }
        
        console.error('[Delete Contact] API error:', {
          status: response.status,
          statusText: response.statusText,
          error: errorMessage,
          contactId,
        });
        
        toast.error(errorMessage);
      }
    } catch (error) {
      console.error('[Delete Contact] Error:', {
        error: error instanceof Error ? error.message : String(error),
        contactId,
      });
      toast.error('Failed to delete contact. Please try again.');
    }
  }

  // Memoize expensive computations
  const allSelected = useMemo(
    () => contacts.length > 0 && selectedIds.size === contacts.length,
    [contacts.length, selectedIds.size]
  );
  const someSelected = useMemo(
    () => selectedIds.size > 0 && selectedIds.size < contacts.length,
    [selectedIds.size, contacts.length]
  );
  const showBulkActions = useMemo(
    () => selectedIds.size > 0,
    [selectedIds.size]
  );
  const showSelectAllBanner = useMemo(
    () => allSelected && !selectAllPages && contacts.length > 0,
    [allSelected, selectAllPages, contacts.length]
  );

  return (
    <>
      {/* Select All Pages Banner */}
      {showSelectAllBanner && (
        <div className="bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              <span className="text-sm text-blue-900 dark:text-blue-100">
                All {contacts.length} contacts on this page are selected.
              </span>
            </div>
            <Button
              variant="link"
              size="sm"
              onClick={handleSelectAllPages}
              disabled={loadingAllIds}
              className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
            >
              {loadingAllIds ? 'Loading...' : 'Select all contacts across all pages'}
            </Button>
          </div>
        </div>
      )}

      {/* All Pages Selected Banner */}
      {selectAllPages && (
        <div className="bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg p-4 mb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
              <span className="text-sm font-medium text-green-900 dark:text-green-100">
                All {totalContactsCount} contacts across all pages are selected.
              </span>
            </div>
            <Button
              variant="link"
              size="sm"
              onClick={handleDeselectAllPages}
              className="text-green-600 dark:text-green-400 hover:text-green-700 dark:hover:text-green-300"
            >
              Clear selection
            </Button>
          </div>
        </div>
      )}

      {/* Bulk Actions Toolbar */}
      {showBulkActions && (
        <div className="bg-primary/10 border border-primary/20 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-medium">
                {selectAllPages ? `${totalContactsCount}` : selectedIds.size} contact(s) selected
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={selectAllPages ? handleDeselectAllPages : () => setSelectedIds(new Set())}
              >
                Clear selection
              </Button>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="default"
                size="sm"
                onClick={() => {
                  const contactIds = Array.from(selectedIds);
                  const params = new URLSearchParams();
                  params.set('contacts', contactIds.join(','));
                  router.push(`/campaigns/new?${params.toString()}`);
                }}
                className="bg-primary hover:bg-primary/90"
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Campaign
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  // CRITICAL: Read selection from MULTIPLE sources to ensure accuracy
                  // 1. Read from ref (most up-to-date, updated synchronously)
                  const refSelection = new Set(selectedIdsRef.current);
                  // 2. Read from state (may be stale due to React batching)
                  const stateSelection = new Set(selectedIds);
                  // 3. Read from DOM checkboxes (most reliable - actual UI state)
                  // CRITICAL: Exclude header checkbox by only looking in tbody and using data-contact-id
                  const domSelection = new Set<string>();
                  if (typeof document !== 'undefined') {
                    const tbody = document.querySelector('tbody');
                    if (tbody) {
                      // Method 1: Use data-contact-id attribute (most reliable)
                      const checkboxesWithId = tbody.querySelectorAll<HTMLInputElement>(
                        'input[type="checkbox"][data-contact-id]:checked'
                      );
                      checkboxesWithId.forEach((checkbox) => {
                        const contactId = checkbox.getAttribute('data-contact-id');
                        if (contactId) {
                          domSelection.add(contactId);
                        }
                      });
                      
                      // Method 2: Fallback - find from row data attribute
                      if (domSelection.size === 0) {
                        const checkedRows = tbody.querySelectorAll<HTMLTableRowElement>(
                          'tr[data-contact-id]'
                        );
                        checkedRows.forEach((row) => {
                          const checkbox = row.querySelector<HTMLInputElement>('input[type="checkbox"]:checked');
                          if (checkbox) {
                            const contactId = row.getAttribute('data-contact-id');
                            if (contactId) {
                              domSelection.add(contactId);
                            }
                          }
                        });
                      }
                      
                      // Method 3: Last resort - extract from link href
                      if (domSelection.size === 0) {
                        const checkboxes = tbody.querySelectorAll<HTMLInputElement>(
                          'input[type="checkbox"]:checked'
                        );
                        checkboxes.forEach((checkbox) => {
                          const row = checkbox.closest('tr');
                          if (row) {
                            const link = row.querySelector('a[href^="/contacts/"]');
                            if (link) {
                              const href = link.getAttribute('href');
                              const contactId = href?.replace('/contacts/', '').split('?')[0];
                              if (contactId && contactId.length > 0) {
                                domSelection.add(contactId);
                              }
                            }
                          }
                        });
                      }
                    }
                  }
                  
                  // CRITICAL: Determine final selection using priority logic
                  // Priority: DOM (most reliable) > Ref (synchronous) > State (may be stale)
                  const finalSelection = new Set<string>();
                  
                  // If DOM has exactly 1, trust it (most reliable - actual UI state)
                  if (domSelection.size === 1) {
                    domSelection.forEach(id => finalSelection.add(id));
                    console.log('[ContactsTable] ✅ Using DOM selection (1 contact) - most reliable');
                  }
                  // Else if ref has exactly 1, use it (updated synchronously)
                  else if (refSelection.size === 1) {
                    refSelection.forEach(id => finalSelection.add(id));
                    console.log('[ContactsTable] ✅ Using ref selection (1 contact) - synchronous');
                  }
                  // Else if state has exactly 1, use it
                  else if (stateSelection.size === 1) {
                    stateSelection.forEach(id => finalSelection.add(id));
                    console.log('[ContactsTable] ✅ Using state selection (1 contact)');
                  }
                  // If all sources agree, use any of them
                  else if (refSelection.size === stateSelection.size && 
                           refSelection.size === domSelection.size &&
                           Array.from(refSelection).every(id => stateSelection.has(id) && domSelection.has(id))) {
                    refSelection.forEach(id => finalSelection.add(id));
                    console.log('[ContactsTable] ✅ All sources agree, using ref selection');
                  }
                  // Otherwise, use the SMALLEST selection (most conservative - prevents analyzing all)
                  else {
                    const allSources = [
                      { name: 'ref', set: refSelection },
                      { name: 'state', set: stateSelection },
                      { name: 'dom', set: domSelection }
                    ].filter(s => s.set.size > 0); // Only consider non-empty sources
                    
                    if (allSources.length > 0) {
                      const smallest = allSources.reduce((a, b) => 
                        a.set.size <= b.set.size ? a : b
                      );
                      smallest.set.forEach(id => finalSelection.add(id));
                      console.log(`[ContactsTable] ⚠️ Sources disagree, using smallest (${smallest.name}: ${smallest.set.size} contacts)`);
                    }
                  }
                  
                  const selectionSize = finalSelection.size;
                  let selectionArray = Array.from(finalSelection);
                  
                  console.log('[ContactsTable] 🔍 Analyze button clicked - MULTI-SOURCE CHECK');
                  console.log('  Ref selection size:', refSelection.size, Array.from(refSelection));
                  console.log('  State selection size:', stateSelection.size, Array.from(stateSelection));
                  console.log('  DOM selection size:', domSelection.size, Array.from(domSelection));
                  console.log('  FINAL selection size:', selectionSize);
                  console.log('  FINAL selected IDs:', selectionArray);
                  console.log('  selectAllPages:', selectAllPages);
                  console.log('  allContactIds length:', allContactIds.length);
                  
                  // CRITICAL: If final selection is 1 but allContactIds suggests more, force clear it
                  // This handles the case where user manually changed from "select all" to single selection
                  if (finalSelection.size === 1 && allContactIds.length > 1) {
                    console.warn('[ContactsTable] 🚨 CRITICAL: Final selection is 1 but allContactIds has more!');
                    console.warn(`  Final selection: ${Array.from(finalSelection)}`);
                    console.warn(`  allContactIds: ${allContactIds.length} contacts`);
                    console.warn('  FORCING clear of allContactIds to prevent analyzing all contacts');
                    setSelectAllPages(false);
                    setAllContactIds([]);
                    setTotalContactsCount(0);
                    // Ensure ref and state match final selection
                    setSelectedIds(finalSelection);
                    selectedIdsRef.current = finalSelection;
                  }
                  
                  // CRITICAL: If final selection is 1, force clear all "select all" flags
                  if (selectionSize === 1) {
                    console.log('[ContactsTable] 🔒 SINGLE SELECTION DETECTED - Clearing all flags');
                    setSelectAllPages(false);
                    setAllContactIds([]);
                    setTotalContactsCount(0);
                    // Update ref and state to match
                    setSelectedIds(finalSelection);
                    selectedIdsRef.current = finalSelection;
                  }
                  
                  // ABSOLUTE SAFETY: If finalSelection is 1, ensure we ONLY send that 1 contact
                  // This is a hard stop - no exceptions, regardless of any flags or arrays
                  if (finalSelection.size === 1) {
                    const singleId = Array.from(finalSelection)[0];
                    console.log('[ContactsTable] 🔒 HARD LIMIT: Final selection is 1, forcing to send only that contact');
                    console.log(`  Contact ID: ${singleId}`);
                    // Override selectionArray to ensure only 1 contact is sent
                    selectionArray = [singleId];
                  }
                  
                  // Safety check: If only 1 is selected but flags suggest more, warn user
                  if (selectionSize === 1 && (selectAllPages || allContactIds.length > 1)) {
                    console.warn('[ContactsTable] 🚨 WARNING: Only 1 selected but flags suggest more!');
                    const confirmed = window.confirm(
                      `You have selected 1 contact. However, the system detected that "select all pages" might be active. ` +
                      `Do you want to analyze only the selected contact, or cancel to review your selection?`
                    );
                    if (!confirmed) {
                      console.log('[ContactsTable] User cancelled analysis');
                      return;
                    }
                    // Force clear the flags
                    setSelectAllPages(false);
                    setAllContactIds([]);
                    setTotalContactsCount(0);
                  }
                  
                  // CRITICAL: Pass selection directly to handleBulkAction to bypass all state checks
                  // This ensures we use the exact selection we just determined
                  // FINAL VALIDATION: Ensure selectionArray matches finalSelection
                  if (selectionArray.length !== finalSelection.size) {
                    console.error('[ContactsTable] 🚨 CRITICAL: selectionArray length mismatch!');
                    console.error(`  finalSelection.size: ${finalSelection.size}`);
                    console.error(`  selectionArray.length: ${selectionArray.length}`);
                    selectionArray = Array.from(finalSelection);
                  }
                  
                  await handleBulkAction('analyze', undefined, selectionArray);
                }}
                disabled={bulkActionLoading}
                className="bg-purple-50 hover:bg-purple-100 dark:bg-purple-950/20 dark:hover:bg-purple-950/40"
              >
                <Sparkles className="h-4 w-4 mr-2" />
                Analyze
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  const contactIds = Array.from(selectedIds);
                  if (contactIds.length === 0) {
                    toast.error('Please select at least one contact');
                    return;
                  }
                  
                  setBulkActionLoading(true);
                  try {
                    // Update best times for all selected contacts
                    const results = await Promise.allSettled(
                      contactIds.map((contactId) =>
                        fetch(`/api/contacts/${contactId}/update-best-times`, {
                          method: 'POST',
                        }).then((res) => res.json())
                      )
                    );
                    
                    const successful = results.filter((r) => r.status === 'fulfilled' && r.value.success).length;
                    const failed = results.length - successful;
                    
                    if (successful > 0) {
                      toast.success(
                        `Updated best times for ${successful} contact(s)${failed > 0 ? ` (${failed} failed)` : ''}`
                      );
                      queryClient.invalidateQueries({ queryKey: ['contacts'] });
                      router.refresh();
                    } else {
                      toast.error('Failed to update best times for selected contacts');
                    }
                  } catch (error) {
                    console.error('[UpdateBestTimes] Bulk error:', error);
                    toast.error('Failed to update best times');
                  } finally {
                    setBulkActionLoading(false);
                  }
                }}
                disabled={bulkActionLoading}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Update Best Times
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" disabled={bulkActionLoading}>
                    <Tag className="h-4 w-4 mr-2" />
                    Add Tags
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  <DropdownMenuLabel>Select tags to add</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {tags.map((tag) => (
                    <DropdownMenuItem
                      key={tag.id}
                      onClick={() => handleBulkAction('addTags', { tags: [tag.name] })}
                    >
                      <div
                        className="w-3 h-3 rounded-full mr-2"
                        style={{ backgroundColor: tag.color }}
                      />
                      {tag.name}
                    </DropdownMenuItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>

              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" disabled={bulkActionLoading}>
                    <MoveRight className="h-4 w-4 mr-2" />
                    Move to Stage
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel>Select stage</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {pipelines.map((pipeline) => (
                    <div key={pipeline.id}>
                      <DropdownMenuLabel className="text-xs text-muted-foreground">
                        {pipeline.name}
                      </DropdownMenuLabel>
                      {pipeline.stages.map((stage) => (
                        <DropdownMenuItem
                          key={stage.id}
                          onClick={() => handleBulkAction('moveToStage', { stageId: stage.id })}
                        >
                          <div
                            className="w-3 h-3 rounded-full mr-2"
                            style={{ backgroundColor: stage.color }}
                          />
                          {stage.name}
                        </DropdownMenuItem>
                      ))}
                    </div>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>

              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  if (selectedIds.size === 0) {
                    toast.error('Please select at least one contact');
                    return;
                  }
                  setBulkMessageOpen(true);
                }}
                disabled={bulkActionLoading}
              >
                <MessageSquare className="h-4 w-4 mr-2" />
                Send Message
              </Button>

              <Button
                variant="destructive"
                size="sm"
                onClick={() => setDeleteDialogOpen(true)}
                disabled={bulkActionLoading}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">
                <Checkbox
                  checked={allSelected}
                  onCheckedChange={handleSelectAll}
                  aria-label="Select all"
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  ref={(el: any) => {
                    if (el) {
                      el.indeterminate = someSelected;
                    }
                  }}
                />
              </TableHead>
              <TableHead>
                <Button
                  variant="ghost"
                  size="sm"
                  className="-ml-3 h-8"
                  onClick={() => handleSort('name')}
                  disabled={isPending}
                >
                  Contact
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>Page</TableHead>
              <TableHead>Platforms</TableHead>
              <TableHead>
                <Button
                  variant="ghost"
                  size="sm"
                  className="-ml-3 h-8"
                  onClick={() => handleSort('score')}
                  disabled={isPending}
                >
                  Score
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>Stage</TableHead>
              <TableHead>Tags</TableHead>
              <TableHead>
                <Button
                  variant="ghost"
                  size="sm"
                  className="-ml-3 h-8"
                  onClick={() => handleSort('date')}
                  disabled={isPending}
                >
                  Added
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead className="w-12"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {contacts.map((contact) => (
              <ContactRow
                key={contact.id}
                contact={contact}
                isSelected={selectedIds.has(contact.id)}
                onSelect={handleSelectOne}
                onDelete={handleDeleteContact}
              />
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete {selectedIds.size} contact(s) and all associated data.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                handleBulkAction('delete');
                setDeleteDialogOpen(false);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <BulkMessageDialog
        open={bulkMessageOpen}
        onOpenChange={setBulkMessageOpen}
        contactIds={Array.from(selectedIds)}
        onSuccess={() => {
          setSelectedIds(new Set());
          queryClient.invalidateQueries({ queryKey: ['contacts'] });
        }}
      />
    </>
  );
}

