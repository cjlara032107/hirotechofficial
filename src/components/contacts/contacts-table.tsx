'use client';

import { useState, useTransition } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
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
} from 'lucide-react';
import { toast } from 'sonner';
import { useQueryState } from 'nuqs';

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
}

export function ContactsTable({ contacts, tags, pipelines }: ContactsTableProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isPending, startTransition] = useTransition();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectAllPages, setSelectAllPages] = useState(false);
  const [totalContactsCount, setTotalContactsCount] = useState(0);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const [loadingAllIds, setLoadingAllIds] = useState(false);

  const [sortBy, setSortBy] = useQueryState('sortBy', {
    defaultValue: 'date',
    shallow: false,
  });
  const [sortOrder, setSortOrder] = useQueryState('sortOrder', {
    defaultValue: 'desc',
    shallow: false,
  });

  function handleSort(column: 'name' | 'score' | 'date') {
    startTransition(() => {
      if (sortBy === column) {
        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
      } else {
        setSortBy(column);
        setSortOrder('asc');
      }
      router.refresh();
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
      setSelectedIds(new Set(ids));
      setSelectAllPages(true);
    }
  }

  function handleDeselectAllPages() {
    setSelectedIds(new Set());
    setSelectAllPages(false);
    setTotalContactsCount(0);
  }

  function handleSelectAll(checked: boolean) {
    if (checked) {
      setSelectedIds(new Set(contacts.map((c) => c.id)));
      setSelectAllPages(false);
    } else {
      setSelectedIds(new Set());
      setSelectAllPages(false);
    }
  }

  function handleSelectOne(id: string, checked: boolean) {
    const newSelected = new Set(selectedIds);
    if (checked) {
      newSelected.add(id);
    } else {
      newSelected.delete(id);
    }
    setSelectedIds(newSelected);
    
    // Reset "select all pages" if user manually deselects
    if (selectAllPages && !checked) {
      setSelectAllPages(false);
      setTotalContactsCount(0);
    }
  }

  async function handleBulkAction(
    action: string,
    data?: { tags?: string[]; stageId?: string }
  ) {
    if (selectedIds.size === 0) return;

    try {
      setBulkActionLoading(true);
      const response = await fetch('/api/contacts/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          contactIds: Array.from(selectedIds),
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
        toast.success(
          `Successfully ${action === 'delete' ? 'deleted' : 'updated'} ${
            selectedIds.size
          } contact(s)`
        );
        setSelectedIds(new Set());
        router.refresh();
      } else {
        toast.error(result.error || 'Failed to perform action');
      }
    } catch (error: unknown) {
      console.error('Bulk action error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to perform bulk action';
      toast.error(errorMessage);
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
        router.refresh();
      } else {
        toast.error('Failed to delete contact');
      }
    } catch (_error) {
      toast.error('Failed to delete contact');
    }
  }

  const allSelected = contacts.length > 0 && selectedIds.size === contacts.length;
  const someSelected = selectedIds.size > 0 && selectedIds.size < contacts.length;
  const showBulkActions = selectedIds.size > 0;
  const showSelectAllBanner = allSelected && !selectAllPages && contacts.length > 0;

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
                  ref={(el) => {
                    if (el) {
                      // TypeScript doesn't know about the indeterminate property
                      // eslint-disable-next-line @typescript-eslint/no-explicit-any
                      (el as any).indeterminate = someSelected;
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
              <TableRow
                key={contact.id}
                data-state={selectedIds.has(contact.id) ? 'selected' : undefined}
              >
                <TableCell>
                  <Checkbox
                    checked={selectedIds.has(contact.id)}
                    onCheckedChange={(checked) =>
                      handleSelectOne(contact.id, checked as boolean)
                    }
                    aria-label={`Select ${contact.firstName}`}
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
                      <DropdownMenuItem
                        className="text-destructive"
                        onClick={() => handleDeleteContact(contact.id)}
                      >
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
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
    </>
  );
}

