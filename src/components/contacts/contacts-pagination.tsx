'use client';

import { useTransition } from 'react';
import { Button } from '@/components/ui/button';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';
import { useQueryState } from 'nuqs';

interface ContactsPaginationProps {
  currentPage: number;
  totalPages: number;
  totalContacts: number;
  limit: number;
  onPrefetchPage?: (page: number) => void;
}

export function ContactsPagination({
  currentPage,
  totalPages,
  totalContacts,
  limit,
  onPrefetchPage,
}: ContactsPaginationProps) {
  const [isPending, startTransition] = useTransition();
  const [, setPage] = useQueryState('page', {
    defaultValue: '1',
    shallow: true,
  });

  function handlePageChange(page: number) {
    startTransition(() => {
      setPage(page.toString());
    });
  }

  // Handle edge cases: 0 contacts or 1 contact
  if (totalContacts === 0) {
    return null; // Don't show pagination for empty state
  }

  // For 1 contact, show simple count without pagination controls
  if (totalContacts === 1 && totalPages === 1) {
    return (
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Showing 1 of 1 contact
        </p>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-between">
      <p className="text-sm text-muted-foreground">
        Showing {(currentPage - 1) * limit + 1} to{' '}
        {Math.min(currentPage * limit, totalContacts)} of {totalContacts} contacts
      </p>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="icon"
          onClick={() => handlePageChange(1)}
          disabled={currentPage === 1 || isPending}
          onMouseEnter={() => currentPage > 1 && onPrefetchPage?.(1)}
        >
          <ChevronsLeft className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
          disabled={currentPage === 1 || isPending}
          onMouseEnter={() => currentPage > 1 && onPrefetchPage?.(currentPage - 1)}
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="text-sm">
          Page {currentPage} of {totalPages}
        </span>
        <Button
          variant="outline"
          size="icon"
          onClick={() => handlePageChange(Math.min(totalPages, currentPage + 1))}
          disabled={currentPage === totalPages || isPending}
          onMouseEnter={() => currentPage < totalPages && onPrefetchPage?.(currentPage + 1)}
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          onClick={() => handlePageChange(totalPages)}
          disabled={currentPage === totalPages || isPending}
          onMouseEnter={() => currentPage < totalPages && onPrefetchPage?.(totalPages)}
        >
          <ChevronsRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

