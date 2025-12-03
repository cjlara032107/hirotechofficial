'use client';

import { useTransition, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Input } from '@/components/ui/input';
import { Search } from 'lucide-react';

export function ContactsSearch() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isPending, startTransition] = useTransition();
  
  // Get search from URL params
  const urlSearch = searchParams.get('search') || '';
  const [search, setSearch] = useState(urlSearch);
  
  // Sync with URL params when they change
  useEffect(() => {
    const urlValue = searchParams.get('search') || '';
    setSearch(urlValue);
  }, [searchParams]);

  function handleSearch(value: string) {
    setSearch(value);
    startTransition(() => {
      const params = new URLSearchParams(searchParams.toString());
      if (value && value.trim()) {
        params.set('search', value);
      } else {
        params.delete('search');
      }
      // Reset to page 1 when searching
      params.set('page', '1');
      const newUrl = params.toString() ? `?${params.toString()}` : window.location.pathname;
      router.push(newUrl);
      router.refresh();
    });
  }

  return (
    <div className="relative flex-1">
      <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
      <Input
        placeholder="Search contacts..."
        className="pl-10"
        value={search}
        onChange={(e) => handleSearch(e.target.value)}
        disabled={isPending}
      />
    </div>
  );
}

