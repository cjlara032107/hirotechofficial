'use client';

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';

/**
 * Client component that listens for analysis completion events
 * and refreshes the page if we're on a contact detail page
 */
export function ContactDetailRefresh() {
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    // Only listen if we're on a contact detail page
    const isContactDetailPage = pathname?.startsWith('/contacts/') && pathname !== '/contacts';
    
    if (!isContactDetailPage) {
      return;
    }

    const handleAnalysisComplete = () => {
      // Refresh the page data by calling router.refresh()
      // This will re-fetch server components without losing client state
      console.log('[Contact Detail Refresh] Analysis completed, refreshing page data...');
      router.refresh();
    };

    // Listen for custom event when analysis completes
    window.addEventListener('analysisCompleted', handleAnalysisComplete);

    return () => {
      window.removeEventListener('analysisCompleted', handleAnalysisComplete);
    };
  }, [pathname, router]);

  return null; // This component doesn't render anything
}

