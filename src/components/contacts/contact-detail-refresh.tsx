'use client';

import { useEffect, useRef } from 'react';
import { useRouter, usePathname } from 'next/navigation';

/**
 * Client component that listens for analysis completion events
 * and refreshes the page if we're on a contact detail page
 */
export function ContactDetailRefresh() {
  const router = useRouter();
  const pathname = usePathname();
  const refreshTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    // Only listen if we're on a contact detail page
    const isContactDetailPage = pathname?.startsWith('/contacts/') && pathname !== '/contacts';
    
    if (!isContactDetailPage) {
      return;
    }

    const handleAnalysisComplete = (event?: CustomEvent) => {
      // Clear any pending refresh
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
        refreshTimeoutRef.current = null;
      }

      // Get contact ID from pathname
      const contactId = pathname?.split('/contacts/')[1]?.split('?')[0];
      
      console.log('[Contact Detail Refresh] Analysis completed, refreshing page data...', {
        contactId,
        pathname,
      });

      // Use a small delay to ensure the database has been updated
      refreshTimeoutRef.current = setTimeout(() => {
        // First, refresh the router cache to force re-fetch of server components
        router.refresh();
        
        // Also force a navigation to the same page with a cache-busting query param
        // This ensures we get fresh data even if router.refresh() doesn't work
        if (pathname && contactId) {
          const refreshUrl = `${pathname}?refresh=${Date.now()}`;
          router.push(refreshUrl);
          
          // After a short delay, remove the query param to clean up the URL
          setTimeout(() => {
            router.replace(pathname);
          }, 100);
        }
      }, 500); // 500ms delay to ensure DB write has completed
    };

    // Listen for custom event when analysis completes
    window.addEventListener('analysisCompleted', handleAnalysisComplete as EventListener);

    return () => {
      window.removeEventListener('analysisCompleted', handleAnalysisComplete as EventListener);
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
    };
  }, [pathname, router]);

  return null; // This component doesn't render anything
}

