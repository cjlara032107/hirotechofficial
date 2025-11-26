'use client';

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { toast } from 'sonner';

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

    const handleAnalysisComplete = (event: Event) => {
      const customEvent = event as CustomEvent;
      const { jobId, analyzedContacts, failedContacts } = customEvent.detail || {};
      
      // Refresh the page data by calling router.refresh()
      // This will re-fetch server components without losing client state
      console.log('[Contact Detail Refresh] Analysis completed, refreshing page data...', { jobId, analyzedContacts, failedContacts });
      
      // Add a small delay to ensure database updates have propagated
      setTimeout(() => {
        router.refresh();
        toast.info('Contact details updated', {
          description: 'The contact information has been refreshed with the latest analysis results.',
          duration: 3000,
        });
      }, 1000); // 1 second delay to ensure DB updates are committed
    };

    // Listen for custom event when analysis completes
    window.addEventListener('analysisCompleted', handleAnalysisComplete);

    return () => {
      window.removeEventListener('analysisCompleted', handleAnalysisComplete);
    };
  }, [pathname, router]);

  return null; // This component doesn't render anything
}

