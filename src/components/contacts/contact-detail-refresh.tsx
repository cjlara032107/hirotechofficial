'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';

interface ContactDetailRefreshProps {
  contactId: string;
}

/**
 * Client component that listens for analysis completion events
 * and refreshes the page to show updated contact details
 */
export function ContactDetailRefresh({ contactId }: ContactDetailRefreshProps) {
  const router = useRouter();

  useEffect(() => {
    const handleAnalysisCompleted = (event: CustomEvent) => {
      const { jobId, status } = event.detail;
      console.log(`[ContactDetailRefresh] Received analysisCompleted event for job ${jobId} with status ${status}`);
      
      // Provide a small delay to allow database updates to propagate
      setTimeout(() => {
        console.log(`[ContactDetailRefresh] Refreshing page for contact ${contactId}`);
        router.refresh(); // This will re-fetch data for all server components on the page
        toast.info('Contact data refreshed', {
          description: 'The contact details have been updated with the latest analysis results.',
          duration: 2000,
        });
      }, 1000); // 1 second delay
    };

    window.addEventListener('analysisCompleted', handleAnalysisCompleted as EventListener);

    return () => {
      window.removeEventListener('analysisCompleted', handleAnalysisCompleted as EventListener);
    };
  }, [contactId, router]);

  return null; // This component doesn't render anything itself
}

