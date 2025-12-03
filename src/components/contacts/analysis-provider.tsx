'use client';

import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { AnalysisIndicator } from './analysis-indicator';

interface AnalysisContextType {
  activeJobId: string | null;
  setActiveJobId: (jobId: string | null) => void;
}

const AnalysisContext = createContext<AnalysisContextType | undefined>(undefined);

export function useAnalysis() {
  const context = useContext(AnalysisContext);
  if (!context) {
    throw new Error('useAnalysis must be used within AnalysisProvider');
  }
  return context;
}

interface AnalysisProviderProps {
  children: ReactNode;
}

export function AnalysisProvider({ children }: AnalysisProviderProps) {
  // Initialize state from sessionStorage if available (client-side only)
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState(false);

  // Load from sessionStorage after mount to avoid SSR issues
  useEffect(() => {
    setIsMounted(true);
    if (typeof window !== 'undefined') {
      const storedJobId = sessionStorage.getItem('activeAnalysisJobId');
      if (storedJobId) {
        setActiveJobId(storedJobId);
      }
    }
  }, []);

  useEffect(() => {
    // Listen for new analysis jobs
    if (typeof window !== 'undefined') {
      const handleAnalysisStarted = (event: CustomEvent) => {
        const { jobId } = event.detail;
        setActiveJobId(jobId);
        sessionStorage.setItem('activeAnalysisJobId', jobId);
      };

      window.addEventListener('analysisStarted', handleAnalysisStarted as EventListener);

      return () => {
        window.removeEventListener('analysisStarted', handleAnalysisStarted as EventListener);
      };
    }
  }, []);

  const handleJobComplete = () => {
    setActiveJobId(null);
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem('activeAnalysisJobId');
    }
  };

  const handleDismiss = () => {
    setActiveJobId(null);
    if (typeof window !== 'undefined') {
      sessionStorage.removeItem('activeAnalysisJobId');
    }
  };

  return (
    <AnalysisContext.Provider value={{ activeJobId, setActiveJobId }}>
      {children}
      {isMounted && activeJobId && (
        <AnalysisIndicator
          jobId={activeJobId}
          onComplete={handleJobComplete}
          onDismiss={handleDismiss}
        />
      )}
    </AnalysisContext.Provider>
  );
}


