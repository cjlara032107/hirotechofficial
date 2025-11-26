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
  const [activeJobId, setActiveJobId] = useState<string | null>(null);

  useEffect(() => {
    // Check for active job in session storage on mount
    if (typeof window !== 'undefined') {
      const storedJobId = sessionStorage.getItem('activeAnalysisJobId');
      if (storedJobId) {
        setActiveJobId(storedJobId);
      }

      // Listen for new analysis jobs
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
      {activeJobId && (
        <AnalysisIndicator
          jobId={activeJobId}
          onComplete={handleJobComplete}
          onDismiss={handleDismiss}
        />
      )}
    </AnalysisContext.Provider>
  );
}


