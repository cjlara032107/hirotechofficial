'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { Sparkles } from 'lucide-react';

export function AnalyzeAllButton() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  async function handleAnalyzeAll() {
    setIsAnalyzing(true);
    try {
      const res = await fetch('/api/contacts/analyze-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit: 100, skipIfHasContext: true }),
      });
      
      if (!res.ok) {
        throw new Error('Failed to analyze contacts');
      }
      
      const result = await res.json();
      toast.success(`Analyzed ${result.successCount} contacts successfully`);
    } catch (error) {
      toast.error('Failed to analyze contacts');
      console.error('Analysis error:', error);
    } finally {
      setIsAnalyzing(false);
    }
  }

  return (
    <Button onClick={handleAnalyzeAll} disabled={isAnalyzing} variant="outline">
      <Sparkles className="h-4 w-4 mr-2" />
      {isAnalyzing ? 'Analyzing...' : 'AI Analyze All'}
    </Button>
  );
}

