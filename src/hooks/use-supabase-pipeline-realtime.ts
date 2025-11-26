import { useEffect, useState } from 'react';
import { createClient } from '@/lib/supabase/client';
import { RealtimePostgresChangesPayload } from '@supabase/supabase-js';

interface PipelineUpdate {
  type: 'contact_changed' | 'pipeline_changed' | 'stage_changed' | 'automation_changed';
  timestamp: number;
  pipelineId?: string; // For filtering
}

interface Pipeline {
  id: string;
  [key: string]: unknown;
}

interface PipelineStage {
  id: string;
  pipelineId: string;
  [key: string]: unknown;
}

interface PipelineAutomation {
  id: string;
  pipelineId: string;
  [key: string]: unknown;
}

interface Contact {
  id: string;
  pipelineId?: string;
  [key: string]: unknown;
}

/**
 * Supabase Realtime hook for pipeline updates
 * Listens to Pipeline, PipelineStage, PipelineAutomation, and Contact table changes
 * NO POLLING - Event-driven, instant updates
 */
export function useSupabasePipelineRealtime(pipelineId: string) {
  const [updateSignal, setUpdateSignal] = useState<PipelineUpdate | null>(null);
  const [isSubscribed, setIsSubscribed] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    const supabase = createClient();

    console.log(`[Supabase Realtime] Subscribing to pipeline ${pipelineId}...`);

    let subscribedChannels = 0;
    const totalChannels = 4; // Pipeline, PipelineStage, PipelineAutomation, Contact
    let hasError = false;

    const updateSubscriptionStatus = (status: string) => {
      if (status === 'SUBSCRIBED') {
        subscribedChannels++;
        if (subscribedChannels === totalChannels) {
          console.log('[Supabase Realtime] Successfully subscribed to all pipeline updates');
          setIsSubscribed(true);
          setError(null);
        }
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        if (!hasError) {
          hasError = true;
          console.error(`[Supabase Realtime] Subscription error: ${status}`);
          setError(new Error(`Failed to subscribe to realtime updates: ${status}`));
          setIsSubscribed(false);
        }
      }
    };

    // Subscribe to Pipeline changes (watch all, filter by id in handler)
    const pipelineChannel = supabase
      .channel(`pipeline-${pipelineId}-pipeline`)
      .on(
        'postgres_changes',
        {
          event: '*', // INSERT, UPDATE, DELETE
          schema: 'public',
          table: 'Pipeline'
        },
        (payload) => {
          const changedPipelineId = (payload.new as { id?: string })?.id || (payload.old as { id?: string })?.id;
          if (changedPipelineId === pipelineId) {
            console.log('[Supabase Realtime] Pipeline changed:', payload.eventType);
            setUpdateSignal({
              type: 'pipeline_changed',
              timestamp: Date.now(),
              pipelineId: changedPipelineId
            });
          }
        }
      )
      .subscribe(updateSubscriptionStatus);

    // Subscribe to PipelineStage changes (watch all, filter by pipelineId in handler)
    const stageChannel = supabase
      .channel(`pipeline-${pipelineId}-stages`)
      .on(
        'postgres_changes',
        {
          event: '*', // INSERT, UPDATE, DELETE
          schema: 'public',
          table: 'PipelineStage'
        },
        (payload) => {
          const changedPipelineId = (payload.new as { pipelineId?: string })?.pipelineId || (payload.old as { pipelineId?: string })?.pipelineId;
          if (changedPipelineId === pipelineId) {
            console.log('[Supabase Realtime] Stage changed:', payload.eventType);
            setUpdateSignal({
              type: 'stage_changed',
              timestamp: Date.now(),
              pipelineId: changedPipelineId
            });
          }
        }
      )
      .subscribe(updateSubscriptionStatus);

    // Subscribe to PipelineAutomation changes (watch all, filter by pipelineId in handler)
    const automationChannel = supabase
      .channel(`pipeline-${pipelineId}-automations`)
      .on(
        'postgres_changes',
        {
          event: '*', // INSERT, UPDATE, DELETE
          schema: 'public',
          table: 'PipelineAutomation'
        },
        (payload) => {
          const changedPipelineId = (payload.new as { pipelineId?: string })?.pipelineId || (payload.old as { pipelineId?: string })?.pipelineId;
          if (changedPipelineId === pipelineId) {
            console.log('[Supabase Realtime] Automation changed:', payload.eventType);
            setUpdateSignal({
              type: 'automation_changed',
              timestamp: Date.now(),
              pipelineId: changedPipelineId
            });
          }
        }
      )
      .subscribe(updateSubscriptionStatus);

    // Subscribe to Contact changes for this pipeline (filtered at database level)
    const contactChannel = supabase
      .channel(`pipeline-${pipelineId}-contacts`)
      .on(
        'postgres_changes',
        {
          event: '*', // INSERT, UPDATE, DELETE
          schema: 'public',
          table: 'Contact',
          filter: `pipelineId=eq.${pipelineId}`
        },
        (payload: RealtimePostgresChangesPayload<Contact>) => {
          console.log('[Supabase Realtime] Contact changed:', payload.eventType);
          setUpdateSignal({
            type: 'contact_changed',
            timestamp: Date.now(),
            pipelineId
          });
        }
      )
      .subscribe(updateSubscriptionStatus);

    // Cleanup on unmount
    return () => {
      console.log('[Supabase Realtime] Unsubscribing from pipeline updates...');
      supabase.removeChannel(pipelineChannel);
      supabase.removeChannel(stageChannel);
      supabase.removeChannel(automationChannel);
      supabase.removeChannel(contactChannel);
      setIsSubscribed(false);
      subscribedChannels = 0;
    };
  }, [pipelineId]); // Only re-subscribe if pipelineId changes (stable!)

  return { 
    updateSignal, 
    isSubscribed,
    error
  };
}

