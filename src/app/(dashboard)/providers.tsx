'use client';

import { SupabaseRealtimeProvider } from '@/contexts/supabase-realtime-context';

/**
 * Dashboard Providers
 * Note: Using Supabase for auth, not NextAuth
 * Supabase Realtime is used for team messaging and real-time updates
 */
export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SupabaseRealtimeProvider>
      {children}
    </SupabaseRealtimeProvider>
  );
}

