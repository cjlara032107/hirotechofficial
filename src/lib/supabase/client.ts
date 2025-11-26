import { createBrowserClient } from '@supabase/ssr';

export function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  // Validate environment variables
  if (!supabaseUrl) {
    console.error('[Supabase Client] ❌ NEXT_PUBLIC_SUPABASE_URL is missing');
    throw new Error('Supabase URL is not configured. Please set NEXT_PUBLIC_SUPABASE_URL environment variable.');
  }

  if (!supabaseAnonKey) {
    console.error('[Supabase Client] ❌ NEXT_PUBLIC_SUPABASE_ANON_KEY is missing');
    throw new Error('Supabase Anon Key is not configured. Please set NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable.');
  }

  // Validate URL format
  try {
    new URL(supabaseUrl);
  } catch (error) {
    console.error('[Supabase Client] ❌ Invalid Supabase URL format:', supabaseUrl);
    throw new Error(`Invalid Supabase URL format: ${supabaseUrl}`);
  }

  try {
    const client = createBrowserClient(supabaseUrl, supabaseAnonKey);
    console.log('[Supabase Client] ✅ Client created successfully');
    return client;
  } catch (error) {
    console.error('[Supabase Client] ❌ Failed to create client:', error);
    throw new Error(`Failed to create Supabase client: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

