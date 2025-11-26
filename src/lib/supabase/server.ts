import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

export async function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  // Validate environment variables
  if (!supabaseUrl) {
    console.error('[Supabase Server] ❌ NEXT_PUBLIC_SUPABASE_URL is missing');
    throw new Error('Supabase URL is not configured. Please set NEXT_PUBLIC_SUPABASE_URL environment variable.');
  }

  if (!supabaseAnonKey) {
    console.error('[Supabase Server] ❌ NEXT_PUBLIC_SUPABASE_ANON_KEY is missing');
    throw new Error('Supabase Anon Key is not configured. Please set NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable.');
  }

  // Validate URL format
  try {
    new URL(supabaseUrl);
  } catch (error) {
    console.error('[Supabase Server] ❌ Invalid Supabase URL format:', supabaseUrl);
    throw new Error(`Invalid Supabase URL format: ${supabaseUrl}`);
  }

  const cookieStore = await cookies();

  try {
    const client = createServerClient(
      supabaseUrl,
      supabaseAnonKey,
      {
        cookies: {
          getAll() {
            return cookieStore.getAll();
          },
          setAll(cookiesToSet) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              );
            } catch {
              // The `setAll` method was called from a Server Component.
              // This can be ignored if you have middleware refreshing
              // user sessions.
            }
          },
        },
      }
    );
    return client;
  } catch (error) {
    console.error('[Supabase Server] ❌ Failed to create client:', error);
    throw new Error(`Failed to create Supabase client: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

