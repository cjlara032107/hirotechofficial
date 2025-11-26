import { NextResponse } from 'next/server';

/**
 * Test endpoint to verify Supabase configuration
 * Visit: /api/test-supabase-config
 */
export async function GET() {
  try {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

    const config = {
      hasUrl: !!supabaseUrl,
      hasAnonKey: !!supabaseAnonKey,
      urlFormat: supabaseUrl ? (supabaseUrl.startsWith('https://') ? 'valid' : 'invalid') : 'missing',
      urlDomain: supabaseUrl ? new URL(supabaseUrl).hostname : null,
      anonKeyLength: supabaseAnonKey?.length || 0,
      // Don't expose full keys in response
      urlPreview: supabaseUrl ? `${supabaseUrl.substring(0, 20)}...` : null,
      anonKeyPreview: supabaseAnonKey ? `${supabaseAnonKey.substring(0, 20)}...` : null,
    };

    return NextResponse.json({
      status: config.hasUrl && config.hasAnonKey ? 'OK' : 'ERROR',
      config,
      message: config.hasUrl && config.hasAnonKey 
        ? 'Supabase configuration looks good!'
        : 'Supabase configuration is missing or incomplete',
      errors: [
        !config.hasUrl && 'NEXT_PUBLIC_SUPABASE_URL is missing',
        !config.hasAnonKey && 'NEXT_PUBLIC_SUPABASE_ANON_KEY is missing',
        config.urlFormat === 'invalid' && 'NEXT_PUBLIC_SUPABASE_URL format is invalid (should start with https://)',
      ].filter(Boolean),
    });
  } catch (error) {
    return NextResponse.json({
      status: 'ERROR',
      error: error instanceof Error ? error.message : 'Unknown error',
    }, { status: 500 });
  }
}

