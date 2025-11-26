import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  // Validate environment variables
  if (!supabaseUrl || !supabaseAnonKey) {
    console.error('[Middleware] ❌ Supabase environment variables missing');
    console.error('[Middleware] NEXT_PUBLIC_SUPABASE_URL:', supabaseUrl ? '✅ Set' : '❌ Missing');
    console.error('[Middleware] NEXT_PUBLIC_SUPABASE_ANON_KEY:', supabaseAnonKey ? '✅ Set' : '❌ Missing');
    
    // Allow request to continue but log error
    // This prevents middleware from crashing the entire app
    return NextResponse.next({ request });
  }

  let supabaseResponse = NextResponse.next({
    request,
  });

  try {
    const supabase = createServerClient(
      supabaseUrl,
      supabaseAnonKey,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          supabaseResponse = NextResponse.next({
            request,
          });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // IMPORTANT: DO NOT REMOVE auth.getUser()
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;

  console.log('[Middleware] 🔍 Request:', pathname, 'User:', user?.email || 'none');

  // Allow API routes to handle their own authentication
  if (pathname.startsWith('/api/')) {
    console.log('[Middleware] ✅ Allowing API route');
    return supabaseResponse;
  }

  const isAuthPage = pathname.startsWith('/login') || pathname.startsWith('/register');

  // Redirect logged-in users away from auth pages
  if (isAuthPage && user) {
    console.log('[Middleware] ↪️ Redirecting logged-in user to dashboard');
    const url = request.nextUrl.clone();
    url.pathname = '/dashboard';
    return NextResponse.redirect(url);
  }

  // Redirect logged-out users to login
  if (!isAuthPage && !user) {
    console.log('[Middleware] ↪️ Redirecting logged-out user to login');
    const url = request.nextUrl.clone();
    url.pathname = '/login';
    return NextResponse.redirect(url);
  }

  // Note: Page access check for developers is handled in API routes and page components
  // Middleware runs in Edge Runtime which doesn't support Prisma
  // Developer page access is enforced at the page/API route level instead

    console.log('[Middleware] ✅ Allowing request');
    return supabaseResponse;
  } catch (error) {
    console.error('[Middleware] ❌ Error in middleware:', error);
    // Return response even on error to prevent app crash
    return NextResponse.next({ request });
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api/auth (auth endpoints should not be protected by middleware)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api/auth|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};

