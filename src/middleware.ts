import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

// Safe logger import with fallback
let logger: any = null;
try {
  const loggerModule = require('@/lib/utils/logger');
  logger = loggerModule.logger;
} catch (e) {
  // Logger not available - use console as fallback
  logger = {
    debug: () => {},
    info: () => {},
    warn: (msg: string, ctx?: any) => console.warn(msg, ctx),
    error: (msg: string, err?: any, ctx?: any) => console.error(msg, err, ctx),
  };
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow API routes to bypass middleware completely to prevent crashes
  if (pathname.startsWith('/api/')) {
    try {
      if (logger) logger.debug('Allowing API route', { path: pathname });
    } catch (e) {
      // Ignore logger errors
    }
    return NextResponse.next({ request });
  }

  try {
    let supabaseResponse = NextResponse.next({
      request,
    });

    // Check for required environment variables
    if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) {
      // If Supabase env vars are missing, allow the request through
      // API routes will handle their own auth
      return NextResponse.next({ request });
    }

    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
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
    // This call automatically refreshes expired tokens if a valid refresh token exists
    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser();

    // Log token expiration errors for debugging (but don't block the request yet)
    if (authError && authError.message.includes('expired')) {
      try {
        logger.warn('Token expired in middleware', {
          error: authError.message,
          path: pathname,
        });
      } catch (e) {
        // Ignore logger errors
      }
    }

    try {
      logger.debug('Middleware processing request', {
        path: pathname,
        method: request.method,
        userId: user?.id,
        userEmail: user?.email || 'none',
        ip: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || undefined,
      });
    } catch (e) {
      // Ignore logger errors
    }

    const isAuthPage = pathname.startsWith('/login') || pathname.startsWith('/register');

    // Redirect logged-in users away from auth pages
    if (isAuthPage && user) {
      try {
        logger.info('Redirecting logged-in user to dashboard', {
          path: pathname,
          userId: user.id,
          userEmail: user.email,
        });
      } catch (e) {
        // Ignore logger errors
      }
      const url = request.nextUrl.clone();
      url.pathname = '/dashboard';
      return NextResponse.redirect(url);
    }

    // Redirect logged-out users to login
    if (!isAuthPage && !user) {
      try {
        logger.info('Redirecting logged-out user to login', {
          path: pathname,
        });
      } catch (e) {
        // Ignore logger errors
      }
      const url = request.nextUrl.clone();
      url.pathname = '/login';
      return NextResponse.redirect(url);
    }

    // Note: Page access check for developers is handled in API routes and page components
    // Middleware runs in Edge Runtime which doesn't support Prisma
    // Developer page access is enforced at the page/API route level instead

    try {
      logger.debug('Request allowed', {
        path: pathname,
        userId: user?.id,
      });
    } catch (e) {
      // Ignore logger errors
    }
    return supabaseResponse;
  } catch (error) {
    // If middleware fails, allow the request through
    // This prevents middleware crashes from blocking all requests
    console.error('[Middleware] Error in middleware, allowing request through:', error);
    return NextResponse.next({ request });
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api/ (ALL API routes bypass middleware)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api/|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};

