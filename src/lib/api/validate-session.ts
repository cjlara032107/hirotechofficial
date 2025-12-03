import { NextResponse } from 'next/server';
import { auth } from '@/auth';

interface ValidatedSession {
  user: {
    id: string;
    organizationId: string;
    email?: string;
    name?: string;
    role?: string;
    [key: string]: any;
  };
}

/**
 * Validates session and returns error response if invalid
 * Use this in API routes to ensure session has required fields
 * Returns null if valid, or an error response if invalid
 */
export function validateSession(session: any): { error: NextResponse } | { session: ValidatedSession } {
  if (!session?.user) {
    return { error: NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) };
  }

  if (!session.user.organizationId) {
    return {
      error: NextResponse.json(
        { error: 'User organization not found. Please complete your profile.' },
        { status: 403 }
      ),
    };
  }

  if (!session.user.id) {
    return {
      error: NextResponse.json(
        { error: 'User ID not found. Please try logging in again.' },
        { status: 403 }
      ),
    };
  }

  return { session: session as ValidatedSession };
}

/**
 * Validates session with automatic token refresh handling
 * This function fetches the session and validates it in one call
 * Use this as the standard way to validate sessions in API routes
 * 
 * @returns Validated session or error response
 */
export async function requireAuth(): Promise<{ error: NextResponse } | { session: ValidatedSession }> {
  try {
    const session = await auth();
    return validateSession(session);
  } catch (error) {
    console.error('[requireAuth] Error fetching session:', error);
    // If there's an error fetching the session (e.g., token expired, invalid token),
    // return 401 Unauthorized
    return {
      error: NextResponse.json(
        { error: 'Session expired or invalid. Please log in again.' },
        { status: 401 }
      ),
    };
  }
}

