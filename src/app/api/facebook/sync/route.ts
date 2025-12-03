import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { syncContacts } from '@/lib/facebook/sync-contacts';
import { validateUUID } from '@/lib/api/validate-uuid';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { facebookPageId } = body;

    if (!facebookPageId) {
      return NextResponse.json(
        { error: 'Missing facebookPageId' },
        { status: 400 }
      );
    }

    // Validate facebookPageId is valid UUID format
    if (typeof facebookPageId !== 'string') {
      return NextResponse.json(
        { error: 'facebookPageId must be a string' },
        { status: 400 }
      );
    }

    const trimmedFacebookPageId = facebookPageId.trim();
    if (trimmedFacebookPageId.length === 0) {
      return NextResponse.json(
        { error: 'facebookPageId cannot be empty' },
        { status: 400 }
      );
    }
    const uuidValidation = validateUUID(trimmedFacebookPageId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: uuidValidation.error.message },
        { status: uuidValidation.error.status }
      );
    }

    const result = await syncContacts(trimmedFacebookPageId);

    return NextResponse.json(result);
  } catch (error: unknown) {
    console.error('Sync error:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    return NextResponse.json(
      { error: 'Failed to sync contacts. Please try again.' },
      { status: 500 }
    );
  }
}

