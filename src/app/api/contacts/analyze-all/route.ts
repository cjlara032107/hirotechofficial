import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { analyzeExistingContacts } from '@/lib/ai/analyze-existing-contacts';

export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const organizationId = session.user.organizationId;
    const body = await req.json();
    const { limit = 100, skipIfHasContext = true } = body;

    const result = await analyzeExistingContacts({
      organizationId,
      limit,
      skipIfHasContext,
    });

    return NextResponse.json(result);
  } catch (error: unknown) {
    console.error('[API] Analyze contacts error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Failed to analyze contacts';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

