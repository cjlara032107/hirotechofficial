import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { analyzeExistingContacts } from '@/lib/ai/analyze-existing-contacts';

export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const organizationId = (session.user as any).organizationId;
    const body = await req.json();
    const { limit = 100, skipIfHasContext = true } = body;

    const result = await analyzeExistingContacts({
      organizationId,
      limit,
      skipIfHasContext,
    });

    return NextResponse.json(result);
  } catch (error: any) {
    console.error('[API] Analyze contacts error:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to analyze contacts' },
      { status: 500 }
    );
  }
}

