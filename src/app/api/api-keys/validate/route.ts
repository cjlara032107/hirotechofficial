/**
 * API Key Validation Endpoint
 * 
 * Validates API keys by testing them against the actual API
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { validateAllApiKeys, validateApiKeyById } from '@/lib/ai/api-key-validator';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    if (session.user.role !== 'DEVELOPER') {
      return NextResponse.json(
        { error: 'Forbidden - Developer access required' },
        { status: 403 }
      );
    }

    const body = await request.json();
    const { keyId } = body;

    if (keyId) {
      // Validate single key
      const result = await validateApiKeyById(keyId);
      if (!result) {
        return NextResponse.json(
          { error: 'Key not found' },
          { status: 404 }
        );
      }
      return NextResponse.json({ result });
    } else {
      // Validate all active keys
      const results = await validateAllApiKeys();
      return NextResponse.json({ results });
    }
  } catch (error) {
    console.error('API key validation error:', error);
    return NextResponse.json(
      { error: 'Failed to validate API keys' },
      { status: 500 }
    );
  }
}








