import { NextResponse } from 'next/server';
import { auth } from '@/auth';

/**
 * GET /api/test-encryption
 * Test if ENCRYPTION_KEY is available and valid
 */
export async function GET() {
  // Require authentication for security
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  try {
    const encryptionKey = process.env.ENCRYPTION_KEY;
    
    if (!encryptionKey) {
      return NextResponse.json({
        status: 'error',
        message: 'ENCRYPTION_KEY is not set',
        details: {
          nodeEnv: process.env.NODE_ENV,
          hasKey: false,
          keyLength: 0,
        },
      }, { status: 500 });
    }

    const isValidLength = encryptionKey.length === 64;
    const isValidHex = /^[0-9a-f]{64}$/i.test(encryptionKey);

    return NextResponse.json({
      status: isValidLength && isValidHex ? 'ok' : 'error',
      message: isValidLength && isValidHex 
        ? 'ENCRYPTION_KEY is valid' 
        : 'ENCRYPTION_KEY format is invalid',
      details: {
        hasKey: true,
        keyLength: encryptionKey.length,
        expectedLength: 64,
        isValidLength,
        isValidHex,
        keyPrefix: encryptionKey.substring(0, 8) + '...',
      },
    });
  } catch (error) {
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    console.error('Test encryption error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const sanitizedError = errorMessage
      .replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
      .replace(/at\s+.*/g, '') // Remove stack trace lines
      .replace(/\(.*?\)/g, '') // Remove file paths
      .substring(0, 200); // Limit length
    
    return NextResponse.json({
      status: 'error',
      message: 'Failed to check ENCRYPTION_KEY',
      error: sanitizedError,
    }, { status: 500 });
  }
}













