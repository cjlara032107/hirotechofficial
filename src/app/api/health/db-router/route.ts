import { NextResponse } from 'next/server';

export async function GET() {
  try {
    // Only check multi-DB router if enabled
    if (process.env.ENABLE_MULTI_DB === 'true') {
      const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
      const router = getDatabaseRouter();
      const status = router.getStatus();

      return NextResponse.json({
        success: true,
        multiDbEnabled: true,
        status,
        timestamp: new Date().toISOString(),
      });
    }

    // Single database mode
    return NextResponse.json({
      success: true,
      multiDbEnabled: false,
      message: 'Single database mode - set ENABLE_MULTI_DB=true to enable multi-database routing',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        multiDbEnabled: false,
      },
      { status: 500 }
    );
  }
}




