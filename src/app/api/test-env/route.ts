import { NextResponse } from 'next/server';

export async function GET() {
  const hasNvidiaKey = !!process.env.NVIDIA_API_KEY;
  const hasDbUrl = !!process.env.DATABASE_URL;
  const nvidiaKeyPreview = process.env.NVIDIA_API_KEY 
    ? `${process.env.NVIDIA_API_KEY.substring(0, 20)}... (${process.env.NVIDIA_API_KEY.length} chars)`
    : 'MISSING';
  
  return NextResponse.json({
    success: true,
    environment: {
      nvidiaApiKey: {
        exists: hasNvidiaKey,
        preview: nvidiaKeyPreview
      },
      databaseUrl: {
        exists: hasDbUrl,
        preview: hasDbUrl ? 'SET' : 'MISSING'
      }
    },
    message: hasNvidiaKey && hasDbUrl 
      ? '✅ All environment variables are loaded correctly'
      : '❌ Some environment variables are missing - restart the dev server'
  });
}
