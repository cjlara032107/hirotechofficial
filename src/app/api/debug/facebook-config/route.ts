import { NextResponse } from 'next/server';
import { auth } from '@/auth';

export async function GET() {
  // Require authentication for security
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  const appId = process.env.FACEBOOK_APP_ID;
  const appSecret = process.env.FACEBOOK_APP_SECRET;
  
  const redirectUri = `${appUrl}/api/facebook/callback`;
  
  // Generate sample OAuth URL
  const params = new URLSearchParams({
    client_id: appId || 'NOT_SET',
    redirect_uri: redirectUri,
    scope: 'pages_show_list,pages_messaging,pages_read_engagement,instagram_basic,instagram_manage_messages',
    response_type: 'code',
    state: 'test',
  });
  
  const oauthUrl = `https://www.facebook.com/v19.0/dialog/oauth?${params.toString()}`;
  
  return NextResponse.json({
    environment: {
      NEXT_PUBLIC_APP_URL: appUrl || 'NOT SET',
      FACEBOOK_APP_ID: appId || 'NOT SET',
      FACEBOOK_APP_SECRET: appSecret ? 'SET (hidden)' : 'NOT SET',
    },
    computed: {
      redirectUri,
      oauthUrl,
    },
    instructions: {
      step1: 'Check if NEXT_PUBLIC_APP_URL is correct (should be your ngrok URL)',
      step2: 'Check if FACEBOOK_APP_ID is set',
      step3: 'Copy the redirectUri and add it EXACTLY to Facebook App OAuth Settings',
      step4: 'Make sure there are no trailing slashes or double slashes',
    },
  }, {
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

