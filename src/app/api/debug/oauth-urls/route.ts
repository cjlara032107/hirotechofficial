import { NextResponse } from 'next/server';
import { auth } from '@/auth';

/**
 * Debug endpoint to show exactly what OAuth URLs are being used
 * Visit this to copy the exact URLs to add to Facebook
 */
export async function GET() {
  // Require authentication for security
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  const appId = process.env.FACEBOOK_APP_ID;
  
  const callbackUrl = `${appUrl}/api/facebook/callback`;
  const callbackPopupUrl = `${appUrl}/api/facebook/callback-popup`;
  
  return NextResponse.json({
    status: appUrl ? 'READY' : 'ERROR',
    configuration: {
      NEXT_PUBLIC_APP_URL: appUrl || '❌ NOT SET',
      FACEBOOK_APP_ID: appId || '❌ NOT SET',
    },
    callbackUrls: {
      regular: callbackUrl,
      popup: callbackPopupUrl,
    },
    instructions: [
      '1. Go to https://developers.facebook.com/apps/',
      '2. Select your app',
      '3. Click "Facebook Login" in the left sidebar',
      '4. Click "Settings"',
      '5. Scroll to "Valid OAuth Redirect URIs"',
      '6. Copy and paste BOTH URLs below (one per line)',
      '7. Click "Save Changes" at the bottom',
      '8. Wait a few seconds for changes to propagate',
    ],
    urlsToCopy: [
      callbackUrl,
      callbackPopupUrl,
    ],
    facebookAppSettingsUrl: `https://developers.facebook.com/apps/${appId}/fb-login/settings/`,
    troubleshooting: {
      common_issues: [
        'Make sure URLs are EXACTLY the same (case-sensitive)',
        'No trailing slashes (/) at the end',
        'Must use https:// not http:// (unless localhost)',
        'Both URLs must be added',
        'Click "Save Changes" button after adding',
        'Wait 10-30 seconds after saving for changes to take effect',
      ],
    },
  }, {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

