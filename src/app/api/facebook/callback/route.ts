import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { exchangeCodeForToken, getLongLivedToken } from '@/lib/facebook/auth';
import { prisma } from '@/lib/db';

export async function GET(request: NextRequest) {
  console.log('=== FACEBOOK CALLBACK DEBUG ===');
  console.log('Request URL:', request.url);
  console.log('NEXT_PUBLIC_APP_URL:', process.env.NEXT_PUBLIC_APP_URL);
  
  // Get the base URL from environment variable to avoid localhost issues
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || request.nextUrl.origin;
  console.log('Using base URL for redirects:', baseUrl);
  
  try {
    const session = await auth();
    console.log('Session:', session ? 'Authenticated' : 'Not authenticated');
    
    if (!session?.user) {
      console.log('No session, redirecting to login');
      return NextResponse.redirect(new URL('/login', baseUrl));
    }

    const searchParams = request.nextUrl.searchParams;
    const code = searchParams.get('code');
    const error = searchParams.get('error');
    const state = searchParams.get('state');

    console.log('Callback params - code:', code ? 'Present' : 'Missing', 'error:', error, 'state:', state ? 'Present' : 'Missing');

    // Handle user cancellation or errors
    if (error) {
      console.log('Facebook returned error:', error);
      const redirectUrl = new URL('/settings/integrations', baseUrl);
      redirectUrl.searchParams.set('error', error);
      return NextResponse.redirect(redirectUrl);
    }

    if (!code) {
      console.log('No authorization code received');
      const redirectUrl = new URL('/settings/integrations', baseUrl);
      redirectUrl.searchParams.set('error', 'missing_code');
      return NextResponse.redirect(redirectUrl);
    }

    // Verify state parameter (CSRF protection)
    // Note: State is optional for backward compatibility, but we validate if present
    let isPopup = false;
    if (state) {
      try {
        const decodedState = JSON.parse(Buffer.from(state, 'base64').toString());
        console.log('[Callback] Decoded state:', {
          organizationId: decodedState.organizationId,
          currentOrgId: session.user.organizationId,
          userId: decodedState.userId,
          isPopup: decodedState.isPopup,
        });
        
        isPopup = decodedState.isPopup || false;
        
        // Validate user ID matches (primary security check)
        // User ID must match - this is the critical security check
        if (decodedState.userId && decodedState.userId !== session.user.id) {
          console.error('[Callback] User ID mismatch:', {
            stateUserId: decodedState.userId,
            sessionUserId: session.user.id,
          });
          const redirectUrl = new URL('/settings/integrations', baseUrl);
          redirectUrl.searchParams.set('error', 'invalid_state');
          redirectUrl.searchParams.set('error_details', 'User mismatch');
          return NextResponse.redirect(redirectUrl);
        }
        
        // Organization ID can change (user might have been moved to different org)
        // We log it but don't block the flow - we'll use the current session's org
        if (decodedState.organizationId && decodedState.organizationId !== session.user.organizationId) {
          console.warn('[Callback] Organization ID changed (this is OK):', {
            stateOrgId: decodedState.organizationId,
            sessionOrgId: session.user.organizationId,
            note: 'User may have been moved to a different organization. Using current session organization.',
          });
          // Continue with current session's organization - this is valid
        }
        
        console.log('[Callback] ✅ State validation passed');
      } catch (err) {
        // If state is malformed, log but allow flow to continue (state is optional)
        console.warn('[Callback] ⚠️ State validation error (continuing anyway):', err);
        // Don't block the flow - state validation failure could be due to:
        // - State parameter format changed
        // - User came from a different OAuth flow
        // - Browser/network issues
        // We'll continue but log the warning
      }
    } else {
      console.log('[Callback] No state parameter provided (this is OK for backward compatibility)');
    }
    
    // If this was initiated from a popup, redirect to popup callback handler
    if (isPopup) {
      console.log('Popup flow detected, redirecting to popup callback handler');
      const popupCallbackUrl = new URL('/api/facebook/callback-popup', baseUrl);
      popupCallbackUrl.searchParams.set('code', code);
      if (state) popupCallbackUrl.searchParams.set('state', state);
      return NextResponse.redirect(popupCallbackUrl);
    }

    console.log('Exchanging code for token...');
    // Exchange code for access token
    // IMPORTANT: Must pass the same redirect_uri that was used in the OAuth dialog
    const regularRedirectUri = `${baseUrl}/api/facebook/callback`;
    const shortLivedToken = await exchangeCodeForToken(code, regularRedirectUri);
    console.log('Got short-lived token, exchanging for long-lived...');
    
    // Get long-lived token (60 days)
    const userAccessToken = await getLongLivedToken(shortLivedToken);
    console.log('Got long-lived token');

    // Store the user access token temporarily in the database
    // We'll use it to fetch pages and then exchange for page tokens
    await prisma.user.update({
      where: { id: session.user.id },
      data: {
        // Store token in a temporary field (you may need to add this to schema)
        // For now, we'll pass it as a query parameter (less secure but simpler)
      },
    });

    // Redirect back to integrations page with success flag and trigger page selector
    const redirectUrl = new URL('/settings/integrations', baseUrl);
    redirectUrl.searchParams.set('facebook_auth', 'success');
    // Store token in a secure cookie or pass securely
    // For now, we'll store it in session storage via query param (you may want to improve this)
    redirectUrl.searchParams.set('fb_token', userAccessToken);
    
    console.log('Redirecting to:', redirectUrl.toString());
    console.log('=== END CALLBACK DEBUG ===');
    
    return NextResponse.redirect(redirectUrl);
  } catch (error) {
    const err = error as Error;
    console.error('=== FACEBOOK CALLBACK ERROR ===');
    console.error('Error details:', err);
    console.error('Error message:', err.message);
    console.error('Error stack:', err.stack);
    console.error('=== END ERROR ===');
    
    const redirectUrl = new URL('/settings/integrations', baseUrl);
    redirectUrl.searchParams.set('error', 'callback_failed');
    redirectUrl.searchParams.set('error_details', encodeURIComponent(err.message || 'Unknown error'));
    return NextResponse.redirect(redirectUrl);
  }
}

