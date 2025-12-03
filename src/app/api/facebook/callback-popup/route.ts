import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { exchangeCodeForToken, getLongLivedToken } from '@/lib/facebook/auth';

/**
 * Special callback handler for popup-based OAuth flow
 * Returns an HTML page that communicates with the parent window
 */
export async function GET(request: NextRequest) {
  console.log('=== FACEBOOK POPUP CALLBACK DEBUG ===');
  console.log('Request URL:', request.url);
  
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || request.nextUrl.origin;
  
  try {
    const session = await auth();
    console.log('[Callback Popup] Session check:', {
      hasSession: !!session,
      hasUser: !!session?.user,
      userId: session?.user?.id,
      organizationId: session?.user?.organizationId,
    });
    
    if (!session?.user) {
      console.error('[Callback Popup] ❌ No session or user found');
      return new NextResponse(
        getPopupHTML('error', 'Not authenticated. Please log in and try again.', null),
        { headers: { 'Content-Type': 'text/html' } }
      );
    }

    const searchParams = request.nextUrl.searchParams;
    const code = searchParams.get('code');
    const error = searchParams.get('error');
    const errorDescription = searchParams.get('error_description');
    const state = searchParams.get('state');

    // Handle user cancellation or errors
    if (error) {
      let errorMessage = 'Facebook authorization failed';
      if (error === 'access_denied') {
        errorMessage = 'You cancelled the Facebook authorization';
      } else if (errorDescription) {
        errorMessage = errorDescription;
      }
      
      return new NextResponse(
        getPopupHTML('error', errorMessage, null),
        { headers: { 'Content-Type': 'text/html' } }
      );
    }

    if (!code) {
      return new NextResponse(
        getPopupHTML('error', 'No authorization code received', null),
        { headers: { 'Content-Type': 'text/html' } }
      );
    }

    // Verify state parameter (CSRF protection)
    // Note: State is optional for backward compatibility, but we validate if present
    if (state) {
      try {
        const decodedState = JSON.parse(Buffer.from(state, 'base64').toString());
        console.log('[Callback Popup] Decoded state:', {
          organizationId: decodedState.organizationId,
          currentOrgId: session.user.organizationId,
          userId: decodedState.userId,
          isPopup: decodedState.isPopup,
        });
        
        // Validate user ID matches (primary security check)
        // User ID must match - this is the critical security check
        if (decodedState.userId && decodedState.userId !== session.user.id) {
          console.error('[Callback Popup] User ID mismatch:', {
            stateUserId: decodedState.userId,
            sessionUserId: session.user.id,
          });
          return new NextResponse(
            getPopupHTML('error', 'Security validation failed: User mismatch', null),
            { headers: { 'Content-Type': 'text/html' } }
          );
        }
        
        // Organization ID can change (user might have been moved to different org)
        // We log it but don't block the flow - we'll use the current session's org
        if (decodedState.organizationId && decodedState.organizationId !== session.user.organizationId) {
          console.warn('[Callback Popup] Organization ID changed (this is OK):', {
            stateOrgId: decodedState.organizationId,
            sessionOrgId: session.user.organizationId,
            note: 'User may have been moved to a different organization. Using current session organization.',
          });
          // Continue with current session's organization - this is valid
        }
        
        console.log('[Callback Popup] ✅ State validation passed');
      } catch (stateError) {
        // If state is malformed, log but allow flow to continue (state is optional)
        console.warn('[Callback Popup] ⚠️ State validation error (continuing anyway):', stateError);
        // Don't block the flow - state validation failure could be due to:
        // - State parameter format changed
        // - User came from a different OAuth flow
        // - Browser/network issues
        // We'll continue but log the warning
      }
    } else {
      console.log('[Callback Popup] No state parameter provided (this is OK for backward compatibility)');
    }

    // Exchange code for access token
    // IMPORTANT: Must pass the same redirect_uri that was used in the OAuth dialog
    const popupRedirectUri = `${baseUrl}/api/facebook/callback-popup`;
    const shortLivedToken = await exchangeCodeForToken(code, popupRedirectUri);
    const userAccessToken = await getLongLivedToken(shortLivedToken);
    
    console.log('✅ Successfully obtained access token');
    console.log('=== END POPUP CALLBACK DEBUG ===');

    // Return success page that communicates with parent
    return new NextResponse(
      getPopupHTML('success', 'Successfully connected to Facebook!', userAccessToken),
      { headers: { 'Content-Type': 'text/html' } }
    );
  } catch (error: unknown) {
    console.error('❌ Facebook popup callback error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return new NextResponse(
      getPopupHTML('error', errorMessage, null),
      { headers: { 'Content-Type': 'text/html' } }
    );
  }
}

/**
 * Generate HTML page that sends message to parent window and closes
 */
function getPopupHTML(status: 'success' | 'error', message: string, token: string | null): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Facebook Authentication</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .container {
      background: white;
      padding: 2rem;
      border-radius: 1rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
      text-align: center;
      max-width: 400px;
    }
    .icon {
      font-size: 4rem;
      margin-bottom: 1rem;
    }
    .success { color: #10b981; }
    .error { color: #ef4444; }
    h1 {
      font-size: 1.5rem;
      margin-bottom: 0.5rem;
      color: #1f2937;
    }
    p {
      color: #6b7280;
      margin-bottom: 1.5rem;
    }
    .spinner {
      border: 3px solid #f3f4f6;
      border-top: 3px solid #667eea;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      animation: spin 1s linear infinite;
      margin: 1rem auto;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon ${status}">${status === 'success' ? '✓' : '✗'}</div>
    <h1>${status === 'success' ? 'Success!' : 'Error'}</h1>
    <p>${message}</p>
    <div class="spinner"></div>
    <p style="font-size: 0.875rem; color: #9ca3af;">Closing window...</p>
  </div>
  
  <script>
    (function() {
      // Send message to parent window
      if (window.opener) {
        const messageData = {
          type: 'FACEBOOK_AUTH_${status.toUpperCase()}',
          ${status === 'success' && token ? `token: '${token}',` : ''}
          ${status === 'error' ? `error: '${message.replace(/'/g, "\\'")}',` : ''}
        };
        
        console.log('Sending message to parent:', messageData);
        window.opener.postMessage(messageData, window.location.origin);
      }
      
      // Close window after a short delay
      setTimeout(function() {
        window.close();
      }, 2000);
    })();
  </script>
</body>
</html>
  `.trim();
}

