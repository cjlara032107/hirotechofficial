import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { connectPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { startInstantSync } from '@/lib/facebook/instant-sync';
import { validateUUID } from '@/lib/api/validate-uuid';

export async function POST(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { facebookPageId } = body;

    if (!facebookPageId) {
      return NextResponse.json(
        { error: 'Missing facebookPageId' },
        { status: 400 }
      );
    }

    // Validate facebookPageId is valid UUID format
    if (typeof facebookPageId !== 'string') {
      return NextResponse.json(
        { error: 'facebookPageId must be a string' },
        { status: 400 }
      );
    }

    const trimmedFacebookPageId = facebookPageId.trim();
    if (trimmedFacebookPageId.length === 0) {
      return NextResponse.json(
        { error: 'facebookPageId cannot be empty' },
        { status: 400 }
      );
    }
    const uuidValidation = validateUUID(trimmedFacebookPageId);
    if (uuidValidation?.error) {
      return NextResponse.json(
        { error: uuidValidation.error.message },
        { status: uuidValidation.error.status }
      );
    }

    // CRITICAL: Ensure database connection is established (required for Vercel serverless)
    await connectPrisma();

    // ============================================
    // MULTI-DB ROUTING TRACE
    // ============================================
    const multiDbEnabled = process.env.ENABLE_MULTI_DB === 'true';
    const routingStrategy = process.env.DB_ROUTING_STRATEGY || 'hash';
    
    console.log('[Sync Instant API] ============================================');
    console.log('[Sync Instant API] MULTI-DB ROUTING INTENT');
    console.log('[Sync Instant API] - Organization ID:', session.user.organizationId);
    console.log('[Sync Instant API] - Multi-DB Enabled:', multiDbEnabled);
    console.log('[Sync Instant API] - Routing Strategy:', routingStrategy);
    console.log('[Sync Instant API] - Page ID:', trimmedFacebookPageId);
    console.log('[Sync Instant API] ============================================');

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);
    
    // Log which database was chosen
    let chosenDbIndex = 0;
    let chosenDbHost = 'unknown';
    if (multiDbEnabled) {
      try {
        const { getDatabaseRouter } = await import('@/lib/db/multi-db-router');
        const router = getDatabaseRouter();
        const allConfigs = router.getAllDatabaseConfigs();
        const chosenClient = router.getClient(session.user.organizationId);
        
        // Find matching config
        const matchedConfig = allConfigs.find(cfg => cfg.client === chosenClient);
        if (matchedConfig) {
          chosenDbIndex = matchedConfig.index;
          // Extract host from URL (mask credentials)
          const urlMatch = matchedConfig.url.match(/postgresql:\/\/[^@]*@([^\/]+)/);
          chosenDbHost = urlMatch ? urlMatch[1] : 'unknown';
        }
        
        console.log('[Sync Instant API] ============================================');
        console.log('[Sync Instant API] ROUTED DATABASE SELECTED');
        console.log('[Sync Instant API] - DB Index:', chosenDbIndex);
        console.log('[Sync Instant API] - DB Host:', chosenDbHost);
        console.log('[Sync Instant API] - Total DBs Available:', allConfigs.length);
        console.log('[Sync Instant API] ============================================');
      } catch (routerError) {
        console.error('[Sync Instant API] Error getting router info:', routerError);
      }
    } else {
      console.log('[Sync Instant API] Using default (single) database');
    }

    console.log('[Sync Instant API] Looking for page:', {
      pageId: trimmedFacebookPageId,
      organizationId: session.user.organizationId,
      routedToDbIndex: chosenDbIndex,
      routedToDbHost: chosenDbHost,
    });

    // Verify the page belongs to the user's organization
    const page = await prisma.facebookPage.findFirst({
      where: {
        id: trimmedFacebookPageId,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        pageId: true,
        pageName: true,
        organizationId: true,
      },
    });

    if (!page) {
      console.warn('[Sync Instant API] Page not found in routed database:', {
        pageId: trimmedFacebookPageId,
        organizationId: session.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      
      // If multi-DB is enabled, try checking all databases as fallback
      if (process.env.ENABLE_MULTI_DB === 'true') {
        try {
          // Try default database first
          const { prisma: defaultPrisma } = await import('@/lib/db');
          
          // First, find the page by ID only (without organization filter) to see where it exists
          const pageInDefault = await defaultPrisma.facebookPage.findFirst({
            where: { id: trimmedFacebookPageId },
            select: { id: true, organizationId: true, pageId: true, pageName: true },
          });
          
          if (pageInDefault) {
            console.log('[Sync Instant API] ============================================');
            console.log('[Sync Instant API] FALLBACK: PAGE FOUND IN DEFAULT DB');
            console.log('[Sync Instant API] - Page ID:', trimmedFacebookPageId);
            console.log('[Sync Instant API] - Page Org ID:', pageInDefault.organizationId);
            console.log('[Sync Instant API] - Session Org ID:', session.user.organizationId);
            console.log('[Sync Instant API] - Page Name:', pageInDefault.pageName);
            console.log('[Sync Instant API] - Note: Page exists in default DB but not in routed DB', chosenDbIndex);
            console.log('[Sync Instant API] - Routed DB was:', chosenDbHost);
            console.log('[Sync Instant API] ============================================');
            
            // Check if organization matches
            if (pageInDefault.organizationId !== session.user.organizationId) {
              console.error('[Sync Instant API] ============================================');
              console.error('[Sync Instant API] ❌ ORGANIZATION MISMATCH - ACCESS DENIED');
              console.error('[Sync Instant API] - Page ID:', trimmedFacebookPageId);
              console.error('[Sync Instant API] - Page Org ID:', pageInDefault.organizationId);
              console.error('[Sync Instant API] - Session Org ID:', session.user.organizationId);
              console.error('[Sync Instant API] - Page Name:', pageInDefault.pageName);
              console.error('[Sync Instant API] - User ID:', session.user.id);
              console.error('[Sync Instant API] - Routed DB Index:', chosenDbIndex);
              console.error('[Sync Instant API] - Routed DB Host:', chosenDbHost);
              console.error('[Sync Instant API] - Cause: Page belongs to different organization');
              console.error('[Sync Instant API] - This indicates session issue or multi-DB routing problem');
              console.error('[Sync Instant API] ============================================');
              
              return NextResponse.json(
                { 
                  error: 'Facebook page not found or access denied. This page belongs to a different organization. Please refresh the page and try again.',
                  details: 'Organization mismatch detected. This may be due to a session issue or multi-database routing problem.'
                },
                { status: 403 }
              );
            }
            
            // Page found in default database but not in routed database
            // This indicates a multi-DB routing issue - use the page from default database
            console.warn('[Sync Instant API] ============================================');
            console.warn('[Sync Instant API] ⚠️  ROUTING MISMATCH - USING FALLBACK');
            console.warn('[Sync Instant API] - Page ID:', trimmedFacebookPageId);
            console.warn('[Sync Instant API] - Page found in: DEFAULT DB (DB 0)');
            console.warn('[Sync Instant API] - Page NOT found in: ROUTED DB', chosenDbIndex, `(${chosenDbHost})`);
            console.warn('[Sync Instant API] - Page Org ID:', pageInDefault.organizationId);
            console.warn('[Sync Instant API] - Session Org ID:', session.user.organizationId);
            console.warn('[Sync Instant API] - Action: Using page from default DB for sync');
            console.warn('[Sync Instant API] - Recommendation: This org should be in DB', chosenDbIndex, 'but page is in DB 0');
            console.warn('[Sync Instant API] ============================================');
            
            // Use the page from default database for sync
            const pageForSync = {
              id: pageInDefault.id,
              pageId: pageInDefault.pageId,
              pageName: pageInDefault.pageName || 'Unknown',
              organizationId: pageInDefault.organizationId,
            };
            
            console.log('[Sync Instant API] Starting instant sync with page from default database:', pageForSync);
            // Use the routed prisma client for the sync
            const result = await startInstantSync(trimmedFacebookPageId, session.user.id, prisma);
            console.log('[Sync Instant API] Instant sync started, jobId:', result.jobId);
            
            return NextResponse.json(result);
          } else {
            console.warn('[Sync Instant API] Page not found in default database either:', {
              pageId: trimmedFacebookPageId,
              organizationId: session.user.organizationId,
            });
          }
        } catch (fallbackError) {
          console.error('[Sync Instant API] Error checking default database:', fallbackError);
        }
      }
      
      return NextResponse.json(
        { error: 'Facebook page not found' },
        { status: 404 }
      );
    }

    console.log('[Sync Instant API] Found page:', {
      databaseId: page.id,
      facebookPageId: page.pageId,
      pageName: page.pageName,
    });

    // Start instant sync (stores contacts immediately, queues AI analysis)
    console.log('[Sync Instant API] Starting instant sync for page:', trimmedFacebookPageId);
    // Use the routed prisma client for the sync
    const result = await startInstantSync(trimmedFacebookPageId, session.user.id, prisma);
    console.log('[Sync Instant API] Instant sync started, jobId:', result.jobId);
    
    // CRITICAL: Use Vercel's waitUntil to keep the function alive for background tasks
    // This ensures the background promise continues executing after the response is sent
    if ('waitUntil' in request) {
      // Store the background promise and wait for it
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const backgroundPromise = (globalThis as any).__activeSyncPromises?.values().next().value;
      if (backgroundPromise) {
        console.log('[Sync Instant API] Using waitUntil to keep promise alive');
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (request as any).waitUntil(backgroundPromise);
      } else {
        console.warn('[Sync Instant API] ⚠️ No background promise found in globalThis.__activeSyncPromises');
      }
    } else {
      console.log('[Sync Instant API] ⚠️ waitUntil not available (not running on Vercel)');
    }

    console.log('[Sync Instant API] Returning response, jobId:', result.jobId);
    return NextResponse.json(result);
  } catch (error) {
    console.error('Instant sync error:', error);
    // Log detailed error information for debugging
    if (error instanceof Error) {
      console.error('Error name:', error.name);
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
    }
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    // In development, provide more context for debugging
    const errorMessage = process.env.NODE_ENV === 'development' && error instanceof Error
      ? `Failed to start instant sync: ${error.message}`
      : 'Failed to start instant sync. Please try again.';
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

