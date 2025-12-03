import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { getUserPages, getPageAccessToken, getInstagramBusinessAccount } from '@/lib/facebook/auth';

interface SelectedPage {
  id: string;
  name: string;
}

/**
 * GET - Fetch user's Facebook pages
 */
export async function GET(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const userAccessToken = searchParams.get('token');

    if (!userAccessToken) {
      return NextResponse.json(
        { error: 'Missing user access token' },
        { status: 400 }
      );
    }

    // Fetch user's Facebook pages
    const pages = await getUserPages(userAccessToken);

    // Check which pages are already connected (within this organization only)
    // Multiple organizations can connect the same page, so we only check within current org
    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);
    const pageIds = pages.map((p) => p.id);
    const existingPages = await prisma.facebookPage.findMany({
      where: {
        organizationId: session.user.organizationId, // Only check within this organization
        pageId: { in: pageIds },
      },
      select: { pageId: true, organizationId: true },
    });

    const existingPageIds = new Set(existingPages.map(p => p.pageId));
    
    console.log(`[Facebook Pages GET] User ${session.user.id} (Org: ${session.user.organizationId})`);
    console.log(`  - Total pages from Facebook: ${pages.length}`);
    console.log(`  - Pages already connected in this org: ${existingPages.length}`);
    console.log(`  - Available to connect: ${pages.length - existingPageIds.size}`);

    // Mark pages as already connected (only if connected in THIS organization)
    // Pages connected by other organizations will show as available
    // SECURITY: Do not expose access tokens in API responses
    const pagesWithStatus = pages.map((page) => {
      const isConnected = existingPageIds.has(page.id);
      if (isConnected) {
        console.log(`  - Page ${page.id} (${page.name}) is already connected in this organization`);
      }
      return {
        id: page.id,
        name: page.name,
        isConnected, // Only true if connected in THIS organization
      };
    });

    return NextResponse.json({ pages: pagesWithStatus });
  } catch (error: unknown) {
    console.error('Fetch pages error:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    return NextResponse.json(
      { error: 'Failed to fetch Facebook pages. Please try again.' },
      { status: 500 }
    );
  }
}

/**
 * POST - Save selected Facebook pages
 */
export async function POST(request: NextRequest) {
  console.log('=== FACEBOOK PAGES SAVE START ===');
  console.log('Timestamp:', new Date().toISOString());
  
  try {
    const session = await auth();
    console.log('Session check:', {
      authenticated: !!session?.user,
      userId: session?.user?.id,
      organizationId: session?.user?.organizationId,
    });
    
    if (!session?.user) {
      console.log('❌ Unauthorized - no session');
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json() as { selectedPages?: SelectedPage[]; userAccessToken?: string };
    const { selectedPages, userAccessToken } = body;
    
    console.log('Request body:', {
      pagesCount: selectedPages?.length || 0,
      hasToken: !!userAccessToken,
    });

    if (!selectedPages || !Array.isArray(selectedPages) || selectedPages.length === 0) {
      console.log('❌ No pages selected');
      return NextResponse.json(
        { error: 'No pages selected' },
        { status: 400 }
      );
    }

    if (!userAccessToken) {
      console.log('❌ Missing user access token');
      return NextResponse.json(
        { error: 'Missing user access token' },
        { status: 400 }
      );
    }

    interface SavedPage {
      id: string;
      pageId: string;
      pageName: string;
      instagramAccountId: string | null;
    }

    interface PageError {
      pageId: string;
      pageName: string;
      error: string;
    }

    const savedPages: SavedPage[] = [];
    const errors: PageError[] = [];

    console.log(`Processing ${selectedPages.length} page(s)...`);

    // Step 1: Fetch all page data in parallel (API calls)
    interface PageData {
      page: SelectedPage;
      pageAccessToken: string;
      pageName: string;
      igAccount: { id: string; username: string } | null;
      error?: string;
    }

    const pageDataResults = await Promise.all(
      selectedPages.map(async (page): Promise<PageData> => {
        try {
          console.log(`\n--- Processing page: ${page.name} (${page.id}) ---`);
          console.log('Step 1: Getting page access token...');
          const { pageAccessToken, pageName } = await getPageAccessToken(
            userAccessToken,
            page.id
          );
          console.log('✓ Got page access token');

          console.log('Step 2: Checking Instagram business account...');
          const igAccount = await getInstagramBusinessAccount(pageAccessToken);
          console.log('✓ Instagram check complete:', igAccount ? `Found: ${igAccount.username}` : 'None');

          return {
            page,
            pageAccessToken,
            pageName,
            igAccount: igAccount ? { id: igAccount.id, username: igAccount.username } : null,
          };
        } catch (error: unknown) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          console.error(`❌ Error processing page ${page.id}:`, errorMessage);
          // SECURITY: Sanitize error messages to prevent sensitive data exposure
          const sanitizedError = errorMessage
            .replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
            .replace(/at\s+.*/g, '') // Remove stack trace lines
            .replace(/\(.*?\)/g, '') // Remove file paths
            .substring(0, 200); // Limit length
          
          return {
            page,
            pageAccessToken: '',
            pageName: page.name,
            igAccount: null,
            error: sanitizedError,
          };
        }
      })
    );

    // Step 2: Check existing pages in bulk (only for current organization)
    // Use getPrismaForOrg for multi-DB routing support
    // First verify organization exists, if not try default database
    let prisma = getPrismaForOrg(session.user.organizationId);
    const pageIds = pageDataResults.map(p => p.page.id);
    
    // Verify organization exists in the database we're using
    try {
      const orgExists = await prisma.organization.findUnique({
        where: { id: session.user.organizationId },
        select: { id: true },
      });
      
      if (!orgExists) {
        console.warn(`[Facebook Pages POST] ⚠️ Organization ${session.user.organizationId} not found in routed database, trying default database...`);
        const { prisma: defaultPrisma } = await import('@/lib/db');
        const orgInDefault = await defaultPrisma.organization.findUnique({
          where: { id: session.user.organizationId },
          select: { id: true },
        });
        
        if (orgInDefault) {
          console.log(`[Facebook Pages POST] ✅ Organization found in default database, using default prisma client`);
          prisma = defaultPrisma;
        } else {
          return NextResponse.json(
            { 
              error: 'Organization not found',
              details: `Your organization (${session.user.organizationId}) was not found in the database. Please refresh your session or contact support.`
            },
            { status: 404 }
          );
        }
      }
    } catch (orgCheckError) {
      console.error('[Facebook Pages POST] Error checking organization:', orgCheckError);
      // Continue anyway - might be a transient error, will fail later if org doesn't exist
    }
    
    console.log(`[Facebook Pages POST] Step 2: Checking for existing pages...`);
    console.log(`  - User: ${session.user.id}`);
    console.log(`  - Organization: ${session.user.organizationId}`);
    console.log(`  - Page IDs to check: ${pageIds.join(', ')}`);
    
    const existingPages = await prisma.facebookPage.findMany({
      where: {
        pageId: { in: pageIds },
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        pageId: true,
        organizationId: true,
        pageName: true,
      },
    });
    
    console.log(`[Facebook Pages POST] Found ${existingPages.length} existing pages in this organization:`);
    existingPages.forEach(p => {
      console.log(`  - Page ${p.pageId} (${p.pageName}) - ID: ${p.id}`);
    });
    console.log(`  - Pages to create: ${pageIds.length - existingPages.length}`);

    // Create a map keyed by pageId for quick lookup within the organization
    const existingPagesMap = new Map(
      existingPages.map(p => [p.pageId, p])
    );

    // Step 3: Separate pages into creates and updates
    const pagesToCreate: Array<{
      pageId: string;
      pageName: string;
      pageAccessToken: string;
      instagramAccountId: string | null;
      instagramUsername: string | null;
      organizationId: string;
    }> = [];

    const pagesToUpdate: Array<{
      id: string;
      pageName: string;
      pageAccessToken: string;
      instagramAccountId: string | null;
      instagramUsername: string | null;
    }> = [];

    for (const pageData of pageDataResults) {
      if (pageData.error) {
        errors.push({
          pageId: pageData.page.id,
          pageName: pageData.page.name,
          error: pageData.error,
        });
        continue;
      }

      const existingPage = existingPagesMap.get(pageData.page.id);

      if (existingPage) {
        // Update existing page (same organization)
        pagesToUpdate.push({
          id: existingPage.id,
          pageName: pageData.pageName,
          pageAccessToken: pageData.pageAccessToken,
          instagramAccountId: pageData.igAccount?.id || null,
          instagramUsername: pageData.igAccount?.username || null,
        });
      } else {
        // Create new page (either doesn't exist, or exists for different organization - both are fine)
        pagesToCreate.push({
          pageId: pageData.page.id,
          pageName: pageData.pageName,
          pageAccessToken: pageData.pageAccessToken,
          instagramAccountId: pageData.igAccount?.id || null,
          instagramUsername: pageData.igAccount?.username || null,
          organizationId: session.user.organizationId,
        });
      }
    }

    // Step 4: Execute bulk operations in a transaction
    if (pagesToCreate.length > 0 || pagesToUpdate.length > 0) {
      await prisma.$transaction(async (tx) => {
        // Bulk create new pages (use upsert to handle race conditions)
        if (pagesToCreate.length > 0) {
          console.log(`Step 4: Creating ${pagesToCreate.length} new page(s)...`);
          const createdPages = await Promise.all(
            pagesToCreate.map(async (pageData) => {
              try {
                console.log(`[Create Page] Attempting to create page ${pageData.pageId} for org ${pageData.organizationId}`);
                // Try to create the page
                // Note: Multiple organizations can now have the same pageId and instagramAccountId
                const created = await tx.facebookPage.create({
                  data: pageData,
                });
                console.log(`[Create Page] ✅ Successfully created page ${pageData.pageId} (ID: ${created.id})`);
                return created;
              } catch (error: any) {
                console.error(`[Create Page] ❌ Error creating page ${pageData.pageId}:`, {
                  code: error?.code,
                  message: error?.message,
                  constraint: error?.meta?.constraint,
                  error: error,
                });
                
                // Handle foreign key constraint violation FIRST (organization doesn't exist)
                // This is more critical than unique constraint errors
                if (error?.code === 'P2003' && (error?.meta?.constraint?.includes('organizationId') || error?.message?.includes('organizationId_fkey'))) {
                  console.error(`[Create Page] Organization ${pageData.organizationId} does not exist in this database`);
                  console.error(`  - This is likely a multi-DB routing issue`);
                  console.error(`  - Attempting to find organization in default database...`);
                  
                  // Try to find organization in default database
                  try {
                    const { prisma: defaultPrisma } = await import('@/lib/db');
                    const orgInDefault = await defaultPrisma.organization.findUnique({
                      where: { id: pageData.organizationId },
                      select: { id: true },
                    });
                    
                    if (orgInDefault) {
                      console.log(`[Create Page] ✅ Organization found in default database, creating page there`);
                      // Create in default database instead (outside transaction)
                      const createdInDefault = await defaultPrisma.facebookPage.create({
                        data: pageData,
                      });
                      console.log(`[Create Page] ✅ Successfully created page ${pageData.pageId} in default database (ID: ${createdInDefault.id})`);
                      return createdInDefault;
                    } else {
                      console.error(`[Create Page] ❌ Organization ${pageData.organizationId} not found in default database either`);
                      throw new Error(`Organization ${pageData.organizationId} not found. The organization may have been deleted or you may need to refresh your session.`);
                    }
                  } catch (defaultDbError: any) {
                    console.error(`[Create Page] Error checking default database:`, defaultDbError);
                    if (defaultDbError?.message?.includes('not found')) {
                      throw defaultDbError;
                    }
                    // If it's a different error, throw the original foreign key error
                    throw new Error(`Organization ${pageData.organizationId} not found in database. Please refresh your session and try again.`);
                  }
                }
                
                // If unique constraint error (page already exists for this organization)
                // This can happen due to race conditions
                const isUniqueError = error?.code === 'P2002' || 
                                     error?.message?.includes('Unique constraint') ||
                                     error?.message?.includes('pageId_organizationId');
                
                if (isUniqueError) {
                  console.log(`[Create Page] Unique constraint error detected, checking for existing page...`);
                  // Check if it's a pageId_organizationId conflict (same org)
                  const existing = await tx.facebookPage.findFirst({
                    where: {
                      pageId: pageData.pageId,
                      organizationId: pageData.organizationId,
                    },
                  });
                  
                  if (existing) {
                    // Page already exists for this organization - update it
                    console.warn(`⚠️ Page ${pageData.pageId} already exists for organization ${pageData.organizationId}, updating instead...`);
                    const updated = await tx.facebookPage.update({
                      where: { id: existing.id },
                      data: {
                        pageName: pageData.pageName,
                        pageAccessToken: pageData.pageAccessToken,
                        instagramAccountId: pageData.instagramAccountId,
                        instagramUsername: pageData.instagramUsername,
                        isActive: true,
                        updatedAt: new Date(),
                      },
                    });
                    console.log(`[Create Page] ✅ Updated existing page ${pageData.pageId} (ID: ${updated.id})`);
                    return updated;
                  } else {
                    // This shouldn't happen with the composite unique constraint
                    console.error(`⚠️ Unique constraint error but page not found for org ${pageData.organizationId}`);
                    console.error(`  - PageId: ${pageData.pageId}`);
                    console.error(`  - OrganizationId: ${pageData.organizationId}`);
                    throw new Error(`Page ${pageData.pageId} cannot be created due to constraint violation`);
                  }
                }
                
                // Re-throw other errors with more context
                console.error(`[Create Page] Unexpected error:`, error);
                throw error;
              }
            })
          );
          savedPages.push(...createdPages);
          console.log(`✅ Created/updated ${createdPages.length} page(s) successfully`);
        }

        // Bulk update existing pages
        if (pagesToUpdate.length > 0) {
          console.log(`Step 4: Updating ${pagesToUpdate.length} existing page(s)...`);
          const updatedPages = await Promise.all(
            pagesToUpdate.map(pageData =>
              tx.facebookPage.update({
                where: { id: pageData.id },
                data: {
                  pageName: pageData.pageName,
                  pageAccessToken: pageData.pageAccessToken,
                  instagramAccountId: pageData.instagramAccountId,
                  instagramUsername: pageData.instagramUsername,
                  isActive: true,
                  updatedAt: new Date(),
                },
              })
            )
          );
          savedPages.push(...updatedPages);
          console.log(`✅ Updated ${updatedPages.length} page(s) successfully`);
        }
      });
    }

    console.log('\n=== FACEBOOK PAGES SAVE COMPLETE ===');
    console.log('Summary:', {
      successful: savedPages.length,
      failed: errors.length,
      total: selectedPages.length,
    });

    const response = {
      success: true,
      savedPages: savedPages.length,
      errors: errors.length > 0 ? errors : undefined,
      pages: savedPages.map(p => ({
        id: p.id,
        pageId: p.pageId,
        name: p.pageName,
        hasInstagram: !!p.instagramAccountId,
      })),
    };
    
    console.log('Response:', response);
    // Check if there were any errors
    if (errors.length > 0 && savedPages.length === 0) {
      // All pages failed
      console.error('❌ All pages failed to connect:', errors);
      return NextResponse.json(
        { 
          error: errors[0]?.error || 'Failed to connect Facebook pages',
          errors: errors,
        },
        { status: 400 }
      );
    }
    
    console.log('Response:', response);
    return NextResponse.json(response);
  } catch (error: unknown) {
    console.error('❌ CRITICAL: Save pages error:', error);
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    // Only log full error details server-side, never expose to client
    const errorStack = error instanceof Error ? error.stack : undefined;
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('Error stack:', errorStack);
    console.error('Error message:', errorMessage);
    
    // Check for specific error types
    if (errorMessage.includes('Unique constraint') || errorMessage.includes('P2002')) {
      return NextResponse.json(
        { 
          error: 'This page is already connected. If you believe this is an error, please try refreshing the page list.',
          details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
        },
        { status: 409 } // Conflict
      );
    }
    
    // Check for foreign key constraint violation (organization doesn't exist)
    const errorCode = (error as any)?.code;
    if (errorCode === 'P2003' || errorMessage.includes('Foreign key constraint') || errorMessage.includes('organizationId_fkey')) {
      // Try to get session for error details
      let orgId = 'unknown';
      try {
        const currentSession = await auth();
        orgId = currentSession?.user?.organizationId || 'unknown';
      } catch {
        // Ignore auth errors in error handler
      }
      
      return NextResponse.json(
        { 
          error: 'Organization not found. Please refresh your session and try again.',
          details: process.env.NODE_ENV === 'development' 
            ? `Organization ${orgId} not found in database. This may be a multi-database routing issue.`
            : undefined,
        },
        { status: 404 }
      );
    }
    
    return NextResponse.json(
      { 
        error: 'Failed to save Facebook pages. Please try again.',
        // Only expose stack in development, and even then sanitize it
        details: process.env.NODE_ENV === 'development' && errorStack
          ? errorStack.replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]') // Remove long tokens/IDs
          : undefined,
      },
      { status: 500 }
    );
  }
}

/**
 * DELETE - Disconnect a Facebook page
 */
export async function DELETE(request: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const pageId = searchParams.get('pageId');

    if (!pageId) {
      return NextResponse.json(
        { error: 'Missing page ID' },
        { status: 400 }
      );
    }

    // Ensure database connection
    try {
      const { connectPrisma } = await import('@/lib/db');
      await connectPrisma();
    } catch (dbError) {
      console.error('[Delete Page] Database connection error:', dbError);
      return NextResponse.json(
        { error: 'Database connection failed. Please try again.' },
        { status: 503 }
      );
    }

    // Use getPrismaForOrg for multi-DB routing support
    const prisma = getPrismaForOrg(session.user.organizationId);
    
    console.log('[Delete Page] Attempting to delete:', {
      pageId,
      organizationId: session.user.organizationId,
      userId: session.user.id,
    });

    // First check if page exists - try to find it in any database if multi-DB is enabled
    let existingPage = await prisma.facebookPage.findFirst({
      where: {
        id: pageId,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        pageName: true,
        pageId: true,
        organizationId: true,
      },
    });

    // If not found and multi-DB is enabled, the page might be in a different database
    // Check if the page exists but belongs to a different organization (security check)
    if (!existingPage && process.env.ENABLE_MULTI_DB === 'true') {
      console.warn('[Delete Page] Page not found in routed database, checking if it exists elsewhere...');
      
      // Try to find the page in the default database as a fallback
      try {
        const { prisma: defaultPrisma } = await import('@/lib/db');
        const pageInDefault = await defaultPrisma.facebookPage.findFirst({
          where: { id: pageId },
          select: {
            id: true,
            pageName: true,
            pageId: true,
            organizationId: true,
          },
        });
        
        if (pageInDefault) {
          if (pageInDefault.organizationId !== session.user.organizationId) {
            console.error('[Delete Page] Page belongs to different organization:', {
              pageId,
              pageOrganizationId: pageInDefault.organizationId,
              userOrganizationId: session.user.organizationId,
            });
            return NextResponse.json(
              { error: 'Page not found or access denied. This page belongs to a different organization.' },
              { status: 403 }
            );
          }
          // Page exists in default DB but not in routed DB - this is a multi-DB routing issue
          console.warn('[Delete Page] Page found in default database but not in routed database. This may indicate a routing issue.');
        }
      } catch (fallbackError) {
        console.error('[Delete Page] Error checking default database:', fallbackError);
      }
    }

    if (!existingPage) {
      console.warn('[Delete Page] Page not found:', {
        pageId,
        organizationId: session.user.organizationId,
        multiDbEnabled: process.env.ENABLE_MULTI_DB === 'true',
      });
      return NextResponse.json(
        { error: 'Page not found or access denied' },
        { status: 404 }
      );
    }

    console.log('[Delete Page] Found page, deleting:', {
      databaseId: existingPage.id,
      facebookPageId: existingPage.pageId,
      pageName: existingPage.pageName,
    });
    
    // Delete the page (ensure it belongs to the user's organization)
    const deletedPage = await prisma.facebookPage.deleteMany({
      where: {
        id: pageId,
        organizationId: session.user.organizationId,
      },
    });

    if (deletedPage.count === 0) {
      console.warn('[Delete Page] Delete operation returned 0 rows:', {
        pageId,
        organizationId: session.user.organizationId,
      });
      return NextResponse.json(
        { error: 'Page not found or access denied' },
        { status: 404 }
      );
    }

    console.log('[Delete Page] Successfully deleted page:', {
      pageId,
      deletedCount: deletedPage.count,
    });

    return NextResponse.json({ success: true });
  } catch (error: unknown) {
    console.error('[Delete Page] Error:', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    // SECURITY: Sanitize error messages to prevent sensitive data exposure
    return NextResponse.json(
      { error: 'Failed to disconnect page. Please try again.' },
      { status: 500 }
    );
  }
}

