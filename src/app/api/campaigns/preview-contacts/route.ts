import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma as defaultPrisma } from '@/lib/db';
import { getPrismaForOrg } from '@/lib/db/get-prisma-for-org';
import { validateSession } from '@/lib/api/validate-session';
import { validateUUID } from '@/lib/api/validate-uuid';

const PREVIEW_TIMEOUT = 10000; // 10 seconds (reduced to prevent 504)

/**
 * Preview target contacts for a campaign before creation
 * This helps users see who will receive the message
 */
export async function POST(request: NextRequest) {
  const previewStartTime = Date.now();
  
  try {
    const session = await auth();
    const validation = validateSession(session);
    if ('error' in validation) {
      return validation.error;
    }
    const { session: validatedSession } = validation;

    let body;
    try {
      body = await request.json();
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }
    let {
      facebookPageId,
      platform,
      targetTags,
      targetingType = 'ALL_CONTACTS',
      targetContactIds,
    } = body;

    // Validate and sanitize facebookPageId if provided
    if (facebookPageId) {
      if (typeof facebookPageId !== 'string') {
        return NextResponse.json(
          { error: 'facebookPageId must be a string' },
          { status: 400 }
        );
      }

      facebookPageId = facebookPageId.trim();
      if (facebookPageId.length === 0) {
        return NextResponse.json(
          { error: 'facebookPageId cannot be empty' },
          { status: 400 }
        );
      }
      const uuidValidation = validateUUID(facebookPageId);
      if (uuidValidation?.error) {
        return NextResponse.json(
          { error: uuidValidation.error.message },
          { status: uuidValidation.error.status }
        );
      }
    }

    // Get routed prisma client for multi-DB support
    const prisma = getPrismaForOrg(validatedSession.user.organizationId);
    
    // Set up timeout for the entire operation
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error('Preview contacts timeout - request took too long'));
      }, PREVIEW_TIMEOUT);
    });

    // Wrap the main logic in a promise for timeout handling
    const previewPromise = (async () => {
      // Helper function to find page with fallback
      const findPageWithFallback = async (pageId: string) => {
      // First try routed database
      let page = await prisma.facebookPage.findFirst({
        where: {
          id: pageId,
          organizationId: validatedSession.user.organizationId,
        },
      });

      // If not found and multi-DB is enabled, try default database
      if (!page && process.env.ENABLE_MULTI_DB === 'true') {
        page = await defaultPrisma.facebookPage.findFirst({
          where: {
            id: pageId,
          },
        });

        // Verify organization ownership
        if (page && page.organizationId !== validatedSession.user.organizationId) {
          console.error('[Preview Contacts] Page belongs to different organization:', {
            pageId,
            pageOrganizationId: page.organizationId,
            userOrganizationId: validatedSession.user.organizationId,
          });
          return null;
        }
      }

        return page;
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let contacts: any[] = [];

    // Get contacts based on targeting type
    switch (targetingType) {
      case 'SPECIFIC_CONTACTS':
        if (!targetContactIds || targetContactIds.length === 0) {
          return NextResponse.json(
            { error: 'Contact IDs are required for SPECIFIC_CONTACTS targeting' },
            { status: 400 }
          );
        }
        
        // Fetch specific contacts by IDs
        contacts = await prisma.contact.findMany({
          where: {
            id: { in: targetContactIds },
            organizationId: validatedSession.user.organizationId,
          },
          include: {
            facebookPage: {
              select: {
                id: true,
                pageName: true,
                instagramUsername: true,
              },
            },
          },
        });

        // If not all found, try default database
        if (contacts.length !== targetContactIds.length && process.env.ENABLE_MULTI_DB === 'true') {
          const foundIds = new Set(contacts.map(c => c.id));
          const missingIds = targetContactIds.filter((id: string) => !foundIds.has(id));
          const defaultContacts = await defaultPrisma.contact.findMany({
            where: {
              id: { in: missingIds },
              organizationId: validatedSession.user.organizationId,
            },
            include: {
              facebookPage: {
                select: {
                  id: true,
                  pageName: true,
                  instagramUsername: true,
                },
              },
            },
          });
          contacts.push(...defaultContacts);
        }
        break;

      case 'TAGS':
        if (!facebookPageId || !platform) {
          return NextResponse.json(
            { error: 'Facebook page ID and platform are required for TAGS targeting' },
            { status: 400 }
          );
        }

        // Verify the page belongs to the user's organization
        const page = await findPageWithFallback(facebookPageId);

        if (!page) {
          return NextResponse.json(
            { error: 'Facebook page not found or access denied' },
            { status: 404 }
          );
        }

        if (!targetTags || targetTags.length === 0) {
          // If no tags, get all contacts
          contacts = await prisma.contact.findMany({
            where: {
              organizationId: validatedSession.user.organizationId,
              facebookPageId: facebookPageId,
            },
          });
        } else {
          contacts = await prisma.contact.findMany({
            where: {
              organizationId: validatedSession.user.organizationId,
              facebookPageId: facebookPageId,
              tags: {
                hasSome: targetTags,
              },
            },
          });
        }
        break;

      case 'ALL_CONTACTS':
      default:
        if (!facebookPageId || !platform) {
          return NextResponse.json(
            { error: 'Facebook page ID and platform are required' },
            { status: 400 }
          );
        }

        // Verify the page belongs to the user's organization
        const allContactsPage = await findPageWithFallback(facebookPageId);

        if (!allContactsPage) {
          return NextResponse.json(
            { error: 'Facebook page not found or access denied' },
            { status: 404 }
          );
        }

        contacts = await prisma.contact.findMany({
          where: {
            organizationId: validatedSession.user.organizationId,
            facebookPageId: facebookPageId,
          },
        });

        // If no contacts found and multi-DB is enabled, try default database
        if (contacts.length === 0 && process.env.ENABLE_MULTI_DB === 'true') {
          contacts = await defaultPrisma.contact.findMany({
            where: {
              organizationId: validatedSession.user.organizationId,
              facebookPageId: facebookPageId,
            },
          });
        }
        break;
    }

    // Filter by platform capability (only for non-SPECIFIC_CONTACTS targeting)
    let targetContacts = contacts;
    if (targetingType !== 'SPECIFIC_CONTACTS' && platform) {
      targetContacts = contacts.filter((contact) => {
        if (platform === 'MESSENGER') {
          return contact.hasMessenger && contact.messengerPSID;
        }
        if (platform === 'INSTAGRAM') {
          return contact.hasInstagram && contact.instagramSID;
        }
        return false;
      });
    }

      // Return contact preview data
      const previewContacts = targetContacts.map((contact) => ({
        id: contact.id,
        firstName: contact.firstName || 'Unknown',
        lastName: contact.lastName || '',
        email: contact.email || null,
        phone: contact.phone || null,
        tags: contact.tags || [],
        hasMessenger: contact.hasMessenger,
        hasInstagram: contact.hasInstagram,
        aiContext: contact.aiContext || null,
        lastInteraction: contact.lastInteraction || null,
        facebookPageId: contact.facebookPageId || (contact.facebookPage?.id || null),
        facebookPage: contact.facebookPage || null,
      }));

      return NextResponse.json({
        contacts: previewContacts,
        total: previewContacts.length,
      });
    })();

    // Race between preview and timeout
    return await Promise.race([previewPromise, timeoutPromise]);
  } catch (error) {
    const elapsed = Date.now() - previewStartTime;
    const err = error as Error;
    const errorMessage = err.message || 'Failed to preview contacts';
    
    console.error('Preview contacts error:', errorMessage, { elapsed });
    
    // Always return JSON, even on timeout
    try {
      // Check for timeout
      if (errorMessage.includes('timeout') || elapsed >= PREVIEW_TIMEOUT) {
        return NextResponse.json(
          { error: 'Request timed out. Please try again or reduce the number of contacts.' },
          { status: 408 }
        );
      }
      
      // Check for database connection errors
      if (errorMessage.includes('PrismaClientInitializationError') || 
          errorMessage.includes('Can\'t reach database server') ||
          errorMessage.includes('Connection') ||
          errorMessage.includes('Unable to check out process from the pool')) {
        return NextResponse.json(
          { error: 'Database connection error. Please try again in a moment.' },
          { status: 503 }
        );
      }
      
      return NextResponse.json(
        { error: errorMessage },
        { status: 500 }
      );
    } catch (jsonError) {
      // Fallback if JSON creation fails
      console.error('Failed to create error response:', jsonError);
      return new NextResponse(
        JSON.stringify({ error: 'An unexpected error occurred' }),
        { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }
}




