import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';
import { validateSession } from '@/lib/api/validate-session';

/**
 * Preview target contacts for a campaign before creation
 * This helps users see who will receive the message
 */
export async function POST(request: NextRequest) {
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
    const {
      facebookPageId,
      platform,
      targetTags,
      targetingType = 'ALL_CONTACTS',
      targetContactIds,
    } = body;

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
        break;

      case 'TAGS':
        if (!facebookPageId || !platform) {
          return NextResponse.json(
            { error: 'Facebook page ID and platform are required for TAGS targeting' },
            { status: 400 }
          );
        }

        // Verify the page belongs to the user's organization
        const page = await prisma.facebookPage.findFirst({
          where: {
            id: facebookPageId,
            organizationId: validatedSession.user.organizationId,
          },
        });

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
        const allContactsPage = await prisma.facebookPage.findFirst({
          where: {
            id: facebookPageId,
            organizationId: validatedSession.user.organizationId,
          },
        });

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
  } catch (error) {
    const err = error as Error;
    console.error('Preview contacts error:', err);
    return NextResponse.json(
      { error: 'Failed to preview contacts' },
      { status: 500 }
    );
  }
}




