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

    const body = await request.json();
    const {
      facebookPageId,
      platform,
      targetTags,
      targetingType = 'ALL_CONTACTS',
    } = body;

    if (!facebookPageId || !platform) {
      return NextResponse.json(
        { error: 'Facebook page ID and platform are required' },
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

    let contacts: any[] = [];

    // Get contacts based on targeting type
    switch (targetingType) {
      case 'TAGS':
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
        contacts = await prisma.contact.findMany({
          where: {
            organizationId: validatedSession.user.organizationId,
            facebookPageId: facebookPageId,
          },
        });
        break;
    }

    // Filter by platform capability
    const targetContacts = contacts.filter((contact) => {
      if (platform === 'MESSENGER') {
        return contact.hasMessenger && contact.messengerPSID;
      }
      if (platform === 'INSTAGRAM') {
        return contact.hasInstagram && contact.instagramSID;
      }
      return false;
    });

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




