/**
 * Test endpoint to debug best contact times computation
 * This is a temporary debugging endpoint
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  try {
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;

    // Get contact info
    const contact = await prisma.contact.findFirst({
      where: {
        id,
        organizationId: session.user.organizationId,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
      },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    // Get messages
    const messages = await prisma.message.findMany({
      where: {
        contactId: id,
      },
      orderBy: {
        createdAt: 'asc',
      },
      select: {
        id: true,
        isFromBusiness: true,
        createdAt: true,
        sentAt: true,
      },
    });

    const businessMessages = messages.filter(m => m.isFromBusiness);
    const contactMessages = messages.filter(m => !m.isFromBusiness);

    return NextResponse.json({
      contact: {
        id: contact.id,
        name: `${contact.firstName} ${contact.lastName}`,
      },
      messages: {
        total: messages.length,
        fromBusiness: businessMessages.length,
        fromContact: contactMessages.length,
      },
      sampleMessages: messages.slice(0, 5).map(m => ({
        id: m.id,
        isFromBusiness: m.isFromBusiness,
        createdAt: m.createdAt,
        sentAt: m.sentAt,
      })),
    });
  } catch (error) {
    console.error('[TestBestTimes] Error:', error);
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}









