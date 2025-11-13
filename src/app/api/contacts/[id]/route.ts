import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { prisma } from '@/lib/db';

export async function GET(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const includeMessages = searchParams.get('includeMessages') === 'true';
    const messagesLimit = parseInt(searchParams.get('messagesLimit') || '20');

    const contact = await prisma.contact.findFirst({
      where: {
        id: id,
        organizationId: session.user.organizationId,
      },
      include: {
        stage: true,
        pipeline: true,
        facebookPage: true,
        activities: {
          take: 50,
          orderBy: { createdAt: 'desc' },
          include: {
            user: {
              select: { name: true, email: true },
            },
          },
        },
        ...(includeMessages && {
          conversations: {
            include: {
              messages: {
                take: messagesLimit,
                orderBy: { createdAt: 'desc' }
              }
            }
          }
        })
      },
    });

    if (!contact) {
      return NextResponse.json({ error: 'Contact not found' }, { status: 404 });
    }

    return NextResponse.json(contact);
  } catch (error) {
    const err = error as Error;
    console.error('Get contact error:', err);
    return NextResponse.json(
      { error: 'Failed to fetch contact' },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { firstName, lastName, notes, leadScore, leadStatus } = body;

    const contact = await prisma.contact.update({
      where: {
        id: id,
      },
      data: {
        ...(firstName && { firstName }),
        ...(lastName && { lastName }),
        ...(notes !== undefined && { notes }),
        ...(leadScore !== undefined && { leadScore }),
        ...(leadStatus && { leadStatus }),
      },
    });

    return NextResponse.json(contact);
  } catch (error) {
    const err = error as Error;
    console.error('Update contact error:', err);
    return NextResponse.json(
      { error: 'Failed to update contact' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: NextRequest,
  props: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await props.params;
    const session = await auth();
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    await prisma.contact.delete({
      where: { id: id },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    const err = error as Error;
    console.error('Delete contact error:', err);
    return NextResponse.json(
      { error: 'Failed to delete contact' },
      { status: 500 }
    );
  }
}

